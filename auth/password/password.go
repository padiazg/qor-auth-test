package password

import (
	"fmt"
	"log"
	"reflect"
	"strings"

	"github.com/jinzhu/copier"
	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/auth/providers/password"
	"github.com/qor/qor/utils"
	"github.com/qor/session"
)

// Allow use username/password
func InitProvider(a *auth.Auth) {
	a.RegisterProvider(password.New(&password.Config{
		Confirmable: false,
		RegisterHandler: func(ctx *auth.Context) (*claims.Claims, error) {
			// check if password and confirm_password martches
			ctx.Request.ParseForm()
			if ctx.Request.Form.Get("confirm_password") != ctx.Request.Form.Get("password") {
				return nil, fmt.Errorf("password confirmation doesn't match password")
			}

			return passwordRegisterHandler(ctx)
		},
		// AuthorizeHandler: passwordLoginHandler,
		// AuthorizeHandler: password.DefaultAuthorizeHandler,
	}))
}

func passwordRegisterHandler(ctx *auth.Context) (*claims.Claims, error) {
	var (
		err         error
		currentUser interface{}
		schema      auth.Schema
		authInfo    auth_identity.Basic
		req         = ctx.Request
		tx          = ctx.Auth.GetDB(req)
		provider, _ = ctx.Provider.(*password.Provider)
	)

	req.ParseForm()
	if req.Form.Get("login") == "" {
		return nil, auth.ErrInvalidAccount
	}

	if req.Form.Get("password") == "" {
		return nil, auth.ErrInvalidPassword
	}

	authInfo.Provider = provider.GetName()
	authInfo.UID = strings.TrimSpace(req.Form.Get("login"))

	if !tx.Model(ctx.Auth.AuthIdentityModel).Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).Scan(&authInfo).RecordNotFound() {
		return nil, auth.ErrInvalidAccount
	}

	if authInfo.EncryptedPassword, err = provider.Encryptor.Digest(strings.TrimSpace(req.Form.Get("password"))); err == nil {
		schema.Provider = authInfo.Provider
		schema.UID = authInfo.UID
		schema.Email = authInfo.UID
		schema.RawInfo = authInfo

		currentUser, authInfo.UserID, err = ctx.Auth.UserStorer.Save(&schema, ctx)
		if err != nil {
			return nil, err
		}

		// create auth identity
		authIdentity := reflect.New(utils.ModelType(ctx.Auth.Config.AuthIdentityModel)).Interface()
		copier.Copy(authIdentity, authInfo)
		log.Printf("PasswordRegisterHandler | authIdentity1 => %#v\n", authIdentity)
		if err = tx.Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).FirstOrCreate(authIdentity).Error; err == nil {
			log.Printf("PasswordRegisterHandler | authIdentity2 => %#v\n", authIdentity)
			if provider.Config.Confirmable {
				ctx.SessionStorer.Flash(ctx.Writer, req, session.Message{Message: password.ConfirmFlashMessage, Type: "success"})
				err = provider.Config.ConfirmMailer(schema.Email, ctx, authInfo.ToClaims(), currentUser)
			}

			return authInfo.ToClaims(), err
		}
	}

	return nil, err
}

// func passwordLoginHandler(ctx *auth.Context) (*claims.Claims, error) {
// 	var (
// 		err error
// 		// currentUser interface{}
// 		// schema      auth.Schema
// 		authInfo    auth_identity.Basic
// 		req         = ctx.Request
// 		tx          = ctx.Auth.GetDB(req)
// 		provider, _ = ctx.Provider.(*password.Provider)
// 	)

// 	req.ParseForm()
// 	if req.Form.Get("login") == "" {
// 		return nil, auth.ErrInvalidAccount
// 	}

// 	if req.Form.Get("password") == "" {
// 		return nil, auth.ErrInvalidPassword
// 	}

// 	authInfo.Provider = provider.GetName()
// 	authInfo.UID = strings.TrimSpace(req.Form.Get("login"))

// 	if tx.
// 		Model(ctx.Auth.AuthIdentityModel).
// 		Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).
// 		Scan(&authInfo).
// 		RecordNotFound() {
// 		return nil, auth.ErrInvalidAccount
// 	}

// 	return nil, err
// }
