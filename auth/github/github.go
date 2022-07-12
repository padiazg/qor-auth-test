package github

import (
	"context"
	"fmt"
	"reflect"

	gh "github.com/google/go-github/github"
	"github.com/jinzhu/copier"
	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/auth/providers/github"
	"github.com/qor/qor/utils"
)

// Allow use Github
func InitProvider(a *auth.Auth) {
	// https://docs.github.com/en/github/authenticating-to-github/keeping-your-account-and-data-secure/creating-a-personal-access-token
	a.RegisterProvider(github.New(&github.Config{
		ClientID:         "",
		ClientSecret:     "",
		AuthorizeHandler: authorizeHandler,
	}))
}

func authorizeHandler(ctx *auth.Context) (*claims.Claims, error) {
	var (
		req          = ctx.Request
		schema       auth.Schema
		authInfo     auth_identity.Basic
		tx           = ctx.Auth.GetDB(req)
		authIdentity = reflect.New(utils.ModelType(ctx.Auth.Config.AuthIdentityModel)).Interface()
		provider     = ctx.Provider.(*github.GithubProvider)
		// authUser     = reflect.New(utils.ModelType(ctx.Auth.Config.UserModel)).Interface()
	)

	state := req.URL.Query().Get("state")
	claims, err := ctx.Auth.SessionStorer.ValidateClaims(state)

	if err != nil || claims.Valid() != nil || claims.Subject != "state" {
		return nil, auth.ErrUnauthorized
	}

	if err == nil {
		oauthCfg := provider.OAuthConfig(ctx)
		tkn, err := oauthCfg.Exchange(context.TODO(), req.URL.Query().Get("code"))

		if err != nil {
			return nil, err
		}

		client := gh.NewClient(oauthCfg.Client(context.TODO(), tkn))
		user, _, err := client.Users.Get(context.TODO(), "")
		if err != nil {
			return nil, err
		}

		authInfo.Provider = provider.GetName()
		authInfo.UID = fmt.Sprint(*user.ID)

		// if !tx.Model(ctx.Auth.AuthIdentityModel).Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).Scan(&authInfo).RecordNotFound() {
		if !tx.Model(authIdentity).Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).Scan(&authInfo).RecordNotFound() {
			return authInfo.ToClaims(), nil
		}

		schema.Provider = provider.GetName()
		schema.UID = fmt.Sprint(*user.ID)
		schema.Name = user.GetName()
		schema.Email = user.GetEmail()
		schema.Image = user.GetAvatarURL()
		schema.RawInfo = user
		if _, userID, err := ctx.Auth.UserStorer.Save(&schema, ctx); err == nil {
			if userID != "" {
				authInfo.UserID = userID
			}
		} else {
			return nil, err
		}

		copier.Copy(authIdentity, authInfo)
		if err = tx.Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).FirstOrCreate(authIdentity).Error; err == nil {
			return authInfo.ToClaims(), nil
		}
		return nil, err
	}

	return nil, err
}
