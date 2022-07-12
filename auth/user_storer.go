package auth

import (
	"fmt"
	"reflect"

	"github.com/jinzhu/copier"
	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/qor/utils"
)

// UserStorer default user storer
type UserStorer struct {
}

// Get defined how to get user with user id
func (UserStorer) Get(Claims *claims.Claims, ctx *auth.Context) (user interface{}, err error) {
	// log.Printf("UserStorer.Get")
	db := ctx.DB

	if ctx.Auth.Config.UserModel != nil {
		if Claims.UserID != "" {
			currentUser := reflect.New(utils.ModelType(ctx.Auth.Config.UserModel)).Interface()
			if err = db.First(currentUser, Claims.UserID).Error; err == nil {
				return currentUser, nil
			}
			return nil, auth.ErrInvalidAccount
		}
	}

	var (
		authIdentity = reflect.New(utils.ModelType(ctx.Auth.Config.AuthIdentityModel)).Interface()
		authInfo     = auth_identity.Basic{
			Provider: Claims.Provider,
			UID:      Claims.Id,
		}
	)

	if !db.Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).First(authIdentity).RecordNotFound() {
		if ctx.Auth.Config.UserModel != nil {
			if authBasicInfo, ok := authIdentity.(interface{ ToClaims() *claims.Claims }); ok {
				currentUser := reflect.New(utils.ModelType(ctx.Auth.Config.UserModel)).Interface()
				if err = db.First(currentUser, authBasicInfo.ToClaims().UserID).Error; err == nil {
					return currentUser, nil
				}
				return nil, auth.ErrInvalidAccount
			}
		}

		return authIdentity, nil
	}

	return nil, auth.ErrInvalidAccount
}

// Save defined how to save user
func (UserStorer) Save(schema *auth.Schema, ctx *auth.Context) (user interface{}, userID string, err error) {
	var (
		tx        = ctx.DB
		userModel = ctx.Auth.Config.UserModel
	)

	if userModel != nil {
		currentUser := reflect.New(utils.ModelType(userModel)).Interface()
		copier.Copy(currentUser, schema)

		err = tx.Create(currentUser).Error
		if ctx.Provider.GetName() == "password" {
			err = tx.
				Model(userModel).
				Where("provider = ? AND uid = ?", schema.Provider, schema.UID).
				UpdateColumn("encrypted_password", schema.RawInfo.(auth_identity.Basic).EncryptedPassword).
				Error
		}
		return currentUser, fmt.Sprint(tx.NewScope(currentUser).PrimaryKeyValue()), err
	}
	return nil, "", nil
}
