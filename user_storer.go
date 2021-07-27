package main

import (
	"fmt"
	"log"
	"reflect"

	"github.com/jinzhu/copier"
	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/qor/utils"
)

// UserStorerInterface user storer interface
type UserStorerInterface interface {
	Save(schema *auth.Schema, context *auth.Context) (user interface{}, userID string, err error)
	Get(claims *claims.Claims, context *auth.Context) (user interface{}, err error)
}

// UserStorer default user storer
type UserStorer struct {
}

// Get defined how to get user with user id
func (UserStorer) Get(Claims *claims.Claims, context *auth.Context) (user interface{}, err error) {
	// log.Printf("UserStorer.Get")
	var tx = context.Auth.GetDB(context.Request)

	if context.Auth.Config.UserModel != nil {
		if Claims.UserID != "" {
			currentUser := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
			if err = tx.First(currentUser, Claims.UserID).Error; err == nil {
				return currentUser, nil
			}
			return nil, auth.ErrInvalidAccount
		}
	}

	var (
		authIdentity = reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
		authInfo     = auth_identity.Basic{
			Provider: Claims.Provider,
			UID:      Claims.Id,
		}
	)

	if !tx.Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).First(authIdentity).RecordNotFound() {
		if context.Auth.Config.UserModel != nil {
			if authBasicInfo, ok := authIdentity.(interface {
				ToClaims() *claims.Claims
			}); ok {
				currentUser := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
				if err = tx.First(currentUser, authBasicInfo.ToClaims().UserID).Error; err == nil {
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
func (UserStorer) Save(schema *auth.Schema, context *auth.Context) (user interface{}, userID string, err error) {
	log.Printf("UserStorer.Save")
	var tx = context.Auth.GetDB(context.Request)

	if context.Auth.Config.UserModel != nil {
		currentUser := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
		copier.Copy(currentUser, schema)

		err = tx.Create(currentUser).Error
		if context.Provider.GetName() == "password" {
			err = tx.
				Model(context.Auth.Config.UserModel).
				Where("provider = ? AND uid = ?", schema.Provider, schema.UID).
				UpdateColumn("encrypted_password", schema.RawInfo.(auth_identity.Basic).EncryptedPassword).
				Error
		}
		return currentUser, fmt.Sprint(tx.NewScope(currentUser).PrimaryKeyValue()), err
	}
	return nil, "", nil
}
