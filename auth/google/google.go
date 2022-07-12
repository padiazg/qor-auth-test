package google

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"

	"github.com/jinzhu/copier"
	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/auth/providers/google"
	"github.com/qor/qor/utils"
)

// Allow use Google
func InitProvider(a *auth.Auth) {
	a.RegisterProvider(google.New(&google.Config{
		ClientID:         "",
		ClientSecret:     "",
		AllowedDomains:   []string{}, // Accept all domains, instead you can pass a whitelist of acceptable domains
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
		provider     = ctx.Provider.(*google.GoogleProvider)
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

		{
			client := oauthCfg.Client(context.TODO(), tkn)
			resp, err := client.Get(google.UserInfoURL)
			if err != nil {
				return nil, err
			}

			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			userInfo := google.UserInfo{}
			json.Unmarshal(body, &userInfo)
			schema.Provider = provider.GetName()
			schema.UID = userInfo.Email
			schema.Email = userInfo.Email
			schema.FirstName = userInfo.GivenName
			schema.LastName = userInfo.FamilyName
			schema.Image = userInfo.Picture
			schema.Name = userInfo.Name
			schema.RawInfo = userInfo
		}

		if !isDomainAllowed(schema.Email, provider.AllowedDomains) {
			return nil, auth.ErrUnauthorized
		}

		authInfo.Provider = provider.GetName()
		authInfo.UID = schema.UID

		copier.Copy(authIdentity, authInfo)
		if !tx.Model(authIdentity).Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).Scan(&authInfo).RecordNotFound() {
			return authInfo.ToClaims(), nil
		}

		if _, userID, err := ctx.Auth.UserStorer.Save(&schema, ctx); err == nil {
			if userID != "" {
				authInfo.UserID = userID
			}
		} else {
			return nil, err
		}

		if err = tx.Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).FirstOrCreate(authIdentity).Error; err == nil {
			return authInfo.ToClaims(), nil
		}
	}

	return nil, err
}

func isDomainAllowed(email string, domains []string) bool {
	if len(domains) == 0 {
		return true
	}

	for _, domain := range domains {
		if strings.HasSuffix(email, fmt.Sprintf("@%s", domain)) {
			return true
		}
	}
	return false
}
