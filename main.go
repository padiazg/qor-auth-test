package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"reflect"
	"strings"

	"github.com/jinzhu/copier"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"

	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/claims"
	"github.com/qor/auth/providers/github"
	"github.com/qor/auth/providers/password"
	"github.com/qor/qor/utils"
	"github.com/qor/redirect_back"
	"github.com/qor/responder"
	"github.com/qor/session"

	// "github.com/qor/auth/providers/google"
	// "github.com/qor/auth/providers/facebook"
	// "github.com/qor/auth/providers/twitter"
	"github.com/qor/assetfs"
	"github.com/qor/render"
	"github.com/qor/session/gorilla"
	"github.com/qor/session/manager"

	gh "github.com/google/go-github/github"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

type User struct {
	gorm.Model
	auth_identity.Basic
	Enabled bool
}

var (
	ErrPasswordConfirmationNotMatch = errors.New("password confirmation doesn't match password")
	// Initialize gorm DB
	gormDB, _ = gorm.Open("sqlite3", "sample.db")

	// Initialize Auth with configuration
	Auth = auth.New(&auth.Config{
		DB: gormDB,
		Render: render.New(&render.Config{
			AssetFileSystem: &assetfs.AssetFileSystem{},
			ViewPaths:       []string{"views"},
		}),
		Redirector: auth.Redirector{RedirectBack: redirect_back.New(&redirect_back.Config{
			SessionManager:  manager.SessionManager,
			IgnoredPrefixes: []string{"/auth"},
		})},
		UserModel:         auth_identity.AuthIdentity{},
		UserStorer:        UserStorer{},
		AuthIdentityModel: auth_identity.AuthIdentity{},
		LoginHandler:      AuthLoginHandler,
	})
	SessionManager session.ManagerInterface
)

func init() {
	gormDB.LogMode(true)
	// Migrate AuthIdentity model, AuthIdentity will be used to save auth info, like username/password, oauth token, you could change that.
	gormDB.AutoMigrate(&auth_identity.AuthIdentity{})
	gormDB.AutoMigrate(&User{})

	// Register Auth providers
	// Allow use username/password
	Auth.RegisterProvider(password.New(&password.Config{
		Confirmable: false,
		RegisterHandler: func(context *auth.Context) (*claims.Claims, error) {

			// check if password and confirm_password martches
			context.Request.ParseForm()
			if context.Request.Form.Get("confirm_password") != context.Request.Form.Get("password") {
				return nil, ErrPasswordConfirmationNotMatch
			}

			return PasswordRegisterHandler(context)
		},
	}))

	// Allow use Github
	// https://docs.github.com/en/github/authenticating-to-github/keeping-your-account-and-data-secure/creating-a-personal-access-token
	Auth.RegisterProvider(github.New(&github.Config{
		ClientID:         "your-github-client-id",
		ClientSecret:     "your-github-client-secret",
		AuthorizeHandler: GithubAuthorizeHandler,
	}))

	// // Allow use Google
	// Auth.RegisterProvider(google.New(&google.Config{
	//   ClientID:     "google client id",
	//   ClientSecret: "google client secret",
	//   AllowedDomains: []string{}, // Accept all domains, instead you can pass a whitelist of acceptable domains
	// }))

	// // Allow use Facebook
	// Auth.RegisterProvider(facebook.New(&facebook.Config{
	//   ClientID:     "facebook client id",
	//   ClientSecret: "facebook client secret",
	// }))

	// // Allow use Twitter
	// Auth.RegisterProvider(twitter.New(&twitter.Config{
	//   ClientID:     "twitter client id",
	//   ClientSecret: "twitter client secret",
	// }))
}

func main() {

	// Use gorilla session as the backend
	engine := sessions.NewCookieStore([]byte("something-very-secret"))
	SessionManager = gorilla.New("_session", engine)

	r := mux.NewRouter()
	// r := http.NewServeMux()

	// Mount Auth to Router
	r.PathPrefix("/auth").Handler(Auth.NewServeMux())
	// r.Use(manager.SessionManager.Middleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u := Auth.GetCurrentUser(r)
		if u != nil {
			// cu := u.(*auth_identity.AuthIdentity)
			cu := u.(*auth_identity.AuthIdentity)
			fmt.Printf("u => %v", cu)
			fmt.Fprintf(w, "Hello, %v", cu.UID)
		}
	})

	// show all routes
	// fmt.Println("")
	// r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
	// 	t, err := route.GetPathTemplate()
	// 	if err != nil {
	// 		log.Println(err)
	// 		return err
	// 	}
	// 	fmt.Println(strings.Repeat("| ", len(ancestors)), t)
	// 	return nil
	// })

	http.ListenAndServe(":9000", manager.SessionManager.Middleware(r))
}

var AuthLoginHandler = func(c *auth.Context, f func(*auth.Context) (*claims.Claims, error)) {
	log.Printf("LoginHandler | provider => %v\n", c.Provider.GetName())
	var (
		req         = c.Request
		w           = c.Writer
		claims, err = f(c)
	)

	log.Printf("LoginHandler | claims => %v\n", claims)
	if err == nil && claims != nil {
		log.Printf("LoginHandler | logged")
		c.SessionStorer.Flash(w, req, session.Message{Message: "logged"})
		respondAfterLogged(claims, c)
		return
	}

	c.SessionStorer.Flash(w, req, session.Message{Message: template.HTML(err.Error()), Type: "error"})

	log.Printf("LoginHandler | responder")
	responder.
		With("html", func() {
			c.Auth.Config.Render.Execute("auth/login", c, req, w)
		}).
		With([]string{"json"}, func() {}).
		Respond(c.Request)
}

func respondAfterLogged(claims *claims.Claims, context *auth.Context) {
	// login user
	context.Auth.Login(context.Writer, context.Request, claims)

	responder.With("html", func() {
		// write cookie
		context.Auth.Redirector.Redirect(context.Writer, context.Request, "login")
	}).With([]string{"json"}, func() {
		// TODO write json token
	}).Respond(context.Request)
}

var PasswordRegisterHandler = func(context *auth.Context) (*claims.Claims, error) {
	var (
		err         error
		currentUser interface{}
		schema      auth.Schema
		authInfo    auth_identity.Basic
		req         = context.Request
		tx          = context.Auth.GetDB(req)
		provider, _ = context.Provider.(*password.Provider)
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

	if !tx.Model(context.Auth.AuthIdentityModel).Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).Scan(&authInfo).RecordNotFound() {
		return nil, auth.ErrInvalidAccount
	}

	if authInfo.EncryptedPassword, err = provider.Encryptor.Digest(strings.TrimSpace(req.Form.Get("password"))); err == nil {
		schema.Provider = authInfo.Provider
		schema.UID = authInfo.UID
		schema.Email = authInfo.UID
		schema.RawInfo = authInfo

		currentUser, authInfo.UserID, err = context.Auth.UserStorer.Save(&schema, context)
		if err != nil {
			return nil, err
		}

		// create auth identity
		authIdentity := reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
		copier.Copy(authIdentity, authInfo)
		log.Printf("PasswordRegisterHandler | authIdentity1 => %v", authIdentity)
		if err = tx.Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).FirstOrCreate(authIdentity).Error; err == nil {
			log.Printf("PasswordRegisterHandler | authIdentity2 => %v", authIdentity)
			if provider.Config.Confirmable {
				context.SessionStorer.Flash(context.Writer, req, session.Message{Message: password.ConfirmFlashMessage, Type: "success"})
				err = provider.Config.ConfirmMailer(schema.Email, context, authInfo.ToClaims(), currentUser)
			}

			return authInfo.ToClaims(), err
		}
	}

	return nil, err
}

var GithubAuthorizeHandler = func(ctx *auth.Context) (*claims.Claims, error) {
	var (
		schema   auth.Schema
		authInfo auth_identity.Basic
		// authUser     = reflect.New(utils.ModelType(ctx.Auth.Config.UserModel)).Interface()
		authIdentity = reflect.New(utils.ModelType(ctx.Auth.Config.AuthIdentityModel)).Interface()
		req          = ctx.Request
		tx           = ctx.Auth.GetDB(req)
		provider     = ctx.Provider.(*github.GithubProvider)
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

		f := !tx.Model(ctx.Auth.AuthIdentityModel).Where("provider = ? AND uid = ?", authInfo.Provider, authInfo.UID).Scan(&authInfo).RecordNotFound()
		log.Printf("GithubAuthorizeHandler | found => %v", f)
		if f {
			return authInfo.ToClaims(), nil
		}

		{
			schema.Provider = provider.GetName()
			schema.UID = fmt.Sprint(*user.ID)
			schema.Name = user.GetName()
			schema.Email = user.GetEmail()
			schema.Image = user.GetAvatarURL()
			schema.RawInfo = user
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
		return nil, err
	}

	return nil, err
}
