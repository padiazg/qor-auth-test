package auth

import (
	"html/template"

	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	githubp "github.com/padiazg/qor-auth-test/auth/github"
	googlep "github.com/padiazg/qor-auth-test/auth/google"
	passwordp "github.com/padiazg/qor-auth-test/auth/password"
	"github.com/qor/assetfs"
	"github.com/qor/auth"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/auth/authority"
	"github.com/qor/auth/claims"
	"github.com/qor/redirect_back"
	"github.com/qor/render"
	"github.com/qor/responder"
	"github.com/qor/session"
	"github.com/qor/session/gorilla"
	"github.com/qor/session/manager"
)

type User struct {
	gorm.Model
	auth_identity.Basic
	Enabled bool
	Email   string
	Name    string
	Image   string
}

var (
	// SessionManager session.ManagerInterface
	engine    = sessions.NewCookieStore([]byte("something-very-secret"))
	Authority *authority.Authority
)

func InitAuth(db *gorm.DB) *auth.Auth {
	// Use gorilla session as the backend
	manager.SessionManager = gorilla.New("qor_auth_test_session", engine)

	// Initialize Auth with configuration
	// https://github.com/qor/auth/blob/master/auth.go#L27
	Auth := auth.New(&auth.Config{
		DB: db,
		Render: render.New(&render.Config{
			AssetFileSystem: &assetfs.AssetFileSystem{},
			ViewPaths:       []string{"views"},
		}),
		Redirector: auth.Redirector{RedirectBack: redirect_back.New(&redirect_back.Config{
			SessionManager:  manager.SessionManager,
			IgnoredPrefixes: []string{"/auth"},
		})},
		AuthIdentityModel: auth_identity.AuthIdentity{},
		UserModel:         &User{},
		UserStorer:        UserStorer{},
		LoginHandler:      authConfigLoginHandler,
	})

	passwordp.InitProvider(Auth)
	githubp.InitProvider(Auth)
	googlep.InitProvider(Auth)

	Authority = authority.New(&authority.Config{Auth: Auth})

	return Auth

}

// https://github.com/qor/auth/blob/master/auth.go#L51
func authConfigLoginHandler(c *auth.Context, f func(*auth.Context) (*claims.Claims, error)) {
	var (
		req         = c.Request
		w           = c.Writer
		claims, err = f(c)
	)

	if err == nil && claims != nil {
		c.SessionStorer.Flash(w, req, session.Message{Message: "logged"})
		respondAfterLogged(claims, c)
		return
	}

	c.SessionStorer.Flash(w, req, session.Message{Message: template.HTML(err.Error()), Type: "error"})

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

	responder.
		With("html", func() {
			// write cookie
			context.Auth.Redirector.Redirect(context.Writer, context.Request, "login")
		}).
		With([]string{"json"}, func() {
			// TODO write json token
			context.Writer.Write([]byte("this is a json or xml request"))
		}).
		Respond(context.Request)
}
