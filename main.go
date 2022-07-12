package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/qor/auth/auth_identity"
	"github.com/qor/session/manager"

	ah "github.com/padiazg/qor-auth-test/auth"
)

var (
	// Initialize gorm DB
	DB, _ = gorm.Open("sqlite3", "sample.db")
	port  = 9000
)

func init() {
	DB.LogMode(true)

	// Migrate AuthIdentity model, AuthIdentity will be used to save auth info,
	// like username/password, oauth token, you could change that.
	DB.AutoMigrate(&auth_identity.AuthIdentity{})
	DB.AutoMigrate(&ah.User{})
}

func main() {

	// get new Auth manager
	Auth := ah.InitAuth(DB)

	r := mux.NewRouter()
	// r := http.NewServeMux()

	// Mount Auth to Router
	r.PathPrefix("/auth").Handler(Auth.NewServeMux())
	r.Use(manager.SessionManager.Middleware)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u := Auth.GetCurrentUser(r)
		if u != nil {
			// cu := u.(*auth_identity.AuthIdentity)
			cu := u.(*ah.User)
			fmt.Printf("u => %#v", cu)
			fmt.Fprintf(w, "Hello, %v", cu)
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

	log.Printf("Listening on: %v\n", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), r); err != nil {
		panic(err)
	}
}
