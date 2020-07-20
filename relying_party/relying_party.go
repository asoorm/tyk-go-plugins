package main

import (
	"github.com/asoorm/tyk-go-plugins/relying_party/handler"
	"github.com/asoorm/tyk-go-plugins/relying_party/model"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"net/http"
)

var (
	httpHandler http.Handler
)

func init() {

	conf := model.Conf{
		//Logger: log.Get(),
		Storage: model.Storage{
			Address:  "127.0.0.1:6379",
			Password: "",
			DB:       0,
		},
		GatewayClient: model.GatewayClient{
			ClientID:     "tyk-gateway",
			ClientSecret: "SOMESECRET",
			//RedirectURI:  "http://gateway.ahmet:8080/auth/callback",
			Discovery: model.DiscoveryMeta{
				AuthorizationEndpoint: "http://gateway.ahmet:8080/auth/auth",
				TokenEndpoint:         "http://gateway.ahmet:8080/auth/token",
				Issuer:                "http://gateway.ahmet:8080/auth",
			},
		},
		// TODO: make API call and discover this stuff
		UpstreamIdP: oauth2.Config{
			ClientID:     "tyk-gateway",
			ClientSecret: "SOMESECRET",
			Endpoint:     oauth2.Endpoint{
				AuthURL:   "https://IDP/auth",
				TokenURL:  "https://IDP/token",
				AuthStyle: oauth2.AuthStyleInParams,
			},
			RedirectURL:  "http://gateway.ahmet:8080/auth/callback",
			Scopes:       []string{"openid", "email", "profile"},
		},
	}

	di, err := model.NewDIContainer(conf)
	if err != nil {
		panic(err)
	}

	httpHandler = configureRoutes(di)
}

func configureRoutes(di *model.DI) http.Handler {
	r := mux.NewRouter()

	h := handler.Handler{DI: di}

	discoveryMetaHandler, err := h.DiscoveryMeta()
	if err != nil {
		panic(err)
	}

	r.HandleFunc("/auth/.well-known/openid-configuration", discoveryMetaHandler)

	// redirect to IdP auth login page
	authEndpoint, err := h.Auth()
	if err != nil {
		panic(err)
	}
	r.Handle("/auth/auth", authEndpoint)

	// handle successful or unsuccessful login.
	// return to initial auth_request to initally requested callback url
	r.Handle("/auth/callback", h.Callback())

	// listen for access / refresh tokens
	// exchange the authorization code or refresh token with upstream IdP
	// handle response from IdP
	// issue a tyk api key
	r.Handle("/auth/token", h.Token()).Methods(http.MethodPost)
	return r
}

// AuthPlugin catches all requests made to this api, and uses it's own internal router
// to handle auth requests & issue access tokens
func AuthPlugin(w http.ResponseWriter, r *http.Request) {
	httpHandler.ServeHTTP(w, r)
}

func main() {}
