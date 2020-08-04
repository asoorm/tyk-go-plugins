package handler

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"time"

	"github.com/asoorm/tyk-go-plugins/relying_party/dash_client"
	"github.com/asoorm/tyk-go-plugins/relying_party/model"
)

func (h *Handler) Auth() (http.HandlerFunc, error) {
	return func(w http.ResponseWriter, r *http.Request) {
		// redirect to IdP auth login page, but replace callback url with own callback url
		// pulling stuff from the request
		clientID := r.URL.Query().Get("client_id")

		// only for client_credentials
		//clientSecret := r.URL.Query().Get("client_secret")
		scope := r.URL.Query().Get("scope")
		responseType := r.URL.Query().Get("response_type")
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")

		println("=====")
		println("scope: ", scope)
		println("=====")

		// TODO: clean this shit up
		client := dash_client.NewClient("http://dashboard.ahmet:3000", "ae3d21b5256c40624511adc3ef36f453")
		apps, err := client.AllOauthApps()
		if err != nil {
			panic(err)
		}

		found := false
		var authRequest model.AuthorizationRequest
		for _, app := range apps {
			if clientID == app.ClientID && redirectURI == app.RedirectURI {
				found = true
				if state == "" {
					state = RandStringBytes(32)
				}

				authRequest.ClientID = clientID
				authRequest.ClientSecret = app.Secret // saving the need to do another lookup
				authRequest.ResponseType = responseType
				authRequest.RedirectURI = app.RedirectURI
				authRequest.State = state
				authRequest.Scope = scope

				break
			}
		}
		if !found {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(http.StatusText(http.StatusBadRequest)))
			return
		}

		jsBytes, _ := json.Marshal(authRequest)
		h.DI.DB.Set(context.Background(), "auth_request:"+state, jsBytes, time.Minute)

		authCodeURL := h.DI.Conf.UpstreamIdP.AuthCodeURL(state)
		println(authCodeURL)
		http.Redirect(w, r, authCodeURL, http.StatusFound)
	}, nil
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// TODO: crypto RAND
func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
