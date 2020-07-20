package handler

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"time"

	"github.com/asoorm/tyk-go-plugins/relying_party/model"
)

func (h *Handler) Auth() (http.HandlerFunc, error) {
	return func(w http.ResponseWriter, r *http.Request) {
		// redirect to IdP auth login page, but replace callback url with own callback url
		// pulling stuff from the request
		clientID := r.URL.Query().Get("client_id")

		// only for client_credentials
		clientSecret := r.URL.Query().Get("client_secret")
		scope := r.URL.Query().Get("scope")
		responseType := r.URL.Query().Get("response_type")
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")

		// TODO: validate the request better than we do now
		if clientID == "" || scope == "" || responseType == "" || redirectURI == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(http.StatusText(http.StatusBadRequest)))
			return
		}

		if state == "" {
			state = RandStringBytes(10)
		}

		authRequest := model.AuthorizationRequest{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			ResponseType: responseType,
			RedirectURI:  redirectURI,
			State:        state,
		}

		jsBytes, _ := json.Marshal(authRequest)
		h.DI.DB.Set(context.Background(), "auth_request:"+state, jsBytes, time.Minute)

		authCodeURL := h.DI.Conf.UpstreamIdP.AuthCodeURL(state)

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
