package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/asoorm/tyk-go-plugins/relying_party/model"
)

func (h *Handler) Callback() http.HandlerFunc {

	log := h.DI.Conf.Logger.WithField("path", "/callback")
	db := h.DI.DB

	return func(w http.ResponseWriter, r *http.Request) {
		dump, err := httputil.DumpRequest(r, true)
		if err != nil {
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		println(string(dump))

		log.Info("query: ", r.URL.String())

		authorizationCode := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if authorizationCode == "" || state == "" {
			// this is an error.
			// write an error log
			// Redirect to login page

			log.Error("missing authorization code or state")

			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(http.StatusText(http.StatusNotFound)))

			return
		}

		// get the original authorization request
		authReq, err := db.Get(context.Background(), "auth_request:"+state).Result()
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(http.StatusText(http.StatusNotFound)))
			return
		}

		// clean up
		db.Del(context.Background(), "auth_request:"+state)

		var req model.AuthorizationRequest
		json.Unmarshal([]byte(authReq), &req)

		// TODO: We should probably create our own authorization code here
		// save the auth code attempt
		db.Set(context.Background(), "auth_code:"+authorizationCode, authReq, time.Minute)

		// We now got the original auth request. We can return the upstream authorization code to that user
		// replacing state with their own state, back to their own redirect_uri

		redirectURI, _ := url.Parse(req.RedirectURI)
		q := redirectURI.Query()
		q.Set("code", authorizationCode)
		q.Set("state", "code")

		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
	}
}
