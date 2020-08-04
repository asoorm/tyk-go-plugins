package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/asoorm/tyk-go-plugins/relying_party/model"
	"github.com/gorilla/schema"
)

func (h *Handler) Token() http.HandlerFunc {

	//log := h.DI.Conf.Logger.WithField("path", "/token")
	db := h.DI.DB
	decoder := schema.NewDecoder()

	return func(w http.ResponseWriter, r *http.Request) {
		var err error

		err = r.ParseForm()
		if err != nil {
			//log.WithError(err).Error("parsing form")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		dump, err := httputil.DumpRequest(r, true)
		if err != nil {
			//log.WithError(err).Error("dump request")
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		println(string(dump))

		var tokenRequest model.TokenRequest
		err = decoder.Decode(&tokenRequest, r.PostForm)
		if err != nil {
			//log.WithError(err).Error("decode request")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		authCode, err := db.Get(context.Background(), "auth_code:"+tokenRequest.Code).Result()
		if err != nil {
			//log.WithError(err).Error("decode request")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		var authorizationRequest model.AuthorizationRequest
		err = json.Unmarshal([]byte(authCode), &authorizationRequest)
		if err != nil {
			//log.WithError(err).Error("unable to unmarshal json")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		var errCollector []string
		if tokenRequest.ClientID != authorizationRequest.ClientID {
			errCollector = append(errCollector, "wrong client id")
		}

		if tokenRequest.RedirectURI != authorizationRequest.RedirectURI {
			errCollector = append(errCollector, "wrong redirect uri")
		}

		if tokenRequest.ClientSecret != authorizationRequest.ClientSecret {
			errCollector = append(errCollector, "wrong client secret")
		}

		if tokenRequest.GrantType != "authorization_code" {
			errCollector = append(errCollector, "wrong grant_type")
		}

		if len(errCollector) > 0 {
			errorsJson, _ := json.Marshal(errCollector)
			println(fmt.Sprintf("errors: %s", string(errorsJson)))
			//log.WithError(errors.New("token request error")).Errorf("%#v", errCollector)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		tok, err := h.DI.Conf.UpstreamIdP.Exchange(context.Background(), tokenRequest.Code)
		if err != nil {
			//log.WithError(err).Error("problem exchanging auth code for access token")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}

		// Rather than sending token back to client - should probably create own tokens
		h.writeJSON(w, tok, http.StatusOK)
	}
}
