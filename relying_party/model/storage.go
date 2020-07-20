package model

type AuthorizationRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	ResponseType string `json:"response_type"`
	RedirectURI  string `json:"redirect_uri"`
	State        string `json:"state"`
}
