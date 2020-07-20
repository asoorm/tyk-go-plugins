package model

type AuthorizationCodeQueryResponse struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

type TokenRequest struct {
	GrantType    string `json:"grant_type" schema:"grant_type"`
	ClientID     string `json:"client_id "schema:"client_id"`
	ClientSecret string `json:"client_secret" schema:"client_secret"`
	Code         string `json:"code" schema:"code"`
	RedirectURI  string `json:"redirect_uri" schema:"redirect_uri"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}
