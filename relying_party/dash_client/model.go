package dash_client

type GetPortalDevelopersResponse struct {
	Data []PortalDeveloper `json:"Data"`
}

type PortalDeveloper struct {
	Inactive     bool                     `json:"inactive"`
	Email        string                   `json:"email"`
	OrgID        string                   `json:"org_id"`
	OAuthClients map[string][]OauthClient `json:"oauth_clients"`
}

type OauthClient struct {
	ClientID    string `json:"client_id"`
	Secret      string `json:"secret"`
	RedirectURI string `json:"redirect_uri"`
}
