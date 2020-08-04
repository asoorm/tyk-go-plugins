package dash_client

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	portalDeveloperEndpoint = "/api/portal/developers"
)

type Client struct {
	httpClient *http.Client
	baseURL string
	apiKey string
}

func NewClient(baseURL string, apiKey string) *Client {
	return &Client{
		httpClient: http.DefaultClient,
		baseURL: baseURL,
		apiKey: apiKey,
	}
}

func (c *Client) AllOauthApps() ([]OauthClient, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL + portalDeveloperEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.apiKey)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", res.StatusCode)
	}

	var resDecoded GetPortalDevelopersResponse
	err = json.NewDecoder(res.Body).Decode(&resDecoded)
	if err != nil {
		return nil, err
	}

	var apps []OauthClient
	for _, developer := range resDecoded.Data {
		// ignore inactive developers
		if developer.Inactive {
			continue
		}
		for _, mapkey := range developer.OAuthClients {
			apps = append(apps, mapkey...)
		}
	}

	return apps, nil
}
