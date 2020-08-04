package dash_client

import (
	"testing"
)

const (
	mockResponse = `{
  "Data":[
    {
      "id":"5ea21401767e023b5bd2186b",
      "email":"ahmet@tyk.io",
      "date_created":"2020-04-23T23:17:37.487+01:00",
      "inactive":false,
      "org_id":"5d67b96d767e02015ea84a6f",
      "keys":{},
      "subscriptions":{},
      "fields":{},
      "nonce":"",
      "sso_key":"",
      "oauth_clients":{
        "5f16cc41d3626e582e6eabfa":[
          {
            "client_id":"55e88c34ef504e9ebf8d7d4fc342fa6f",
            "secret":"YWY4NzkzNjUtMDc2YS00YTBkLTkwNmQtNTlhZjM5MDc4Y2U3",
            "redirect_uri":"http://localhost:3001/authorization-code",
            "app_description":"foo bar baz",
            "use_case":"",
            "date_created":"2020-07-21T12:46:34.299+01:00"
          }
        ]
      },
      "password_max_days":0,
      "password_updated":"2020-04-23T23:17:37.546+01:00",
      "PWHistory":[],
      "last_login_date":"2020-07-06T10:46:20.392+01:00"
    }
  ],
  "Pages":1
}`
)

func TestClient_AllOauthApps(t *testing.T) {
	client := NewClient("http://dashboard.ahmet:3000", "APIKEY")
	oauthApps, err := client.AllOauthApps()
	if err != nil {
		panic(err.Error())
	}

	t.Logf("%#v\n", oauthApps)
}
