package model

import (
	"context"
	"golang.org/x/oauth2"

	"github.com/go-redis/redis/v8"
)

type Conf struct {
	//Logger        *logrus.Logger
	Storage       Storage
	BaseURL       string
	GatewayClient GatewayClient
	UpstreamIdP   oauth2.Config
}

type GatewayClient struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Discovery    DiscoveryMeta
}

type Storage struct {
	Address  string
	Password string
	DB       int
}

type DI struct {
	DB   *redis.Client
	Conf Conf
}

func NewDIContainer(c Conf) (*DI, error) {
	ctx := context.Background()

	rdb := redis.NewClient(&redis.Options{
		Addr:     c.Storage.Address,
		Password: c.Storage.Password, // no password set
		DB:       c.Storage.DB,       // use default DB
	})

	_, err := rdb.Ping(ctx).Result()

	if err != nil {
		return nil, err
	}

	return &DI{
		DB:   rdb,
		Conf: c,
	}, nil
}

type DiscoveryMeta struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	Keys                  string   `json:"keys"`
	UserInfo              string   `json:"user_info"`
	Subjects              []string `json:"subjects"`
	Callback              string   `json:"callback,omitempty"`
}
