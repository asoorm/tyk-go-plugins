package handler

import (
	"net/http"
)

func (h *Handler) DiscoveryMeta() (http.HandlerFunc, error) {

	return func(w http.ResponseWriter, r *http.Request) {
		_ = h.writeJSON(w, h.DI.Conf.GatewayClient.Discovery, http.StatusOK)
	}, nil
}
