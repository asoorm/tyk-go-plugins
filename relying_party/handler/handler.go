package handler

import (
	"encoding/json"
	"fmt"
	"github.com/asoorm/tyk-go-plugins/relying_party/model"
	"net/http"
	"strconv"
)

type Handler struct {
	DI *model.DI
}

func (h *Handler) writeJSON(w http.ResponseWriter, data interface{}, code int) error {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(dataBytes)))
	_, err = w.Write(dataBytes)
	return err
}
