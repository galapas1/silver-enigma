package ninjapanda

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/Optm-Main/ztmesh-core/ztcfg"
)

// // NoiseRegistrationHandler handles the actual registration process of a machine.
func (t *ts2021App) NoiseRegistrationHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	if req.Method != http.MethodPost {
		http.Error(writer, "Wrong method", http.StatusMethodNotAllowed)

		return
	}
	body, _ := io.ReadAll(req.Body)
	defer req.Body.Close()

	registerRequest := ztcfg.RegisterRequest{}
	if err := json.Unmarshal(body, &registerRequest); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse RegisterRequest")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		return
	}

	t.ninjapanda.handleRegisterCommon(
		context.Background(),
		writer,
		req,
		registerRequest,
		t.conn.Peer(),
		true,
	)
}
