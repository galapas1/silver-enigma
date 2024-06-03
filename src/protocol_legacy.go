package ninjapanda

import (
	"context"
	"io"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/rs/zerolog/log"

	"github.com/Optm-Main/ztmesh-core/types/key"
	"github.com/Optm-Main/ztmesh-core/ztcfg"
)

// RegistrationHandler handles the actual registration process of a machine
// Endpoint /machine/:mkey.
func (np *Ninjapanda) RegistrationHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	machineKeyStr, ok := vars["mkey"]
	if !ok || machineKeyStr == "" {
		log.Error().
			Caller().
			Msg("No machine ID in request")
		http.Error(writer, "No machine ID in request", http.StatusBadRequest)

		return
	}

	body, _ := io.ReadAll(req.Body)
	defer req.Body.Close()

	var machineKey key.MachinePublic
	err := machineKey.UnmarshalText([]byte(MachinePublicKeyEnsurePrefix(machineKeyStr)))
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse machine key")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		http.Error(writer, "Cannot parse machine key", http.StatusBadRequest)

		return
	}
	registerRequest := ztcfg.RegisterRequest{}
	err = decode(body, &registerRequest, &machineKey, np.privateKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot decode message")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		http.Error(writer, "Cannot decode message", http.StatusBadRequest)

		return
	}

	np.handleRegisterCommon(
		context.Background(),
		writer,
		req,
		registerRequest,
		machineKey,
		false,
	)
}
