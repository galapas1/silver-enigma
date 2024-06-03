package ninjapanda

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"

	"gorm.io/gorm"

	"github.com/Optm-Main/ztmesh-core/types/key"
	"github.com/Optm-Main/ztmesh-core/ztcfg"
)

// PollNetMapHandler takes care of /machine/:id/map
//
// This is the busiest endpoint, as it keeps the HTTP long poll that updates
// the clients when something in the network changes.
//
// The clients POST stuff like HostInfo and their Endpoints here, but
// only after their first request (marked with the ReadOnly field).
//
// At this moment the updates are sent in a quite horrendous way, but they kinda work.
func (np *Ninjapanda) PollNetMapHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	emitMetrics := startEmitTimer()

	vars := mux.Vars(req)

	machineKeyStr, ok := vars["mkey"]
	if !ok || machineKeyStr == "" {
		log.Error().
			Caller().
			Msg("No machine key in request")
		http.Error(writer, "No machine key in request", http.StatusBadRequest)

		emitMetrics("error")
		return
	}

	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "MachineKey"), machineKeyStr).
		Send()

	body, _ := io.ReadAll(req.Body)

	var machineKey key.MachinePublic
	err := machineKey.UnmarshalText([]byte(MachinePublicKeyEnsurePrefix(machineKeyStr)))
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse client key")

		http.Error(writer, "Cannot parse client key", http.StatusBadRequest)

		emitMetrics("error")
		return
	}

	mapRequest := ztcfg.MapRequest{}
	err = decode(body, &mapRequest, &machineKey, np.privateKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot decode message")

		http.Error(writer, "Cannot decode message", http.StatusBadRequest)

		emitMetrics("error")
		return
	}

	machine, err := np.GetMachineByMachineKey(machineKey.String())
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Warn().
				Caller().
				Str(logtags.GetTag(logtags.machine, "MachineKey"), machineKey.String()).
				Msg("Ignoring request, cannot find machine")

			http.Error(writer, "", http.StatusUnauthorized)

			emitMetrics("error")
			return
		}

		log.Error().
			Caller().
			Str(logtags.GetTag(logtags.machine, "MachineKey"), machineKey.String()).
			Msg("Failed to fetch machine from the database")

		http.Error(writer, "", http.StatusInternalServerError)

		emitMetrics("error")
		return
	}

	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "MachineKey"), machineKeyStr).
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Msg("A machine is entering polling via the legacy protocol")

	err = np.handlePollCommon(writer, context.Background(), machine, mapRequest, false)
	if err != nil {
		emitMetrics("error")
		return
	}

	emitMetrics("success")
	return
}
