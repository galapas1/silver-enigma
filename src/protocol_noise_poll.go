package ninjapanda

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"

	"gorm.io/gorm"

	"github.com/Optm-Main/ztmesh-core/ztcfg"
)

// NoisePollNetMapHandler takes care of /machine/:id/map using the Noise protocol
//
// This is the busiest endpoint, as it keeps the HTTP long poll that updates
// the clients when something in the network changes.
//
// The clients POST stuff like HostInfo and their Endpoints here, but
// only after their first request (marked with the ReadOnly field).
//
// At this moment the updates are sent in a quite horrendous way, but they kinda work.
func (t *ts2021App) NoisePollNetMapHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	emitMetrics := startEmitTimer()

	log.Trace().
		Caller().
		Msg("entered")
	body, _ := io.ReadAll(req.Body)
	defer req.Body.Close()

	mapRequest := ztcfg.MapRequest{}
	if err := json.Unmarshal(body, &mapRequest); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse MapRequest")
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		emitMetrics("error")
		return
	}

	machine, err := t.ninjapanda.GetMachineByAnyKey(
		t.conn.Peer(),
		mapRequest.NodeKey,
	)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Warn().
				Caller().
				Str(logtags.GetTag(logtags.mapRequest, "NodeKey"), mapRequest.NodeKey.String()).
				Msg("Ignoring request, cannot find machine")
			http.Error(writer, "Internal error", http.StatusForbidden)

			emitMetrics("error")
			return
		}
		log.Error().
			Caller().
			Str(logtags.GetTag(logtags.mapRequest, "NodeKey"), mapRequest.NodeKey.String()).
			Msg("Failed to fetch machine from the database")
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		emitMetrics("error")
		return
	}
	log.Debug().
		Caller().
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Msg("A machine is entering polling via the Noise protocol")

	err = t.ninjapanda.handlePollCommon(
		writer,
		req.Context(),
		machine,
		mapRequest,
		true,
	)
	if err != nil {
		emitMetrics("error")
	}

	emitMetrics("success")
}
