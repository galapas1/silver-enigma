package ninjapanda

import (
	"encoding/json"

	"github.com/Optm-Main/ztmesh-core/types/key"

	"github.com/rs/zerolog/log"
)

func (np *Ninjapanda) marshalResponse(
	resp interface{},
	machineKey key.MachinePublic,
	isNoise bool,
) ([]byte, error) {
	jsonBody, err := json.Marshal(resp)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot marshal response")

		return nil, err
	}

	if isNoise {
		return jsonBody, nil
	}

	return np.privateKey.SealTo(machineKey, jsonBody), nil
}
