package ninjapanda

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/rs/zerolog/log"

	"gopkg.in/yaml.v2"

	"github.com/Optm-Main/ztmesh-core/ztcfg"
)

func loadRELAYMapFromPath(path string) (*ztcfg.RELAYMap, error) {
	relayFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer relayFile.Close()
	var relayMap ztcfg.RELAYMap
	b, err := io.ReadAll(relayFile)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(b, &relayMap)

	return &relayMap, err
}

func loadRELAYMapFromURL(addr url.URL) (*ztcfg.RELAYMap, error) {
	ctx, cancel := context.WithTimeout(context.Background(), HTTPReadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr.String(), nil)
	if err != nil {
		return nil, err
	}

	client := http.Client{
		Timeout: HTTPReadTimeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var relayMap ztcfg.RELAYMap
	err = json.Unmarshal(body, &relayMap)

	return &relayMap, err
}

// mergeRELAYMaps naively merges a list of RELAYMaps into a single
// RELAYMap, it will _only_ look at the Regions, an integer.
// If a region exists in two of the given RELAYMaps, the region
// form the _last_ RELAYMap will be preserved.
// An empty RELAYMap list will result in a RELAYMap with no regions.
func mergeRELAYMaps(relayMaps []*ztcfg.RELAYMap) *ztcfg.RELAYMap {
	result := ztcfg.RELAYMap{
		OmitDefaultRegions: false,
		Regions:            map[int]*ztcfg.RELAYRegion{},
	}

	for _, relayMap := range relayMaps {
		for id, region := range relayMap.Regions {
			result.Regions[id] = region
		}
	}

	return &result
}

func GetRELAYMap(cfg RELAYConfig) *ztcfg.RELAYMap {
	relayMaps := make([]*ztcfg.RELAYMap, 0)

	for _, path := range cfg.Paths {
		log.Debug().
			Caller().
			Str(logtags.MakeTag("path"), path).
			Msg("Loading RELAYMap from path")
		relayMap, err := loadRELAYMapFromPath(path)
		if err != nil {
			log.Error().
				Caller().
				Str(logtags.MakeTag("path"), path).
				Err(err).
				Msg("Could not load RELAY map from file path")

			break
		}

		relayMaps = append(relayMaps, relayMap)
	}

	for _, addr := range cfg.URLs {
		relayMap, err := loadRELAYMapFromURL(addr)
		log.Info().
			Caller().
			Str(logtags.GetTag(logtags.relayConfig, "URLs"), addr.String()).
			Msg("Loading RELAYMap from url")
		if err != nil {
			log.Error().
				Caller().
				Str(logtags.GetTag(logtags.relayConfig, "URLs"), addr.String()).
				Err(err).
				Msg("Could not load RELAY map from path")

			break
		}

		relayMaps = append(relayMaps, relayMap)
	}

	relayMap := mergeRELAYMaps(relayMaps)

	log.Info().Caller().Interface("relayMap", relayMap).Msg("RELAYMap loaded")

	if len(relayMap.Regions) == 0 {
		log.Warn().
			Caller().
			Msg("RELAY map is empty, not a single RELAY map datasource was loaded correctly or contained a region")
	}

	return relayMap
}

func (np *Ninjapanda) scheduledRELAYMapUpdateWorker(cancelChan <-chan struct{}) {
	log.Info().
		Caller().
		Dur(logtags.GetTag(logtags.relayConfig, "UpdateFrequency"), np.cfg.RELAY.UpdateFrequency).
		Msg("Setting up a RELAYMap update worker")
	ticker := time.NewTicker(np.cfg.RELAY.UpdateFrequency)

	for {
		select {
		case <-cancelChan:
			return

		case <-ticker.C:
			np.RefreshRelayMap()
			log.Info().Caller().Msg("Fetching RELAYMap updates")

			stateUpdate := StateUpdate{
				Type:     StateRelayUpdated,
				RelayMap: np.RELAYMap,
			}
			if stateUpdate.Valid() {
				ctx := NotifyCtx(context.Background(), "relay-map-refresh", "na")
				np.notifier.NotifyAll(ctx, stateUpdate)
			}
		}
	}
}

func (np *Ninjapanda) RefreshRelayMap() {
	np.RELAYMap = GetRELAYMap(np.cfg.RELAY)
	if np.cfg.RELAY.ServerEnabled {
		np.RELAYMap.Regions[np.RELAYServer.region.RegionID] = &np.RELAYServer.region
	}
}
