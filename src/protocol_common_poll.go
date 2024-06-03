package ninjapanda

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/rs/zerolog/log"
	xslices "golang.org/x/exp/slices"

	"github.com/Optm-Main/ztmesh-core/ztcfg"
)

const (
	keepAliveInterval = 60 * time.Second
)

type contextKey string

const machineNameContextKey = contextKey("machineName")

func (np *Ninjapanda) handlePollCommon(
	writer http.ResponseWriter,
	ctx context.Context,
	machine *Machine,
	mapRequest ztcfg.MapRequest,
	isNoise bool,
) error {
	if machine.GivenName != mapRequest.Hostinfo.Hostname {
		log.Info().
			Caller().
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Str(logtags.GetTag(logtags.hostInfo, "Hostname"), mapRequest.Hostinfo.Hostname).
			Msg("Name change detected on device")

		np.RenameMachine(machine, mapRequest.Hostinfo.Hostname)
		np.SendMachineUpdate(machine)
	}

	np.UpdateLocation(mapRequest, machine)

	if mapRequest.OmitPeers && !mapRequest.Stream && !mapRequest.ReadOnly {
		log.Trace().
			Caller().
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Str(logtags.GetTag(logtags.hostInfo, "Hostname"), mapRequest.Hostinfo.Hostname).
			Msg("[POLL DEBUG] client requested OMIT PEERS")

		err := np.handleUpdateRequest(writer, machine, mapRequest)

		return err

	} else if mapRequest.OmitPeers && !mapRequest.Stream && mapRequest.ReadOnly {
		log.Trace().
			Caller().
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Str(logtags.GetTag(logtags.hostInfo, "Hostname"), mapRequest.Hostinfo.Hostname).
			Msg("[POLL DEBUG] client requested OMIT PEERS & READ ONLY")

		np.handleReadOnlyRequest(writer, machine, mapRequest)

		return nil

	} else if mapRequest.OmitPeers && mapRequest.Stream {
		log.Error().
			Caller().
			Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Msg("ignoring malformed request")

		return fmt.Errorf("malformed request from client: omitPeers ++ stream (ignoring)")
	}

	change := machine.PeerChangeFromMapRequest(mapRequest)

	online := true
	change.Online = &online

	machine.ApplyPeerChange(&change)

	machine.HostInfo = HostInfo(*mapRequest.Hostinfo)

	machine.OS = mapRequest.Hostinfo.OS
	machine.OSVersion = mapRequest.Hostinfo.OSVersion
	machine.Package = mapRequest.Hostinfo.Package
	machine.DeviceModel = mapRequest.Hostinfo.DeviceModel
	machine.ClientVersion = mapRequest.Hostinfo.ZTMVersion

	machine.Distro = mapRequest.Hostinfo.Distro
	machine.DistroVersion = mapRequest.Hostinfo.DistroVersion
	machine.DistroCodeName = mapRequest.Hostinfo.DistroCodeName

	machine.SessionKey = SessionPublicKeyStripPrefix(mapRequest.SessionKey)

	oldRoutes := machine.HostInfo.RoutableIPs
	newRoutes := mapRequest.Hostinfo.RoutableIPs
	if !xslices.Equal(oldRoutes, newRoutes) {
		_, err := np.ProcessMachineRoutes(machine)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
				Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
				Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
				Msg("failed to process machine routes")
			http.Error(writer, "", http.StatusInternalServerError)

			return err
		}
	}

	if err := np.db.Save(machine).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Error().
				Caller().
				Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
				Msg("machine not found")
		}
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Msg("failed to update machine")
		http.Error(writer, "", http.StatusInternalServerError)

		return err
	}

	np.pollNetMapStreamWG.Add(1)
	defer np.pollNetMapStreamWG.Done()

	updateChan := make(chan StateUpdate, np.cfg.ClientPollQueueSize)
	defer closeChanWithLog(updateChan, machine.Hostname, "updateChan")

	np.notifier.AddMachine(machine.MachineKey, updateChan)
	defer np.notifier.RemoveMachine(machine.MachineKey)

	peers, err := np.ListPeersByPolicy(machine)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Msg("failed to list peers")
		http.Error(writer, "", http.StatusInternalServerError)

		return err
	}

	isConnected := np.notifier.ConnectedMap()

	for _, peer := range peers {
		online := isConnected[peer.MachineKey] || peer.isOnline()
		peer.IsOnline = &online
	}

	mapp := NewMapper(
		np,
		machine,
		peers,
		np.RELAYMap,
		np.cfg.BaseDomain,
		np.cfg.DNSConfig,
		false, // client debug flag
		np.cfg.RandomizeClientPort,
	)

	if np.aclPolicy != nil {
		_, err = np.EnableAutoApprovedRoutes(machine)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
				Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
				Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
				Msg("failed to auto approve routes")
		}
	}

	log.Info().
		Caller().
		Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
		Msg("sending initial map")

	mapResp, err := np.FullMapResponse(mapp, mapRequest, machine, np.aclPolicy)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Msg("failed to create response")
		http.Error(writer, "", http.StatusInternalServerError)

		return err
	}

	// Send the client an update to make sure we send an initial response
	_, err = writer.Write(mapResp)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Msg("failed to write response")

		return err
	}

	np.TouchMachine(machine)

	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	} else {
		return fmt.Errorf("failed to flush writer")
	}

	stateUpdate := StateUpdate{
		Type:            StatePeerChanged,
		ChangedMachines: Machines{*machine},
		Message:         "called from handlePoll -> new machine added",
	}
	if stateUpdate.Valid() {
		ctx := NotifyCtx(
			context.Background(),
			"poll-new-machine-added",
			machine.Hostname,
		)
		np.notifier.NotifyWithIgnore(
			ctx,
			stateUpdate,
			machine.MachineKey,
		)
	}

	machineRoutes, _ := np.GetMachineRoutes(machine)
	if len(machineRoutes) > 0 {
		go np.pollForFailoverRoutes("new machine", machine)
	}

	keepAliveTicker := time.NewTicker(keepAliveInterval)

	ctx = context.WithValue(ctx, machineNameContextKey, machine.Hostname)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		log.Info().
			Caller().
			Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Msg("waiting for update on stream")
		select {
		case <-keepAliveTicker.C:
			data, err := mapp.KeepAliveResponse(mapRequest, machine)
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
					Msg("failed to generate keep-alive")

				return err
			}
			_, err = writer.Write(data)
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
					Msg("failed to write keep-alive")

				return err
			}
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			} else {
				return fmt.Errorf("Failed to create http flusher")
			}

			go np.updateNodeOnlineStatus(true, machine)

		case update := <-updateChan:
			log.Info().
				Caller().
				Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
				Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
				Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
				Msg("received update")

			startResponseTime := time.Now()

			var data []byte
			var err error

			machine, err = np.GetMachineByMachineKey(machine.MachineKey)
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
					Msg("failed to find machine by machine_key")

				return fmt.Errorf("failed to find machine by machine_key")
			}

			switch update.Type {
			case StateFullUpdate:
				log.Info().
					Caller().
					Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
					Int(logtags.MakeTag("updateType"), int(update.Type)).
					Msg("sending full update")
				data, err = np.FullMapResponse(mapp, mapRequest, machine, np.aclPolicy)

			case StatePeerChanged:
				log.Info().
					Caller().
					Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
					Str(logtags.MakeTag("update_message"), update.Message).
					Int(logtags.MakeTag("updateType"), int(update.Type)).
					Msg("sending peer changed")

				isConnected := np.notifier.ConnectedMap()
				for _, machine := range update.ChangedMachines {
					isOnline := isConnected[machine.MachineKey] || machine.isOnline()
					machine.IsOnline = &isOnline
				}

				updatedPeers, err := np.ListPeersByPolicy(machine)
				if err != nil {
					log.Error().
						Caller().
						Err(err).
						Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
						Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
						Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
						Msg("failed to list peers")
					http.Error(writer, "", http.StatusInternalServerError)

					return err
				}

				data, err = np.PeerChangedResponse(mapp,
					mapRequest,
					machine,
					update.ChangedMachines,
					updatedPeers,
					update.Message,
				)
			case StatePeerChangedPatch:
				log.Info().
					Caller().
					Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
					Int(logtags.MakeTag("updateType"), int(update.Type)).
					Msg("sending peer changed patched")

				updatedPeers, err := np.ListPeersByPolicy(machine)
				if err != nil {
					log.Error().
						Caller().
						Err(err).
						Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
						Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
						Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
						Msg("failed to list peers")
					http.Error(writer, "", http.StatusInternalServerError)

					return err
				}

				data, err = mapp.PeerChangedPatchResponse(
					mapRequest,
					machine,
					update.ChangePatches,
					updatedPeers,
					np.aclPolicy,
				)
			case StatePeerRemoved:
				log.Info().
					Caller().
					Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
					Int(logtags.MakeTag("updateType"), int(update.Type)).
					Msg("sending peer removed")

				data, err = mapp.PeerRemovedResponse(
					mapRequest,
					machine,
					update.Removed,
				)
			case StateSelfUpdate:
				if len(update.ChangedMachines) == 1 {
					log.Info().
						Caller().
						Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
						Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
						Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
						Int(logtags.MakeTag("updateType"), int(update.Type)).
						Msg("sending self update")

					machine = &update.ChangedMachines[0]
					data, err = np.LiteMapResponse(mapp, mapRequest, machine)
				} else {
					log.Error().
						Caller().
						Err(err).
						Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
						Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
						Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
						Msg("self update error (too many machines): internal error")
				}
			case StateRelayUpdated:
				log.Info().
					Caller().
					Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
					Int(logtags.GetTag(logtags.stateUpdate, "Type"), int(update.Type)).
					Msg("sending relay update")
				data, err = mapp.RELAYMapResponse(mapRequest, machine, update.RelayMap)
			}

			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
					Msg("failed to create map update")

				return err
			}

			log.Info().
				Caller().
				Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
				Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
				Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
				TimeDiff(logtags.MakeTag("timeSpent"), time.Now(), startResponseTime).
				Int(logtags.MakeTag("updateType"), int(update.Type)).
				Msg("response construction done")

			if data != nil {
				startWriteTime := time.Now()
				_, err = writer.Write(data)
				if err != nil {
					log.Error().
						Caller().
						Err(err).
						Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
						Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
						Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
						Msg("failed to write response")

					user, _ := np.GetUserProfileByMachineId(machine.MachineId, true)
					username := "---"
					if user != nil {
						username = user.LoginName
					}
					updateRequestsSentToMachine.WithLabelValues(username, machine.GivenName, "failed").
						Inc()

					return err
				}

				if flusher, ok := writer.(http.Flusher); ok {
					flusher.Flush()
				} else {
					log.Error().Caller().Err(err).Msg("Failed to create http flusher")

					return fmt.Errorf("failed to flush")
				}

				log.Trace().
					Caller().
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
					TimeDiff(logtags.MakeTag("TimeSpent"), time.Now(), startWriteTime).
					Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
					Int(logtags.GetTag(logtags.stateUpdate, "Type"), int(update.Type)).
					Msg("finished writing response")

				log.Info().
					Caller().
					Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
					TimeDiff("timeSpent", time.Now(), startResponseTime).
					Msg("update sent")

				user, _ := np.GetUserProfileByMachineId(machine.MachineId, true)
				username := "---"
				if user != nil {
					username = user.LoginName
				}
				updateRequestsSentToMachine.WithLabelValues(username, machine.GivenName, "success").
					Inc()
			}

		case <-ctx.Done():
			log.Info().
				Caller().
				Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
				Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
				Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
				Msg("done: client closed connection")

			go np.updateNodeOnlineStatus(false, machine)

			go np.pollForFailoverRoutes("machine left", machine)

			return nil

		case <-np.shutdownChan:
			log.Info().
				Caller().
				Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
				Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
				Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
				Msg("long poll handler shutdown")

			return nil
		}
	}
}

func (np *Ninjapanda) handleUpdateRequest(
	writer http.ResponseWriter,
	machine *Machine,
	mapRequest ztcfg.MapRequest,
) error {
	log.Info().
		Caller().
		Bool(logtags.GetTag(logtags.mapRequest, "ReadOnly"), mapRequest.ReadOnly).
		Bool(logtags.GetTag(logtags.mapRequest, "OmitPeers"), mapRequest.OmitPeers).
		Bool(logtags.GetTag(logtags.mapRequest, "Stream"), mapRequest.Stream).
		Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
		Int(logtags.GetTag(logtags.mapRequest, "Version"), int(mapRequest.Version)).
		Msg("update request received")

	change := machine.PeerChangeFromMapRequest(mapRequest)

	online := np.notifier.IsConnected(machine.MachineKey)
	change.Online = &online

	machine.ApplyPeerChange(&change)

	hostInfoEqual := mapRequest.Hostinfo.Equal(machine.GetHostInfo())

	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
		Bool(logtags.MakeTag("HostInfoEqual"), hostInfoEqual).
		Interface(logtags.GetTag(logtags.stateUpdate, ""), change).
		Msg("update request change")

	if !hostInfoEqual {
		oldRoutes := machine.HostInfo.RoutableIPs
		newRoutes := mapRequest.Hostinfo.RoutableIPs

		oldServicesCount := len(machine.HostInfo.Services)
		newServicesCount := len(mapRequest.Hostinfo.Services)

		machine.HostInfo = HostInfo(*mapRequest.Hostinfo)

		machine.OS = mapRequest.Hostinfo.OS
		machine.OSVersion = mapRequest.Hostinfo.OSVersion
		machine.Package = mapRequest.Hostinfo.Package
		machine.DeviceModel = mapRequest.Hostinfo.DeviceModel
		machine.ClientVersion = mapRequest.Hostinfo.ZTMVersion

		machine.Distro = mapRequest.Hostinfo.Distro
		machine.DistroVersion = mapRequest.Hostinfo.DistroVersion
		machine.DistroCodeName = mapRequest.Hostinfo.DistroCodeName

		sendUpdate := false

		if !xslices.Equal(oldRoutes, newRoutes) {
			var err error
			sendUpdate, err = np.ProcessMachineRoutes(machine)
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
					Msg("failed to process machine routes")
				http.Error(writer, "", http.StatusInternalServerError)

				return err
			}

			if np.aclPolicy != nil {
				update, err := np.EnableAutoApprovedRoutes(machine)
				if err != nil {
					log.Error().
						Caller().
						Err(err).
						Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
						Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
						Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
						Msg("failed to auto approve routes")
				}

				if update != nil {
					sendUpdate = true
				}
			}
		}

		sessionKey := SessionPublicKeyStripPrefix(mapRequest.SessionKey)
		if machine.SessionKey != sessionKey {
			machine.SessionKey = sessionKey
			sendUpdate = true
		}

		if oldServicesCount != newServicesCount {
			sendUpdate = true
		}

		if sendUpdate {
			stateUpdate := StateUpdate{
				Type:            StatePeerChanged,
				ChangedMachines: Machines{*machine},
				Message:         "called from handlePoll->update->new hostinfo",
			}
			if stateUpdate.Valid() {
				ctx := NotifyCtx(
					context.Background(),
					"poll-update-state-hostinfo",
					machine.Hostname,
				)
				np.notifier.NotifyWithIgnore(
					ctx,
					stateUpdate,
					machine.MachineKey)
			}

			selfUpdate := StateUpdate{
				Type:            StateSelfUpdate,
				ChangedMachines: Machines{*machine},
			}
			if selfUpdate.Valid() {
				ctx := NotifyCtx(
					context.Background(),
					"poll-update-self-hostinfo",
					machine.Hostname,
				)
				np.notifier.NotifyByMachineKey(
					ctx,
					selfUpdate,
					machine.MachineKey)
			}
		}
	}

	if err := np.db.Save(machine).Error; err != nil {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.machine, "MachineId"), machine.MachineId).
			Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Msg("machine update failed")
	}

	np.TouchMachine(machine)

	stateUpdate := StateUpdate{
		Type:          StatePeerChangedPatch,
		ChangePatches: []*ztcfg.PeerChange{&change},
	}
	if stateUpdate.Valid() {
		ctx := NotifyCtx(
			context.Background(),
			"poll-update-peers-patch",
			machine.Hostname,
		)
		np.notifier.NotifyWithIgnore(
			ctx,
			stateUpdate,
			machine.MachineKey)
	}

	writer.WriteHeader(http.StatusOK)
	if f, ok := writer.(http.Flusher); ok {
		f.Flush()
	}

	return nil
}

func (np *Ninjapanda) handleReadOnlyRequest(
	writer http.ResponseWriter,
	machine *Machine,
	mapRequest ztcfg.MapRequest,
) {
	mapp := NewMapper(
		np,
		machine,
		Machines{},
		np.RELAYMap,
		np.cfg.BaseDomain,
		np.cfg.DNSConfig,
		false, // client debug flag
		np.cfg.RandomizeClientPort,
	)

	log.Trace().
		Caller().
		Bool(logtags.GetTag(logtags.mapRequest, "ReadOnly"), mapRequest.ReadOnly).
		Bool(logtags.GetTag(logtags.mapRequest, "OmitPeers"), mapRequest.OmitPeers).
		Bool(logtags.GetTag(logtags.mapRequest, "Stream"), mapRequest.Stream).
		Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
		Msg("read-only request, responding without peers")

	mapResp, err := np.LiteMapResponse(mapp, mapRequest, machine)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Bool(logtags.GetTag(logtags.mapRequest, "ReadOnly"), mapRequest.ReadOnly).
			Bool(logtags.GetTag(logtags.mapRequest, "OmitPeers"), mapRequest.OmitPeers).
			Bool(logtags.GetTag(logtags.mapRequest, "Stream"), mapRequest.Stream).
			Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Msg("failed to create lite response")

		http.Error(writer, "", http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(mapResp)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Bool(logtags.GetTag(logtags.mapRequest, "ReadOnly"), mapRequest.ReadOnly).
			Bool(logtags.GetTag(logtags.mapRequest, "OmitPeers"), mapRequest.OmitPeers).
			Bool(logtags.GetTag(logtags.mapRequest, "Stream"), mapRequest.Stream).
			Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Msg("failed to write response")
	}
}

func (np *Ninjapanda) updateNodeOnlineStatus(online bool, machine *Machine) {
	nowInUtc := time.Now().UTC()

	np.TouchMachine(machine)

	statusUpdate := StateUpdate{
		Type: StatePeerChangedPatch,
		ChangePatches: []*ztcfg.PeerChange{
			{
				NodeID:   ztcfg.NodeID(machine.ID),
				Online:   &online,
				LastSeen: &nowInUtc,
			},
		},
	}
	if statusUpdate.Valid() {
		ctx := NotifyCtx(
			context.Background(),
			"poll-machine-update-onlinestatus",
			machine.Hostname,
		)
		np.notifier.NotifyWithIgnore(ctx, statusUpdate, machine.MachineKey)
	}
}

func closeChanWithLog[C chan []byte | chan struct{} | chan StateUpdate](
	channel C,
	machine, name string,
) {
	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine).
		Msg(fmt.Sprintf("Closing %s channel", name))

	close(channel)
}

func (np *Ninjapanda) pollForFailoverRoutes(where string, machine *Machine) {
	update, err := np.EnsureFailoverRouteIsAvailable(
		np.notifier.ConnectedMap(),
		machine,
	)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Msgf("failed to ensure failover routes, %s", where)

		return
	}

	if update != nil && !update.Empty() && update.Valid() {
		ctx := NotifyCtx(
			context.Background(),
			fmt.Sprintf(
				"poll-%s-routes-ensurefailover",
				strings.ReplaceAll(where, " ", "-"),
			),
			machine.Hostname,
		)
		np.notifier.NotifyWithIgnore(ctx, *update, machine.MachineKey)
	}
}
