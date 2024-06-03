package ninjapanda

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"

	"gorm.io/gorm"

	"github.com/Optm-Main/ztmesh-core/types/key"
	"github.com/Optm-Main/ztmesh-core/ztcfg"
)

const (
	NoiseCapabilityVersion = 39
)

// KeyHandler provides the Ninjapanda pub key
// Listens in /key.
func (np *Ninjapanda) KeyHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	// New clients send a 'v' parameter to indicate the CurrentCapabilityVersion
	clientCapabilityStr := req.URL.Query().Get("v")
	if len(clientCapabilityStr) > 0 {
		log.Debug().
			Caller().
			Str(logtags.MakeTag("v"), clientCapabilityStr).
			Msg("New noise client")
		clientCapabilityVersion, err := strconv.Atoi(clientCapabilityStr)
		if err != nil {
			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.WriteHeader(http.StatusBadRequest)
			_, err := writer.Write([]byte("Wrong params"))
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Failed to write response")
			}

			return
		}

		// TS2021 (v2 protocol) requires to have a different key
		if clientCapabilityVersion >= NoiseCapabilityVersion {
			resp := ztcfg.OverTLSPublicKeyResponse{
				LegacyPublicKey: np.privateKey.Public(),
				PublicKey:       np.noisePrivateKey.Public(),
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			err = json.NewEncoder(writer).Encode(resp)
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Failed to write response")
			}

			return
		}
	}
	log.Debug().
		Caller().
		Msg("New legacy client")

	// Old clients don't send a 'v' parameter, so we send the legacy public key
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err := writer.Write([]byte(MachinePublicKeyStripPrefix(np.privateKey.Public())))
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

// handleRegisterCommon is the common logic for registering a client in the legacy and Noise protocols
//
// When using Noise, the machineKey is Zero.
func (np *Ninjapanda) handleRegisterCommon(
	ctx context.Context,
	writer http.ResponseWriter,
	req *http.Request,
	registerRequest ztcfg.RegisterRequest,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	nowInUtc := time.Now().UTC()
	machine, err := np.GetMachineByAnyKey(
		machineKey,
		registerRequest.NodeKey,
	)

	if errors.Is(err, gorm.ErrRecordNotFound) {
		// If the machine has AuthKey set, handle registration via PreAuthKeys
		if len(registerRequest.Auth.AuthKey) > 0 {
			np.handleAuthKeyCommon(ctx, writer, registerRequest, machineKey, isNoise)

			return
		}

		// Check if the node is waiting for interactive login.
		//
		// TODO: We could use this field to improve our protocol implementation,
		// and hold the request until the client closes it, or the interactive
		// login is completed (i.e., the user registers the machine).
		// This is not implemented yet, as it is no strictly required. The only side-effect
		// is that the client will hammer ninjapanda with requests until it gets a
		// successful RegisterResponse.
		if len(registerRequest.Followup) > 0 {
			followupUrl, err := url.Parse(registerRequest.Followup)
			if err != nil {
				log.Error().
					Caller().
					Str(logtags.GetTag(logtags.registerRequest, "Followup"), registerRequest.Followup).
					Err(err).
					Msg("failed to parse followup url")

				return
			}

			correlationId := followupUrl.Query().Get("state")
			if len(correlationId) == 0 {
				log.Debug().
					Caller().
					Str(logtags.GetTag(logtags.registerRequest, "Followup"), registerRequest.Followup).
					Msg("failed to parse state from followup url... going old school")

				correlationId, _ = getCorrelationId(
					ctx,
					np.registrationCache,
					NodePublicKeyStripPrefix(registerRequest.NodeKey),
				)
			}

			if registrationStatus, ok := np.registrationCache.SearchMachineRegistration(ctx, correlationId); ok {
				log.Trace().
					Caller().
					Interface(logtags.MakeTag("RegistrationStatus"), registrationStatus).
					Bool(logtags.MakeTag("ok"), ok).
					Send()

				if "success" == registrationStatus.Status {
					np.handleMachineValidRegistrationCommon(
						writer,
						registrationStatus.Machine,
						machineKey,
						isNoise,
					)
					return
				}

				log.Debug().
					Caller().
					Str(logtags.GetTag(logtags.hostInfo, "Hostname"), registerRequest.Hostinfo.Hostname).
					Str(logtags.GetTag(logtags.machine, "MachineKey"), machineKey.ShortString()).
					Str(logtags.GetTag(logtags.registerRequest, "NodeKey"), registerRequest.NodeKey.ShortString()).
					Str(logtags.GetTag(logtags.registerRequest, "Followup"), registerRequest.Followup).
					Str(logtags.MakeTag("CorrelationId"), correlationId).
					Bool(logtags.MakeTag("isNoise"), isNoise).
					Msg("Machine is waiting for interactive login")

				ticker := time.NewTicker(registrationHoldoff)
				select {
				case <-req.Context().Done():
					return
				case <-ticker.C:
					np.handleNewMachineCommon(
						ctx,
						writer,
						registerRequest,
						machineKey,
						isNoise,
					)

					return
				}
			} else {
				// If the registration info expired out of the cache, then send a Conflict error code
				// but silently ignore this request.
				log.Info().
					Str(logtags.MakeTag("CorrelationId"), correlationId).
					Msg("Key forgotten from registration cache")
				writer.WriteHeader(http.StatusConflict)
				return
			}
		}

		log.Info().
			Caller().
			Str(logtags.GetTag(logtags.hostInfo, "Hostname"), registerRequest.Hostinfo.Hostname).
			Str(logtags.GetTag(logtags.machine, "MachineKey"), machineKey.ShortString()).
			Str(logtags.GetTag(logtags.registerRequest, "NodeKey"), registerRequest.NodeKey.ShortString()).
			Str(logtags.GetTag(logtags.registerRequest, "Followup"), registerRequest.Followup).
			Bool(logtags.MakeTag("IsNoise"), isNoise).
			Msg("New machine not yet in the database")

		givenName, err := np.GenerateGivenName(
			machineKey.String(),
			0, // indicates 'in-flight' registration
			registerRequest.Hostinfo.Hostname,
		)
		if err != nil {
			log.Error().
				Caller().
				Str(logtags.GetTag(logtags.hostInfo, "Hostname"), registerRequest.Hostinfo.Hostname).
				Err(err).
				Msg("exiting handler")

			return
		}

		// The machine did not have a key to authenticate, which means
		// that we rely on a method that calls back some how (OpenID or CLI)
		// We create the machine and then keep it around until a callback
		// happens
		machineId, _ := uuid.NewV4()
		newMachine := Machine{
			MachineKey: MachinePublicKeyStripPrefix(machineKey),
			MachineId:  machineId.String(),
			Hostname:   registerRequest.Hostinfo.Hostname,
			GivenName:  givenName,
			NodeKey:    NodePublicKeyStripPrefix(registerRequest.NodeKey),

			OS:            registerRequest.Hostinfo.OS,
			OSVersion:     registerRequest.Hostinfo.OSVersion,
			Package:       registerRequest.Hostinfo.Package,
			DeviceModel:   registerRequest.Hostinfo.DeviceModel,
			ClientVersion: registerRequest.Hostinfo.ZTMVersion,

			Distro:         registerRequest.Hostinfo.Distro,
			DistroVersion:  registerRequest.Hostinfo.DistroVersion,
			DistroCodeName: registerRequest.Hostinfo.DistroCodeName,

			LastSeen: &nowInUtc,
			Expiry:   &time.Time{},
		}

		if !registerRequest.Expiry.IsZero() {
			log.Trace().
				Caller().
				Bool(logtags.MakeTag("isNoise"), isNoise).
				Str(logtags.GetTag(logtags.hostInfo, "Hostname"), registerRequest.Hostinfo.Hostname).
				Time(logtags.GetTag(logtags.registerRequest, "Expiry"), registerRequest.Expiry).
				Msg("Non-zero expiry time requested")
			newMachine.Expiry = &registerRequest.Expiry
		}

		correlationId, isNewId := getCorrelationId(
			ctx,
			np.registrationCache,
			NodePublicKeyStripPrefix(registerRequest.NodeKey),
		)
		if isNewId && np.kafkaClient.IsEnabled() {
			topic := "machine.register"
			msg := MachineKafkaMessage{
				np:            np,
				CorrelationId: correlationId,
				Machine:       &newMachine,
			}
			err := np.kafkaClient.PushToTopic(
				topic,
				msg.Marshal(topic),
				newMachine.Namespace.ExternalId,
			)
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("error pushing to kafka register topic")
			}
		}

		log.Trace().
			Caller().
			Str(logtags.MakeTag("CorrelationId"), correlationId).
			Interface(logtags.GetTag(logtags.machine, ""), newMachine).
			Msg("Caching registration request")

		np.registrationCache.StoreMachineRegistration(
			ctx,
			correlationId,
			MachineRegistrationStatus{
				Status:  "pending-register",
				Machine: newMachine,
			},
			registerCacheExpiration,
		)

		np.handleNewMachineCommon(ctx, writer, registerRequest, machineKey, isNoise)

		return
	}

	// The machine is already in the DB. This could mean one of the following:
	// - The machine is authenticated and ready to /map
	// - We are doing a key refresh
	// - The machine is logged out (or expired) and pending to be authorized.
	// TODO: We need to keep alive the connection here
	if machine != nil {
		// For a while we had a bug where we were not storing the MachineKey for the nodes using the TS2021,
		// due to a misunderstanding of the protocol https://github.com/juanfont/headscale/issues/1054
		// So if we have a not valid MachineKey (but we were able to fetch the machine with the NodeKeys), we update it.
		var storedMachineKey key.MachinePublic
		err = storedMachineKey.UnmarshalText(
			[]byte(MachinePublicKeyEnsurePrefix(machine.MachineKey)),
		)
		if err != nil || storedMachineKey.IsZero() {
			machine.MachineKey = MachinePublicKeyStripPrefix(machineKey)
			if err := np.db.Save(&machine).Error; err != nil {
				log.Error().
					Caller().
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Err(err).
					Msg("Error saving machine key to database")

				return
			}
		}

		// If the NodeKey stored in ninjapanda is the same as the key presented in a registration
		// request, then we have a node that is either:
		// - Trying to log out (sending a expiry in the past)
		// - A valid, registered machine, looking for /map
		// - Expired machine wanting to reauthenticate
		if machine.NodeKey == NodePublicKeyStripPrefix(registerRequest.NodeKey) {
			if !registerRequest.Expiry.IsZero() &&
				registerRequest.Expiry.UTC().Before(nowInUtc) {
				np.handleMachineLogOutCommon(
					writer,
					*machine,
					machineKey,
					isNoise,
				)

				return
			}

			// If machine is not expired, and it is register, we have already accepted this machine,
			// let it proceed with a valid registration
			if !machine.isExpired() {
				np.handleMachineValidRegistrationCommon(
					writer,
					*machine,
					machineKey,
					isNoise,
				)

				return
			}
		}

		if len(registerRequest.Followup) > 0 {
			// We have already send the followup URL, but the user's client
			// is contining to hit this endpoint to see if the machine
			// has been refreshed --> we want to hold them off so to not spam
			// them.
			ticker := time.NewTicker(registrationHoldoff)
			select {
			case <-req.Context().Done():
				return
			case <-ticker.C:
				np.handleMachineExpiredOrLoggedOutCommon(
					ctx,
					writer,
					registerRequest,
					*machine,
					machineKey,
					isNoise,
				)
				return
			}
		}

		// TODO: RegisterRequest includes an Expiry time, that we could optionally use
		machine.Expiry = &time.Time{}

		// If we are here it means the client needs to be reauthorized,
		// we need to make sure the NodeKey matches the one in the request
		// TODO: What happens when using fast user switching between two
		// ninjapanda-managed ztnets?
		machine.NodeKey = NodePublicKeyStripPrefix(registerRequest.NodeKey)
		correlationId, _ := getCorrelationId(
			ctx,
			np.registrationCache,
			"", // force new correlationId
		)
		np.registrationCache.StoreMachineRegistration(
			ctx,
			correlationId,
			MachineRegistrationStatus{
				Status:  "pending-renewal",
				Machine: *machine,
			},
			registerCacheExpiration,
		)

		// The machine has expired or it is logged out
		np.handleMachineExpiredOrLoggedOutCommon(
			ctx,
			writer,
			registerRequest,
			*machine,
			machineKey,
			isNoise,
		)
		return
	}
}

// handleAuthKeyCommon contains the logic to manage auth key client registration
// It is used both by the legacy and the new Noise protocol.
// When using Noise, the machineKey is Zero.
//
// TODO: check if any locks are needed around IP allocation.
func (np *Ninjapanda) handleAuthKeyCommon(
	ctx context.Context,
	writer http.ResponseWriter,
	registerRequest ztcfg.RegisterRequest,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := ztcfg.RegisterResponse{}

	sendErrorResponse := func(err error, pak *PreAuthKey, statusCode int) {
		var namespaceName string = "unknown"
		if pak != nil {
			namespaceName = pak.Namespace.Name
		}
		machineRegistrations.WithLabelValues("new",
			RegisterMethodAuthKey, "error", namespaceName).
			Inc()

		log.Error().
			Caller().
			Bool(logtags.MakeTag("isNoise"), isNoise).
			Str(logtags.GetTag(logtags.hostInfo, "Hostname"), registerRequest.Hostinfo.Hostname).
			Msg("Failed authentication via AuthKey")

		resp.MachineAuthorized = false

		respBody, err := np.marshalResponse(resp, machineKey, isNoise)
		if err != nil {
			log.Error().
				Caller().
				Str(logtags.GetTag(logtags.hostInfo, "Hostname"), registerRequest.Hostinfo.Hostname).
				Bool(logtags.MakeTag("isNoise"), isNoise).
				Err(err).
				Msg("Cannot encode message")
			http.Error(writer, "Internal server error", http.StatusInternalServerError)

			return
		}

		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(statusCode)
		_, err = writer.Write(respBody)
		if err != nil {
			log.Error().
				Caller().
				Bool(logtags.MakeTag("isNoise"), isNoise).
				Err(err).
				Msg("Failed to write response")
		}
	}

	log.Debug().
		Caller().
		Str(logtags.GetTag(logtags.hostInfo, "Hostname"), registerRequest.Hostinfo.Hostname).
		Bool(logtags.MakeTag("isNoise"), isNoise).
		Msg("Processing auth key")

	pak, err := np.checkKeyValidityByAuthKey(registerRequest.Auth.AuthKey)
	if err != nil {
		sendErrorResponse(err, pak, http.StatusUnauthorized)
		return
	}

	log.Debug().
		Caller().
		Bool(logtags.MakeTag("isNoise"), isNoise).
		Str(logtags.GetTag(logtags.hostInfo, "Hostname"), registerRequest.Hostinfo.Hostname).
		Msg("Authentication key was valid, proceeding to acquire IP addresses")

	nodeKey := NodePublicKeyStripPrefix(registerRequest.NodeKey)

	// retrieve machine information if it exist
	// The error is not important, because if it does not
	// exist, then this is a new machine and we will move
	// on to registration.
	machine, _ := np.GetMachineByAnyKey(
		machineKey,
		registerRequest.NodeKey,
	)
	if machine != nil {
		if pak.Namespace.Name != machine.Namespace.Name {
			sendErrorResponse(
				fmt.Errorf(
					"pak namespace (%s) not equal machine namespace (%s), reassignment disallowed",
					pak.Namespace.Name,
					machine.Namespace.Name,
				),
				pak,
				http.StatusUnauthorized,
			)
			return
		}
		log.Trace().
			Caller().
			Bool(logtags.MakeTag("isNoise"), isNoise).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Msg("machine was already registered before, refreshing with new auth key")

		machine.NodeKey = nodeKey
		machine.AuthKeyID = uint(pak.ID)
		err := np.RefreshMachine(machine, registerRequest.Expiry)
		if err != nil {
			log.Error().
				Caller().
				Bool(logtags.MakeTag("isNoise"), isNoise).
				Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
				Err(err).
				Msg("Failed to refresh machine")

			return
		}

		aclTags := pak.toProto(false).AclTags
		if len(aclTags) > 0 {
			// This conditional preserves the existing behaviour,
			// although SaaS would reset the tags on auth-key login
			err = np.SetTags(machine, aclTags)

			if err != nil {
				log.Error().
					Caller().
					Bool(logtags.MakeTag("isNoise"), isNoise).
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Strs(logtags.GetTag(logtags.preAuthKey, "ACLTags"), aclTags).
					Err(err).
					Msg("Failed to set tags after refreshing machine")

				return
			}
		}
	} else {
		nowInUtc := time.Now().UTC()

		givenName, err := np.GenerateGivenName(
			MachinePublicKeyStripPrefix(machineKey),
			pak.Namespace.ID,
			registerRequest.Hostinfo.Hostname,
		)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Bool(logtags.MakeTag("isNoise"), isNoise).
				Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
				Msg("exiting handler")

			return
		}

		machineToRegister := Machine{
			Hostname:       registerRequest.Hostinfo.Hostname,
			GivenName:      givenName,
			Namespace:      pak.Namespace,
			NamespaceID:    pak.Namespace.ID,
			MachineKey:     MachinePublicKeyStripPrefix(machineKey),
			RegisterMethod: RegisterMethodAuthKey,
			Expiry:         &registerRequest.Expiry,
			NodeKey:        nodeKey,
			LastSeen:       &nowInUtc,
			AuthKeyID:      uint(pak.ID),
			ForcedTags:     pak.toProto(false).AclTags,
		}

		// see if org is allowed another machine
		allowed, err := np.grpcCheckLicense(nil, &machineToRegister, MachinesPerOrg)
		if !allowed || err != nil {
			sendErrorResponse(err, pak, http.StatusForbidden)
			return
		}

		machine, err = np.RegisterMachine(ctx, machineToRegister)
		if err != nil {
			log.Error().
				Caller().
				Bool(logtags.MakeTag("isNoise"), isNoise).
				Err(err).
				Msg("could not register machine")

			machineRegistrations.WithLabelValues("new",
				RegisterMethodAuthKey, "error", pak.Namespace.Name).
				Inc()

			http.Error(writer, "Internal server error", http.StatusInternalServerError)

			return
		}
	}

	err = np.UsePreAuthKey(pak)
	if err != nil {
		log.Error().
			Caller().
			Bool(logtags.MakeTag("isNoise"), isNoise).
			Err(err).
			Msg("Failed to use pre-auth key")

		machineRegistrations.WithLabelValues("new",
			RegisterMethodAuthKey, "error", pak.Namespace.Name).
			Inc()

		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.MachineAuthorized = true
	resp.User = *np.getUserForMachine(machine.MachineId)
	// Provide LoginName when registering with pre-auth key
	// Otherwise it will need to exec `ztclient up` twice to fetch the *LoginName*
	resp.Login = *np.getLoginForMachine(machine.MachineId)
	resp.KeySigningAuthorityDetails = key.KeySigningAuthorityDetails{
		KeyServerUrl: np.cfg.KeySigning.KeyServerUrl,
	}

	respBody, err := np.marshalResponse(resp, machineKey, isNoise)
	if err != nil {
		log.Error().
			Caller().
			Bool(logtags.MakeTag("isNoise"), isNoise).
			Str(logtags.GetTag(logtags.hostInfo, "Hostname"), registerRequest.Hostinfo.Hostname).
			Err(err).
			Msg("Cannot encode message")

		machineRegistrations.WithLabelValues("new",
			RegisterMethodAuthKey, "error", pak.Namespace.Name).
			Inc()

		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	machineRegistrations.WithLabelValues("new",
		RegisterMethodAuthKey, "success", pak.Namespace.Name).
		Inc()

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Bool(logtags.MakeTag("isNoise"), isNoise).
			Err(err).
			Msg("Failed to write response")

		return
	}

	log.Info().
		Caller().
		Bool(logtags.MakeTag("isNoise"), isNoise).
		Str(logtags.GetTag(logtags.hostInfo, "Hostname"), registerRequest.Hostinfo.Hostname).
		Str(logtags.GetTag(logtags.machine, "IPAddresses"), strings.Join(machine.IPAddresses.ToStringSlice(), ", ")).
		Msg("Successfully authenticated via AuthKey")
}

// handleNewMachineCommon exposes for both legacy and Noise the functionality to get a URL
// for authorizing the machine. This url is then showed to the user by the local client.
func (np *Ninjapanda) handleNewMachineCommon(
	ctx context.Context,
	writer http.ResponseWriter,
	registerRequest ztcfg.RegisterRequest,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := ztcfg.RegisterResponse{}
	// The machine registration is new, redirect the client to the registration URL
	log.Debug().
		Caller().
		Bool(logtags.MakeTag("isNoise"), isNoise).
		Str(logtags.GetTag(logtags.hostInfo, "Hostname"), registerRequest.Hostinfo.Hostname).
		Msg("The node seems to be new, sending auth url")

	// Try grabbing a custom auth URL first, if applicable
	customAuthURL, err := np.handleCustomMachineAuthURL(ctx, registerRequest)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot process custom machine URL")

		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	if len(customAuthURL) > 0 {
		resp.AuthURL = customAuthURL
	} else if np.oauth2Config != nil {
		resp.AuthURL = fmt.Sprintf(
			"%s/oidc/register/%s",
			strings.TrimSuffix(np.cfg.ServerURL, "/"),
			registerRequest.NodeKey,
		)
	} else {
		log.Trace().
			Caller().
			Msg("no custom auth url, no oauth2... building url")

		resp.AuthURL = fmt.Sprintf("%s/register/%s",
			strings.TrimSuffix(np.cfg.ServerURL, "/"),
			registerRequest.NodeKey)
	}

	respBody, err := np.marshalResponse(resp, machineKey, isNoise)
	if err != nil {
		log.Error().
			Caller().
			Bool(logtags.MakeTag("isNoise"), isNoise).
			Str(logtags.GetTag(logtags.registerResponse, "AuthURL"), resp.AuthURL).
			Err(err).
			Msg("Cannot encode message")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Bool(logtags.MakeTag("isNoise"), isNoise).
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Caller().
		Bool(logtags.MakeTag("isNoise"), isNoise).
		Str(logtags.GetTag(logtags.hostInfo, "Hostname"), registerRequest.Hostinfo.Hostname).
		Msg("Successfully sent auth url")

	return
}

func (np *Ninjapanda) handleMachineLogOutCommon(
	writer http.ResponseWriter,
	machine Machine,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := ztcfg.RegisterResponse{}

	log.Info().
		Bool(logtags.MakeTag("isNoise"), isNoise).
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Msg("Client requested logout")

	err := np.ExpireMachine(&machine)
	if err != nil {
		log.Error().
			Caller().
			Bool(logtags.MakeTag("isNoise"), isNoise).
			Err(err).
			Msg("Failed to expire machine")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	nowInUtc := time.Now().UTC()
	stateUpdate := StateUpdate{
		Type: StatePeerChangedPatch,
		ChangePatches: []*ztcfg.PeerChange{
			{
				NodeID:    ztcfg.NodeID(machine.ID),
				KeyExpiry: &nowInUtc,
			},
		},
	}

	if stateUpdate.Valid() {
		ctx := NotifyCtx(context.Background(), "client-logout", "na")
		np.notifier.NotifyWithIgnore(ctx, stateUpdate, machine.MachineKey)
	}

	err = np.DisassociateUserProfileByMachineId(machine.MachineId)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("failed to remove machine to user profile mapping")
	}

	resp.AuthURL = ""
	resp.MachineAuthorized = false
	resp.NodeKeyExpired = true
	resp.User = *np.getUserForMachine(machine.MachineId)
	respBody, err := np.marshalResponse(resp, machineKey, isNoise)
	if err != nil {
		log.Error().
			Caller().
			Bool(logtags.MakeTag("isNoise"), isNoise).
			Err(err).
			Msg("Cannot encode message")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Bool(logtags.MakeTag("isNoise"), isNoise).
			Err(err).
			Msg("Failed to write response")

		return
	}

	np.SendMachineUpdate(&machine)

	if machine.isEphemeral() {
		err = np.HardDeleteMachine(&machine, np.notifier.ConnectedMap())
		if err != nil {
			log.Error().
				Err(err).
				Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
				Msg("Failed to delete ephemeral machine from the database")
		}

		stateUpdate := StateUpdate{
			Type:    StatePeerRemoved,
			Removed: []ztcfg.NodeID{ztcfg.NodeID(machine.ID)},
		}

		if stateUpdate.Valid() {
			ctx := NotifyCtx(context.Background(), "logout-ephemeral", "na")
			np.notifier.NotifyAll(ctx, stateUpdate)
		}

		return
	}

	log.Info().
		Caller().
		Bool(logtags.MakeTag("isNoise"), isNoise).
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Msg("Successfully logged out")
}

func (np *Ninjapanda) handleMachineValidRegistrationCommon(
	writer http.ResponseWriter,
	machine Machine,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := ztcfg.RegisterResponse{}

	// The machine registration is valid, respond with redirect to /map
	log.Debug().
		Caller().
		Bool(logtags.MakeTag("isNoise"), isNoise).
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Msg("Client is registered and we have the current NodeKey. All clear to /map")

	resp.AuthURL = ""
	resp.MachineAuthorized = true
	resp.User = *np.getUserForMachine(machine.MachineId)
	resp.Login = *np.getLoginForMachine(machine.MachineId)
	resp.KeySigningAuthorityDetails = key.KeySigningAuthorityDetails{
		KeyServerUrl: np.cfg.KeySigning.KeyServerUrl,
	}

	respBody, err := np.marshalResponse(resp, machineKey, isNoise)
	if err != nil {
		log.Error().
			Caller().
			Bool(logtags.MakeTag("isNoise"), isNoise).
			Err(err).
			Msg("Cannot encode message")

		machineRegistrations.WithLabelValues("update",
			"web", "error", machine.Namespace.Name).
			Inc()

		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	machineRegistrations.WithLabelValues("update",
		"web", "success", machine.Namespace.Name).
		Inc()

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Bool(logtags.MakeTag("isNoise"), isNoise).
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Caller().
		Bool(logtags.MakeTag("isNoise"), isNoise).
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Msg("Machine successfully authorized")
}

func (np *Ninjapanda) handleMachineExpiredOrLoggedOutCommon(
	ctx context.Context,
	writer http.ResponseWriter,
	registerRequest ztcfg.RegisterRequest,
	machine Machine,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := ztcfg.RegisterResponse{}

	if len(registerRequest.Auth.AuthKey) > 0 {
		np.handleAuthKeyCommon(ctx, writer, registerRequest, machineKey, isNoise)

		return
	}

	// Try grabbing a custom auth URL first, if applicable
	customAuthURL, err := np.handleCustomMachineAuthURL(ctx, registerRequest)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot process custom machine URL")

		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	// The client has registered before, but has expired or logged out
	log.Trace().
		Caller().
		Bool(logtags.MakeTag("isNoise"), isNoise).
		Str(logtags.GetTag(logtags.machine, "NodeKey"), registerRequest.NodeKey.ShortString()).
		Str(logtags.GetTag(logtags.machine, "MachineKey"), machineKey.ShortString()).
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Msg("Machine registration has expired or logged out. Sending a auth url to register")

	if len(customAuthURL) > 0 {
		resp.AuthURL = customAuthURL
	} else if np.oauth2Config != nil {
		resp.AuthURL = fmt.Sprintf("%s/oidc/register/%s",
			strings.TrimSuffix(np.cfg.ServerURL, "/"),
			registerRequest.NodeKey)
	} else {
		log.Trace().
			Caller().
			Msg("no custom auth url, no oauth2... building url")

		correlationId, _ := getCorrelationId(
			ctx,
			np.registrationCache,
			"", // force new correlationId
		)

		resp.AuthURL = fmt.Sprintf("%s/register/%s",
			strings.TrimSuffix(np.cfg.ServerURL, "/"),
			correlationId)
	}

	respBody, err := np.marshalResponse(resp, machineKey, isNoise)
	if err != nil {
		log.Error().
			Caller().
			Bool(logtags.MakeTag("isNoise"), isNoise).
			Err(err).
			Msg("Cannot encode message")

		machineRegistrations.WithLabelValues("reauth",
			"web", "error", machine.Namespace.Name).
			Inc()

		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	machineRegistrations.WithLabelValues("reauth",
		"web", "success", machine.Namespace.Name).
		Inc()

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Bool(logtags.MakeTag("isNoise"), isNoise).
			Err(err).
			Msg("Failed to write response")
	}

	log.Trace().
		Caller().
		Bool(logtags.MakeTag("isNoise"), isNoise).
		Str(logtags.GetTag(logtags.machine, "MachineKey"), machineKey.ShortString()).
		Str(logtags.GetTag(logtags.machine, "NodeKey"), registerRequest.NodeKey.ShortString()).
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Msg("Machine logged out. Sent AuthURL for reauthentication")
}

func (np *Ninjapanda) handleCustomMachineAuthURL(
	ctx context.Context,
	registerRequest ztcfg.RegisterRequest,
) (authURL string, err error) {
	if len(registerRequest.Followup) > 0 {
		log.Trace().
			Caller().
			Str(logtags.GetTag(logtags.registerRequest, "Followup"), registerRequest.Followup).
			Msg("client register request already has followup")

		return registerRequest.Followup, nil
	}

	customAuthURL := np.cfg.MachineAuthorizationURL
	if len(customAuthURL) == 0 {
		// no custom URL set, not enabled...
		return "", nil
	}
	correlationId, isNewId := getCorrelationId(
		ctx,
		np.registrationCache,
		NodePublicKeyStripPrefix(registerRequest.NodeKey),
	)
	machineRegistrationStatus, ok := np.registrationCache.SearchMachineRegistration(
		ctx,
		correlationId,
	)
	if !ok {
		err = fmt.Errorf(
			"Node key = %s: %v",
			NodePublicKeyStripPrefix(registerRequest.NodeKey),
			ErrMachineNotFoundRegistrationCache,
		)
		log.Error().
			Caller().
			Err(err).
			Msg("Machine not in Cache")

		return "", err
	}

	log.Trace().
		Caller().
		Interface("registration_status", machineRegistrationStatus).
		Bool("success", ok).
		Msg("handleRegisterCommon get from cache")

	machine := machineRegistrationStatus.Machine

	// undefined on register, defined on re-register
	if len(machine.MachineId) == 0 ||
		bytes.Count(
			[]byte(machine.MachineId),
			[]byte{'0'},
		) == len(
			machine.MachineId,
		) {
		machineId, _ := uuid.NewV4()
		machine.MachineId = machineId.String()
	}

	machine.OS = registerRequest.Hostinfo.OS
	machine.OSVersion = registerRequest.Hostinfo.OSVersion
	machine.Package = registerRequest.Hostinfo.Package
	machine.DeviceModel = registerRequest.Hostinfo.DeviceModel
	machine.ClientVersion = registerRequest.Hostinfo.ZTMVersion

	machine.Distro = registerRequest.Hostinfo.Distro
	machine.DistroVersion = registerRequest.Hostinfo.DistroVersion
	machine.DistroCodeName = registerRequest.Hostinfo.DistroCodeName

	u, err := url.Parse(customAuthURL)
	if err != nil {
		err = fmt.Errorf(
			"Node key = %s: %v",
			NodePublicKeyStripPrefix(registerRequest.NodeKey),
			ErrMachineAuthorizationUrlInvalid,
		)
		log.Error().
			Caller().
			Err(err).
			Msg("Invalid MachineAuthorizationURL")

		return "", err
	}

	q := u.Query()
	q.Set("state", correlationId)
	u.RawQuery = q.Encode()
	authURL = u.String()

	// Send the register request to trigger the user to authenticate themselves
	if isNewId && np.kafkaClient.IsEnabled() {
		topic := "machine.register"
		msg := MachineKafkaMessage{
			np:            np,
			CorrelationId: correlationId,
			Machine:       &machine,
		}
		err := np.kafkaClient.PushToTopic(
			topic,
			msg.Marshal(topic),
			machine.Namespace.ExternalId,
		)
		if err != nil {
			log.Error().
				Caller().
				Str("func", "handleCustomMachineAuthURL").
				Err(err).
				Msg("error pushing to kafka register topic")
		}
	}

	np.registrationCache.StoreMachineRegistration(
		ctx,
		correlationId,
		MachineRegistrationStatus{
			Status:  "pending-auth",
			Machine: machine,
		},
		registerCacheExpiration,
	)

	return authURL, nil
}

func getCorrelationId(
	ctx context.Context,
	regCache *CacheClient,
	nodeKey string,
) (string, bool) {
	if len(nodeKey) > 0 {
		registrations, err := regCache.GetMachineRegistrations(ctx)
		if err != nil {
			return "", false
		}
		for key, item := range registrations {
			registrationStatus := item
			machine := registrationStatus.Machine
			if nodeKey == machine.NodeKey {
				log.Debug().
					Caller().
					Str(logtags.GetTag(logtags.machine, "NodeKey"), nodeKey).
					Str(logtags.MakeTag("CorrelationId"), key).
					Msg("returning key by brute force")
				return key, false
			}
		}
	}

	cid, _ := uuid.NewV4()
	correlationId := cid.String()

	log.Debug().
		Caller().
		Str(logtags.MakeTag("CorrelationId"), correlationId).
		Msg("created new id")

	return correlationId, true
}
