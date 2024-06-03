package ninjapanda

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/Optm-Main/ztmesh-core/ztcfg"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

type MachineKafkaMessage struct {
	np            *Ninjapanda
	CorrelationId string
	Machine       *Machine
	NetInfo       *ztcfg.NetInfo
}

func (msg *MachineKafkaMessage) Marshal(topic string) string {
	var b []byte
	var err error

	switch topic {
	case "machine.update":
		msg.Machine.Hostname = msg.Machine.hostnameToFQDN(
			msg.np.cfg.BaseDomain,
			msg.np.DNSConfigForNamespace(msg.Machine.Namespace.Name),
		)
		machineResponseProto := &v1.GetMachineResponse{
			Machine: msg.Machine.sanitize().toProto(),
		}
		userProfile, _ := msg.np.GetUserProfileByMachineId(
			msg.Machine.MachineId,
			!IncludeTaggedDevice,
		)
		if userProfile != nil {
			machineResponseProto.Machine.UserInfo = userProfile.toProto()
		}
		if msg.NetInfo != nil {
			preferredRelayId := int(
				msg.NetInfo.PreferredRELAY,
			)
			if preferredRelayId >= 0 {
				if preferredRelay, ok := msg.np.RELAYMap.Regions[preferredRelayId]; ok {
					machineResponseProto.Machine.PreferredRelay = preferredRelay.RegionName
				}
			}
			regx := regexp.MustCompile(`-`)
			// TODO: do we need to expose this?
			// if len(msg.NetInfo.ExitNodeLatency) > 0 {
			// }
			if len(msg.NetInfo.RELAYLatency) > 0 {
				machineResponseProto.Machine.RelayLatency = make(map[string]float64)
				for k, v := range msg.NetInfo.RELAYLatency {
					toks := regx.Split(k, -1)
					for id, region := range msg.np.RELAYMap.Regions {
						keyId, _ := strconv.Atoi(toks[0])
						if keyId == id {
							// if NetInfo does not contain a valid preferred relay index,
							// take the first region for which latency is reported --hack
							if len(machineResponseProto.Machine.PreferredRelay) == 0 {
								machineResponseProto.Machine.PreferredRelay = region.RegionName
							}
							machineResponseProto.Machine.GetRelayLatency()[region.RegionName] = float64(
								v,
							)
						}
					}
				}
			}
		} else {
			log.Debug().
				Caller().
				Str(logtags.GetTag(logtags.machine, "MachineId"), msg.Machine.MachineId).
				Msg("no relay latency reported")
		}
		b, err = protojson.Marshal(machineResponseProto)
	case "machine.register":
		msg.Machine.Hostname = msg.Machine.hostnameToFQDN(
			msg.np.cfg.BaseDomain,
			msg.np.DNSConfigForNamespace(msg.Machine.Namespace.Name),
		)
		b, err = protojson.Marshal(
			&v1.RegisterMachineResponse{
				Machine:       msg.Machine.sanitize().toProto(),
				CorrelationId: msg.CorrelationId,
			},
		)
	case "machine.delete":
		b, err = protojson.Marshal(
			&v1.DeleteMachineResponse{
				MachineId: msg.Machine.MachineId,
			},
		)
	default:
		err = fmt.Errorf("Unsupported Machine Kafka Message Topic: %s", topic)
	}

	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to prepare kafka message")
	}

	msgPayload := string(b)

	log.Trace().
		Caller().
		Str(logtags.MakeTag("topic"), topic).
		Str(logtags.MakeTag("MachineKafkaMessage"), msgPayload).
		Msg("Marshal")

	return msgPayload
}

func (np *Ninjapanda) SendMachineUpdateByMachineKey(mKey string) {
	if np.kafkaClient.IsEnabled() {
		machine, err := np.GetMachineByMachineKey(mKey)
		if err != nil {
			// uh-oh... what to do?
		}
		np.SendMachineUpdate(machine)
	}
}

func (np *Ninjapanda) SendMachineUpdate(machine *Machine) {
	if np.kafkaClient.IsEnabled() {
		netInfo := machine.GetNetInfo()

		topic := "machine.update"
		msg := MachineKafkaMessage{
			np:      np,
			Machine: machine,
			NetInfo: netInfo,
		}
		err := np.kafkaClient.PushToTopic(
			topic,
			msg.Marshal(topic),
			msg.Machine.Namespace.ExternalId,
		)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("error pushing to kafka update topic")
		}
	}
}
