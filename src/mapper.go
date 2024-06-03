package ninjapanda

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"

	"github.com/Optm-Main/ztmesh-core/envknob"
	"github.com/Optm-Main/ztmesh-core/smallzstd"
	"github.com/Optm-Main/ztmesh-core/types/key"
	"github.com/Optm-Main/ztmesh-core/ztcfg"
)

const (
	mapperIDLength       = 8
	debugMapResponsePerm = 0o755
)

var debugDumpMapResponsePath = envknob.String("HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH")

// One Mapper instance per machine attached to the open stream between
// ninjapanda and client.
type Mapper struct {
	np               *Ninjapanda
	relayMap         *ztcfg.RELAYMap
	baseDomain       string
	dnsCfg           *ztcfg.DNSConfig
	logtail          bool
	randomClientPort bool

	uid     string
	created time.Time
	seq     uint64

	mu      sync.Mutex
	peers   map[uint64]*Machine
	patches map[uint64][]patch
}

type patch struct {
	timestamp time.Time
	change    *ztcfg.PeerChange
}

func NewMapper(
	np *Ninjapanda,
	machine *Machine,
	peers Machines,
	relayMap *ztcfg.RELAYMap,
	baseDomain string,
	dnsCfg *ztcfg.DNSConfig,
	logtail bool,
	randomClientPort bool,
) *Mapper {
	log.Debug().
		Caller().
		Str("machine", machine.Hostname).
		Msg("creating new mapper")

	uid, _ := GenerateRandomStringDNSSafe(mapperIDLength)

	return &Mapper{
		np:               np,
		relayMap:         relayMap,
		baseDomain:       baseDomain,
		dnsCfg:           dnsCfg,
		logtail:          logtail,
		randomClientPort: randomClientPort,

		uid:     uid,
		created: time.Now(),
		seq:     0,

		peers:   peers.IDMap(),
		patches: make(map[uint64][]patch),
	}
}

func (m *Mapper) String() string {
	return fmt.Sprintf(
		"Mapper: { seq: %d, uid: %s, created: %s }",
		m.seq,
		m.uid,
		m.created,
	)
}

func (np *Ninjapanda) fullMapResponse(
	m *Mapper,
	machine *Machine,
	pol *ACLPolicy,
	capVer ztcfg.CapabilityVersion,
) (*ztcfg.MapResponse, error) {
	peers := machineMapToList(m.peers)

	userProfile, _ := np.GetUserProfileByMachineId(
		machine.MachineId,
		IncludeTaggedDevice,
	)
	resp, err := m.baseWithConfigMapResponse(machine, pol, capVer, userProfile)
	if err != nil {
		return nil, err
	}

	err = np.appendPeerChanges(
		resp,
		machine,
		capVer,
		peers,
		peers,
		m.baseDomain,
		m.dnsCfg,
		m.randomClientPort,
	)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (np *Ninjapanda) FullMapResponse(
	m *Mapper,
	mapRequest ztcfg.MapRequest,
	machine *Machine,
	pol *ACLPolicy,
) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// refersh peers...
	updatedPeers, err := np.ListPeersByPolicy(machine)
	if err != nil {
		log.Error().
			Caller().
			Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Msg("failed to list peers")

		return nil, err
	}

	isConnected := np.notifier.ConnectedMap()

	m.peers = updatedPeers.IDMap()
	for _, machine := range updatedPeers {
		machineCopy := machine

		online := isConnected[machineCopy.MachineKey] || machineCopy.isOnline()
		machineCopy.IsOnline = &online

		m.peers[machineCopy.ID] = &machineCopy
	}

	if len(m.patches) > 0 {
		m.patches = make(map[uint64][]patch)
	}

	resp, err := np.fullMapResponse(m, machine, pol, mapRequest.Version)
	if err != nil {
		return nil, err
	}

	return m.marshalMapResponse(mapRequest, resp, machine, mapRequest.Compress)
}

func (np *Ninjapanda) LiteMapResponse(
	m *Mapper,
	mapRequest ztcfg.MapRequest,
	machine *Machine,
	messages ...string,
) ([]byte, error) {
	userProfile, _ := np.GetUserProfileByMachineId(
		machine.MachineId,
		IncludeTaggedDevice,
	)
	resp, err := m.baseWithConfigMapResponse(
		machine,
		np.aclPolicy,
		mapRequest.Version,
		userProfile,
	)
	if err != nil {
		return nil, err
	}

	rules, sshPolicy, err := np.GenerateFilterAndSSHRules(
		np.aclPolicy,
		machine,
		machineMapToList(m.peers),
	)
	if err != nil {
		return nil, err
	}

	resp.PacketFilter = ReduceFilterRules(machine, rules)
	resp.SSHPolicy = sshPolicy

	return m.marshalMapResponse(
		mapRequest,
		resp,
		machine,
		mapRequest.Compress,
		messages...)
}

func (m *Mapper) KeepAliveResponse(
	mapRequest ztcfg.MapRequest,
	machine *Machine,
) ([]byte, error) {
	resp := m.baseMapResponse()
	resp.KeepAlive = true

	return m.marshalMapResponse(mapRequest, &resp, machine, mapRequest.Compress)
}

func (m *Mapper) RELAYMapResponse(
	mapRequest ztcfg.MapRequest,
	machine *Machine,
	relayMap *ztcfg.RELAYMap,
) ([]byte, error) {
	m.relayMap = relayMap

	resp := m.baseMapResponse()
	resp.RELAYMap = relayMap

	return m.marshalMapResponse(mapRequest, &resp, machine, mapRequest.Compress)
}

func (np *Ninjapanda) PeerChangedResponse(
	m *Mapper,
	mapRequest ztcfg.MapRequest,
	machine *Machine,
	changed Machines,
	updatedPeers Machines,
	messages ...string,
) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	isConnected := np.notifier.ConnectedMap()

	for _, machine := range changed {
		if patches, ok := m.patches[machine.ID]; ok {
			online := isConnected[machine.MachineKey] || machine.isOnline()
			machine.IsOnline = &online

			for _, p := range patches {
				machine.ApplyPeerChange(p.change)
			}

			delete(m.patches, machine.ID)
		}
	}

	m.peers = updatedPeers.IDMap()
	for _, machine := range updatedPeers {
		machineCopy := machine

		online := isConnected[machineCopy.MachineKey] || machineCopy.isOnline()
		machineCopy.IsOnline = &online

		m.peers[machineCopy.ID] = &machineCopy
	}

	resp := m.baseMapResponse()

	err := np.appendPeerChanges(
		&resp,
		machine,
		mapRequest.Version,
		machineMapToList(m.peers),
		changed,
		m.baseDomain,
		m.dnsCfg,
		m.randomClientPort,
	)
	if err != nil {
		return nil, err
	}

	return m.marshalMapResponse(
		mapRequest,
		&resp,
		machine,
		mapRequest.Compress,
		messages...)
}

func (m *Mapper) PeerChangedPatchResponse(
	mapRequest ztcfg.MapRequest,
	machine *Machine,
	changed []*ztcfg.PeerChange,
	updatedPeers Machines,
	pol *ACLPolicy,
) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sendUpdate := false
	for _, change := range changed {
		if peer, ok := m.peers[uint64(change.NodeID)]; ok {
			peer.ApplyPeerChange(change)
			sendUpdate = true

			continue
		}

		for _, machine := range updatedPeers {
			if ztcfg.NodeID(machine.ID) == change.NodeID {
				log.Trace().
					Caller().
					Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
					Msgf("peer(nodeId=%d) missing for machine, saving as patch", change.NodeID)

				p := patch{
					timestamp: time.Now(),
					change:    change,
				}

				if patches, ok := m.patches[uint64(change.NodeID)]; ok {
					m.patches[uint64(change.NodeID)] = append(patches, p)
				} else {
					m.patches[uint64(change.NodeID)] = []patch{p}
				}
			}
		}
	}

	if !sendUpdate {
		return nil, nil
	}

	resp := m.baseMapResponse()
	resp.PeersChangedPatch = changed

	log.Trace().
		Caller().
		Interface("PeersChangedPatch", changed).
		Msg("[MAP DEBUG] Sending PeerChangedPatchResponse")

	return m.marshalMapResponse(mapRequest, &resp, machine, mapRequest.Compress)
}

func (m *Mapper) PeerRemovedResponse(
	mapRequest ztcfg.MapRequest,
	machine *Machine,
	removed []ztcfg.NodeID,
) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	notYetRemoved := []ztcfg.NodeID{}

	for _, id := range removed {
		if _, ok := m.peers[uint64(id)]; ok {
			notYetRemoved = append(notYetRemoved, id)
		}

		delete(m.peers, uint64(id))
		delete(m.patches, uint64(id))
	}

	resp := m.baseMapResponse()
	resp.PeersRemoved = notYetRemoved

	log.Trace().
		Caller().
		Interface("PeersRemoved", notYetRemoved).
		Msg("[MAP DEBUG] Sending PeerRemovedResponse")

	return m.marshalMapResponse(mapRequest, &resp, machine, mapRequest.Compress)
}

func (m *Mapper) marshalMapResponse(
	mapRequest ztcfg.MapRequest,
	resp *ztcfg.MapResponse,
	machine *Machine,
	compression string,
	messages ...string,
) ([]byte, error) {
	atomic.AddUint64(&m.seq, 1)

	jsonBody, err := json.Marshal(resp)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot marshal map response")
	}

	if debugDumpMapResponsePath != "" {
		data := map[string]interface{}{
			"Messages":    messages,
			"MapRequest":  mapRequest,
			"MapResponse": resp,
		}

		responseType := "keepalive"

		switch {
		case resp.Peers != nil && len(resp.Peers) > 0:
			responseType = "full"
		case isSelfUpdate(messages...):
			responseType = "self"
		case resp.Peers == nil && resp.PeersChanged == nil && resp.PeersChangedPatch == nil:
			responseType = "lite"
		case resp.PeersChanged != nil && len(resp.PeersChanged) > 0:
			responseType = "changed"
		case resp.PeersChangedPatch != nil && len(resp.PeersChangedPatch) > 0:
			responseType = "patch"
		case resp.PeersRemoved != nil && len(resp.PeersRemoved) > 0:
			responseType = "removed"
		}

		body, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Cannot marshal map response")
		}

		perms := fs.FileMode(debugMapResponsePerm)
		mPath := path.Join(debugDumpMapResponsePath, machine.Hostname)
		err = os.MkdirAll(mPath, perms)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Cannot mkdir")
		}

		now := time.Now().UnixNano()

		mapResponsePath := path.Join(
			mPath,
			fmt.Sprintf(
				"%d-%s-%d-%s.json",
				now,
				m.uid,
				atomic.LoadUint64(&m.seq),
				responseType,
			),
		)

		log.Trace().Msgf("Writing MapResponse to %s", mapResponsePath)
		err = os.WriteFile(mapResponsePath, body, perms)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Cannot write file")
		}
	}

	var respBody []byte
	if compression == ZstdCompression {
		respBody = zstdEncode(jsonBody)
	} else {
		respBody = jsonBody
	}

	data := make([]byte, reservedResponseHeaderSize)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)

	return data, nil
}

func zstdEncode(in []byte) []byte {
	encoder, ok := zstdEncoderPool.Get().(*zstd.Encoder)
	if !ok {
		panic("invalid type in sync pool")
	}
	out := encoder.EncodeAll(in, nil)
	_ = encoder.Close()
	zstdEncoderPool.Put(encoder)

	return out
}

var zstdEncoderPool = &sync.Pool{
	New: func() any {
		encoder, err := smallzstd.NewEncoder(
			nil,
			zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			panic(err)
		}

		return encoder
	},
}

func (m *Mapper) baseMapResponse() ztcfg.MapResponse {
	now := time.Now()

	resp := ztcfg.MapResponse{
		KeepAlive:   false,
		ControlTime: &now,
	}

	return resp
}

func (m *Mapper) baseWithConfigMapResponse(
	machine *Machine,
	pol *ACLPolicy,
	capVer ztcfg.CapabilityVersion,
	userProfile *UserProfile,
) (*ztcfg.MapResponse, error) {
	resp := m.baseMapResponse()

	routes, err := m.np.GetMachineRoutes(machine)
	if err != nil {
		return nil, err
	}
	node, err := toNode(
		machine,
		routes,
		capVer,
		pol,
		m.dnsCfg,
		m.baseDomain,
		m.randomClientPort,
		userProfile,
	)
	if err != nil {
		return nil, err
	}
	resp.Node = node

	resp.RELAYMap = m.relayMap

	resp.Domain = m.baseDomain

	resp.CollectServices = "false"

	resp.KeepAlive = false

	resp.Debug = &ztcfg.Debug{
		DisableZtmLog: false,
	}

	return &resp, nil
}

func machineMapToList(machines map[uint64]*Machine) Machines {
	ret := make(Machines, 0)

	for _, machine := range machines {
		ret = append(ret, *machine)
	}

	return ret
}

func (np *Ninjapanda) appendPeerChanges(
	resp *ztcfg.MapResponse,
	machine *Machine,
	capVer ztcfg.CapabilityVersion,
	peers Machines,
	changed Machines,
	baseDomain string,
	dnsCfg *ztcfg.DNSConfig,
	randomClientPort bool,
) error {
	fullChange := len(peers) == len(changed)

	rules, sshPolicy, err := np.GenerateFilterAndSSHRules(
		np.aclPolicy,
		machine,
		peers,
	)
	if err != nil {
		return err
	}

	if len(rules) > 0 {
		changed = np.FilterMachinesByACL(machine, changed, rules)
	}

	// TODO: reconcile GetMapResponseUserProfiles & GetUserProfileMap
	// so we are not building the same info twice (jrb)
	profiles := np.GetMapResponseUserProfiles(*machine, peers)

	dnsConfig := getMapResponseDNSConfig(
		dnsCfg,
		baseDomain,
		*machine,
		peers,
	)

	nodePeers, err := toNodes(
		np,
		peers,
		capVer,
		np.aclPolicy,
		dnsCfg,
		baseDomain,
		randomClientPort,
		np.GetUserProfileMap(append(peers, *machine)),
	)
	if err != nil {
		return err
	}

	sort.SliceStable(nodePeers, func(x, y int) bool {
		return nodePeers[x].ID < nodePeers[y].ID
	})

	nodePeers = distinct(nodePeers)

	if fullChange {
		resp.Peers = nodePeers
		log.Trace().
			Caller().
			Interface("Peers", nodePeers).
			Msg("[MAP DEBUG] Sending Peers")

	} else {
		resp.PeersChanged = nodePeers
		log.Trace().
			Caller().
			Interface("Peers", nodePeers).
			Msg("[MAP DEBUG] Sending PeersChanged")
	}
	resp.DNSConfig = dnsConfig
	resp.PacketFilter = ReduceFilterRules(machine, rules)
	resp.UserProfiles = profiles
	resp.SSHPolicy = sshPolicy

	return nil
}

func isSelfUpdate(messages ...string) bool {
	for _, message := range messages {
		if strings.Contains(message, SelfUpdateIdentifier) {
			return true
		}
	}

	return false
}

func toNodes(
	np *Ninjapanda,
	machines Machines,
	capVer ztcfg.CapabilityVersion,
	pol *ACLPolicy,
	dnsConfig *ztcfg.DNSConfig,
	baseDomain string,
	randomClientPort bool,
	userProfileMap map[string]*UserProfile,
) ([]*ztcfg.Node, error) {
	nodes := make([]*ztcfg.Node, len(machines))

	for index, machine := range machines {
		if len(machine.SessionKey) == 0 || machine.SessionKey == EmptySessionKey {
			log.Warn().
				Caller().
				Str(logtags.GetTag(logtags.machine, "MachineId"), machine.MachineId).
				Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
				Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
				Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
				Msg("machine missing SessionKey... removing from peer list")

			continue
		}

		var userProfile *UserProfile = nil
		if _userProfile, ok := userProfileMap[machine.MachineId]; ok {
			userProfile = _userProfile
		}
		routes, err := np.GetMachineRoutes(&machine)
		if err != nil {
			return nil, err
		}
		machine, err := toNode(
			&machine,
			routes,
			capVer,
			pol,
			dnsConfig,
			baseDomain,
			randomClientPort,
			userProfile,
		)
		if err != nil {
			return nil, err
		}

		nodes[index] = machine
	}

	return nodes, nil
}

func toNode(
	machine *Machine,
	routes Routes,
	capVer ztcfg.CapabilityVersion,
	pol *ACLPolicy,
	dnsConfig *ztcfg.DNSConfig,
	baseDomain string,
	randomClientPort bool,
	userProfile *UserProfile,
) (*ztcfg.Node, error) {
	addrs := machine.IPAddresses.Prefixes()

	allowedIPs := append(
		[]netip.Prefix{},
		addrs...)

	primaryPrefixes := []netip.Prefix{}

	for _, route := range routes {
		if route.Enabled {
			if route.IsPrimary {
				allowedIPs = append(allowedIPs, netip.Prefix(route.Prefix))
				primaryPrefixes = append(primaryPrefixes, netip.Prefix(route.Prefix))
			} else if route.IsExitRoute() {
				allowedIPs = append(allowedIPs, netip.Prefix(route.Prefix))
			}
		}
	}

	relay := "127.3.3.40:0"
	if machine.HostInfo.NetInfo != nil {
		relay = fmt.Sprintf("127.3.3.40:%d", machine.HostInfo.NetInfo.PreferredRELAY)
	}

	var keyExpiry time.Time
	if machine.Expiry != nil {
		keyExpiry = *machine.Expiry
	} else {
		keyExpiry = time.Time{}
	}

	hostname := machine.hostnameToFQDN(baseDomain, dnsConfig)

	var userId ztcfg.UserID
	if userProfile != nil {
		userId = ztcfg.UserID(userProfile.ID)
	} else {
		userId = 0
	}

	var nodeKey key.NodePublic
	err := nodeKey.UnmarshalText([]byte(NodePublicKeyEnsurePrefix(machine.NodeKey)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse node public key: %w", err)
	}

	var machineKey key.MachinePublic
	if machine.MachineKey != "" {
		err = machineKey.UnmarshalText(
			[]byte(MachinePublicKeyEnsurePrefix(machine.MachineKey)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to parse machine public key: %w", err)
		}
	}

	var sessionKey key.SessionPublic
	if machine.SessionKey != "" {
		err := sessionKey.UnmarshalText(
			[]byte(SessionPublicKeyEnsurePrefix(machine.SessionKey)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to parse session public key: %w", err)
		}
	} else {
		sessionKey = key.SessionPublic{}
	}

	isOnline := (machine.IsOnline != nil && *machine.IsOnline) || machine.isOnline()

	node := ztcfg.Node{
		ID: ztcfg.NodeID(machine.ID),
		StableID: ztcfg.StableNodeID(
			strconv.FormatUint(machine.ID, Base10),
		),
		Name: hostname,
		Cap:  capVer,

		User: ztcfg.UserID(userId),

		Key:       nodeKey,
		KeyExpiry: keyExpiry,

		Machine:       machineKey,
		SessionKey:    sessionKey,
		Addresses:     addrs,
		AllowedIPs:    allowedIPs,
		PrimaryRoutes: primaryPrefixes,
		Endpoints:     machine.Endpoints,
		RELAY:         relay,

		Online:   &isOnline,
		Hostinfo: machine.GetHostInfo().View(),
		Created:  machine.CreatedAt,

		KeepAlive: true,

		MachineAuthorized: !machine.isExpired(),
		// Expired:           machine.IsExpired(),

		// need ztcfg upgrade here
		Capabilities: []string{
			ztcfg.CapabilityFileSharing,
			ztcfg.CapabilityAdmin,
			ztcfg.CapabilitySSH,
		},
	}

	/** REVIEW: is this needed **/
	if capVer >= 74 {
		node.CapMap = ztcfg.NodeCapMap{
			ztcfg.CapabilityFileSharing: []ztcfg.RawMessage{},
			ztcfg.CapabilityAdmin:       []ztcfg.RawMessage{},
			ztcfg.CapabilitySSH:         []ztcfg.RawMessage{},
		}

		if randomClientPort {
			node.CapMap[ztcfg.NodeAttrRandomizeClientPort] = []ztcfg.RawMessage{}
			node.CapMap[ztcfg.NodeAttrDisableUPnP] = []ztcfg.RawMessage{}
		}
	} else {
		node.Capabilities = []string{
			ztcfg.CapabilityFileSharing,
			ztcfg.CapabilityAdmin,
			ztcfg.CapabilitySSH,
		}

		if randomClientPort {
			node.Capabilities = append(node.Capabilities, string(ztcfg.NodeAttrRandomizeClientPort))
		}
	}

	if capVer < 72 {
		node.Capabilities = append(node.Capabilities, string(ztcfg.NodeAttrDisableUPnP))
	}

	if node.Online == nil || !*node.Online {
		// LastSeen is only set when node is
		// not connected to the control server.
		node.LastSeen = node.LastSeen
	}

	return &node, nil
}

func distinct(input []*ztcfg.Node) []*ztcfg.Node {
	uniqueNodes := make(map[ztcfg.NodeID]ztcfg.Node)
	for _, nodePtr := range input {
		node := *nodePtr
		if _, ok := uniqueNodes[node.ID]; !ok {
			uniqueNodes[node.ID] = node
		}
	}

	nodes := make([]*ztcfg.Node, 0)
	for _, node := range uniqueNodes {
		nodePtr := node
		nodes = append(nodes, &nodePtr)
	}

	return nodes
}
