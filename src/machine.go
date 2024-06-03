package ninjapanda

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"

	"go4.org/netipx"

	"gorm.io/gorm"

	"github.com/Optm-Main/ztmesh-core/types/key"
	"github.com/Optm-Main/ztmesh-core/ztcfg"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

const (
	ErrMachineNotFound                  = Error("machine not found")
	ErrMachineRouteIsNotAvailable       = Error("route is not available on machine")
	ErrMachineAddressesInvalid          = Error("failed to parse machine addresses")
	ErrMachineNotFoundRegistrationCache = Error(
		"machine not found in registration cache",
	)
	ErrMachineAuthorizationUrlInvalid  = Error("invalid machine authorization url")
	ErrCouldNotConvertMachineInterface = Error("failed to convert machine interface")
	ErrHostnameTooLong                 = Error("Hostname too long")
	ErrDifferentRegisteredNamespace    = Error(
		"machine was previously registered with a different namespace",
	)
	MachineGivenNameHashLength = 2
	MachineGivenNameTrimSize   = 2
)

const (
	maxHostnameLength = 255
)

var machineNameWithSuffix = *regexp.MustCompile(`^(.*)-([0-9])*$`)

// Machine is a Ninjapanda client.
type Machine struct {
	ID              uint64 `gorm:"primary_key"`
	MachineId       string `gorm:"unique"                       json:"machine_id" yaml:"machine_id"`
	MachineKey      string `gorm:"type:varchar(64);unique_indx"`
	NodeKey         string
	SessionKey      string
	IPAddresses     MachineAddresses
	MachineLocation MachineLocation

	// Hostname represents the name given by the
	// client during registration
	Hostname string

	// Givenname represents either:
	// a DNS normalized version of Hostname
	// a valid name set by the User
	//
	// GivenName is the name used in all DNS related
	// parts of ninjapanda.
	GivenName   string `gorm:"type:varchar(63);unique_indx"`
	NamespaceID uint
	Namespace   Namespace `gorm:"foreignKey:NamespaceID"`

	// from HostInfo
	OS          string
	OSVersion   string
	Package     string
	DeviceModel string

	// from HostInfo.Distro
	Distro         string `json:",omitempty"` // "debian", "ubuntu", "nixos", ...
	DistroVersion  string `json:",omitempty"` // "20.04", ...
	DistroCodeName string `json:",omitempty"` // "jammy", "bullseye", ...

	ClientVersion string

	RegisterMethod string

	ForcedTags StringList

	// TODO: This seems like irrelevant information?
	AuthKeyID uint
	AuthKey   *PreAuthKey

	LastSeen             *time.Time
	LastSuccessfulUpdate *time.Time
	Expiry               *time.Time

	HostInfo  HostInfo
	Endpoints StringList

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time

	IsOnline *bool `gorm:"-"`
}

type MachineRegistrationStatus struct {
	Status  string
	Machine Machine
}

type (
	Machines  []Machine
	MachinesP []*Machine
)

type MachineAddresses []netip.Addr

func (ma MachineAddresses) Prefixes() []netip.Prefix {
	addrs := []netip.Prefix{}
	for _, addr := range ma {
		ip := netip.PrefixFrom(addr, addr.BitLen())
		addrs = append(addrs, ip)
	}

	return addrs
}

func (ma MachineAddresses) InIPSet(set *netipx.IPSet) bool {
	for _, addr := range ma {
		if set.Contains(addr) {
			return true
		}
	}

	return false
}

func (ma MachineAddresses) ToStringSlice() []string {
	strSlice := make([]string, 0, len(ma))
	for _, addr := range ma {
		strSlice = append(strSlice, addr.String())
	}

	return strSlice
}

func (ma *MachineAddresses) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		addresses := strings.Split(value, ",")
		*ma = (*ma)[:0]
		for _, addr := range addresses {
			if len(addr) < 1 {
				continue
			}
			parsed, err := netip.ParseAddr(addr)
			if err != nil {
				return err
			}
			*ma = append(*ma, parsed)
		}

		return nil

	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrMachineAddressesInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (ma MachineAddresses) Value() (driver.Value, error) {
	addresses := strings.Join(ma.ToStringSlice(), ",")

	return addresses, nil
}

// isExpired returns whether the machine registration has expired.
func (machine Machine) isExpired() bool {
	// If Expiry is not set, the client has not indicated that
	// it wants an expiry time, it is therefore considered
	// to mean "not expired"
	if machine.Expiry == nil || machine.Expiry.IsZero() {
		return false
	}

	nowInUtc := time.Now().UTC()
	return nowInUtc.After(*machine.Expiry) || nowInUtc.Equal(*machine.Expiry)
}

// isOnline returns if the machine is connected to Ninjapanda.
// This is really a naive implementation, as we don't really see
// if there is a working connection between the client and the server.
func (machine *Machine) isOnline() bool {
	if machine.LastSeen == nil {
		return false
	}

	if machine.isExpired() {
		return false
	}

	nowInUtc := time.Now().UTC()
	return machine.LastSeen.After(nowInUtc.Add(-keepAliveInterval))
}

// isEphemeral returns if the machine is registered as an Ephemeral node.
func (machine *Machine) isEphemeral() bool {
	return machine.AuthKey != nil && machine.AuthKey.Ephemeral
}

func containsAddresses(inputs []string, addrs []string) bool {
	for _, addr := range addrs {
		if containsStr(inputs, addr) {
			return true
		}
	}

	return false
}

// MatchSourceAndDestinationWithRule.
func MatchSourceAndDestinationWithRule(
	ruleSources []string,
	ruleDestinations []string,
	source []string,
	destination []string,
) bool {
	matches := containsAddresses(ruleSources, source) &&
		containsAddresses(ruleDestinations, destination)

	return matches
}

func getFilteredByACLPeers(
	machines []Machine,
	rules []ztcfg.FilterRule,
	machine *Machine,
) Machines {
	log.Trace().
		Caller().
		Interface(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Msg("Finding peers filtered by ACLs")

	peers := make(map[uint64]Machine)

	machineIPs := machine.IPAddresses.ToStringSlice()
	for _, peer := range machines {
		if peer.ID == machine.ID {
			continue
		}
		for _, rule := range rules {
			var ruleDestIPs []string
			for _, d := range rule.DstPorts {
				ruleDestIPs = append(ruleDestIPs, d.IP)
			}
			peerIPs := peer.IPAddresses.ToStringSlice()
			// match source and destination
			if MatchSourceAndDestinationWithRule(
				rule.SrcIPs,
				ruleDestIPs,
				machineIPs,
				peerIPs,
			) { /* || // match return path
				MatchSourceAndDestinationWithRule(
					rule.SrcIPs,
					ruleDestIPs,
					peerIPs,
					machineIPs,
				) */
				peers[peer.ID] = peer
			}
		}
	}

	authorizedPeers := Machines{}
	if len(peers) > 0 {
		for _, m := range peers {
			authorizedPeers = append(authorizedPeers, m)
		}
		sort.Slice(
			authorizedPeers,
			func(i, j int) bool { return authorizedPeers[i].ID < authorizedPeers[j].ID },
		)
	}

	return authorizedPeers
}

func (np *Ninjapanda) FilterMachinesByACL(
	machine *Machine,
	machines Machines,
	filter []ztcfg.FilterRule,
) Machines {
	result := Machines{}

	for index, peer := range machines {
		if peer.ID == machine.ID {
			continue
		}

		if np.CanAccess(filter, machine, &machines[index]) ||
			np.CanAccess(filter, &peer, machine) {
			result = append(result, peer)
		}
	}

	return result
}

func (np *Ninjapanda) CanAccess(filter []ztcfg.FilterRule, m, _m *Machine) bool {
	allowedIPs := append([]netip.Addr{}, _m.IPAddresses...)

	routes, _ := np.GetMachineRoutes(_m)
	for _, route := range routes {
		if route.Enabled {
			allowedIPs = append(allowedIPs, netip.Prefix(route.Prefix).Addr())
		}
	}

	for _, rule := range filter {
		matcher := MatchFromFilterRule(rule)

		if !matcher.SrcsContainsIPs([]netip.Addr(m.IPAddresses)) {
			continue
		}

		if matcher.DestsContainsIP(allowedIPs) {
			return true
		}
	}

	return false
}

func (np *Ninjapanda) CountMachinesInNamespace(machine *Machine) (int, error) {
	machines, err := np.ListMachinesInNamespace(machine.Namespace.Name)
	if err != nil {
		return 0, err
	}

	return len(machines), nil
}

func (np *Ninjapanda) CountMachinesForUser(userProfile *UserProfile) (int, error) {
	if userProfile == nil {
		return 0, fmt.Errorf("missing userProfile, unable to obtain machine count")
	}

	// make sure we have the full machine list for the user
	userProfile, err := np.GetUserProfileById(userProfile.ID)
	if err != nil {
		return 0, err
	}

	if userProfile == nil {
		log.Info().
			Caller().
			Uint64(logtags.GetTag(logtags.userProfile, "ID"), userProfile.ID).
			Msg("failed to find user profile for profile id")

		return 0, nil
	}

	return len(userProfile.UserMachines), nil
}

func (np *Ninjapanda) ListPeersByPolicy(
	machine *Machine,
) (Machines, error) {
	return np.getPeers(machine)
}

func (np *Ninjapanda) ListDirectPeers(
	machine *Machine,
) (Machines, error) {
	log.Trace().
		Caller().
		Interface(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Msg("finding direct peers")

	machines := Machines{}
	if err := np.db.Preload("AuthKey").Preload("AuthKey.Namespace").Preload("Namespace").
		Where("node_key <> ?", machine.NodeKey).Find(&machines).Error; err != nil {
		log.Error().Caller().Err(err).Msg("error accessing db")

		return Machines{}, err
	}

	sort.Slice(machines, func(i, j int) bool { return machines[i].ID < machines[j].ID })

	log.Trace().
		Caller().
		Interface(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Msgf("found peers: %s", machines.String())

	return machines, nil
}

func (np *Ninjapanda) getPeers(
	machine *Machine,
) (Machines, error) {
	var peers Machines
	var err error

	// If ACLs rules are defined, filter visible host list with the ACLs
	// else use the classic namespace scope
	if np.aclPolicy != nil {
		var machines []Machine
		machines, err = np.ListMachines()
		if err != nil {
			log.Error().Caller().Err(err).Msg("Error retrieving list of machines")

			return Machines{}, err
		}
		peers = getFilteredByACLPeers(machines, np.aclRules, machine)

	} else {
		log.Warn().
			Caller().
			Msgf("** No ACL Rules Defined **")

		peers, err = np.ListDirectPeers(machine)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Cannot fetch peers")

			return Machines{}, err
		}
	}

	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })

	log.Info().
		Caller().
		Interface(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Msgf("Found total peers: %s", peers.String())

	return peers, nil
}

func (np *Ninjapanda) ListMachines() ([]Machine, error) {
	machines := []Machine{}
	if err := np.db.Preload("AuthKey").Preload("AuthKey.Namespace").Preload("Namespace").
		Find(&machines).Error; err != nil {
		return nil, err
	}

	return machines, nil
}

func (np *Ninjapanda) ListMachinesByGivenName(
	givenName string,
	machineId string,
) ([]Machine, error) {
	machines := []Machine{}
	if err := np.db.Preload("AuthKey").
		Preload("AuthKey.Namespace").
		Preload("Namespace").
		Where("given_name = ? and machine_id != ?", givenName, machineId).
		Find(&machines).Error; err != nil {
		return nil, err
	}

	return machines, nil
}

func (np *Ninjapanda) ListMachinesLikeGivenName(
	givenName string,
	namespaceID uint,
	machineID string,
) ([]Machine, error) {
	machines := []Machine{}

	escClause := ""
	_givenName := strings.Replace(givenName, "_", "\\_", -1)

	if _givenName != givenName {
		givenName = _givenName
		// escClause = "ESCAPE '\\'"
	}

	givenName = strings.ToLower(givenName)

	if err := np.db.Preload("AuthKey").Preload("AuthKey.Namespace").Preload("Namespace").
		Where(
			"lower(given_name) like '"+givenName+"%' and namespace_id = ? and machine_id != ? "+escClause,
			namespaceID,
			machineID,
		).
		Find(&machines).Error; err != nil {
		log.Error().Err(err).Msg("Unable to search for this givenName")
		return nil, err
	}
	return machines, nil
}

func (np *Ninjapanda) GetMachine(
	namespace string,
	name string,
) (*Machine, error) {
	machines, err := np.ListMachinesInNamespace(namespace)
	if err != nil {
		return nil, err
	}

	for _, m := range machines {
		if m.Hostname == name {
			return &m, nil
		}
	}

	return nil, ErrMachineNotFound
}

func (np *Ninjapanda) GetMachineByID(
	id uint64,
) (*Machine, error) {
	m := Machine{}
	if err := np.db.Preload("AuthKey").Preload("Namespace").Find(&Machine{ID: id}).First(&m).Error; err != nil {
		return nil, err
	}

	return &m, nil
}

func (np *Ninjapanda) GetMachineByMachineId(
	machineId string,
) (*Machine, error) {
	m := Machine{}
	if result := np.db.Preload("AuthKey").Preload("AuthKey.Namespace").Preload("Namespace").First(&m, "machine_id = ?", machineId); result.Error != nil {
		return nil, result.Error
	}

	return &m, nil
}

func (np *Ninjapanda) GetMachineByMachineKey(
	machineKey string,
) (*Machine, error) {
	m := Machine{}
	if result := np.db.Preload("AuthKey").
		Preload("Namespace").First(&m, "machine_key = ?", machineKey); result.Error != nil {
		return nil, result.Error
	}

	return &m, nil
}

func (np *Ninjapanda) GetMachineByNodeKey(
	nodeKey key.NodePublic,
) (*Machine, error) {
	machine := Machine{}
	if result := np.db.Preload("AuthKey").Preload("Namespace").First(&machine, "node_key = ?",
		NodePublicKeyStripPrefix(nodeKey)); result.Error != nil {
		return nil, result.Error
	}

	return &machine, nil
}

func (np *Ninjapanda) GetMachineByAnyKey(
	machineKey key.MachinePublic,
	nodeKey key.NodePublic,
) (*Machine, error) {
	machine := Machine{}
	if result := np.db.Preload("AuthKey").Preload("Namespace").First(&machine, "machine_key = ? OR node_key = ?",
		MachinePublicKeyStripPrefix(machineKey),
		NodePublicKeyStripPrefix(nodeKey)); result.Error != nil {
		return nil, result.Error
	}

	return &machine, nil
}

func (np *Ninjapanda) SetTags(
	machine *Machine,
	tags []string,
) error {
	newTags := []string{}
	for _, tag := range tags {
		if !contains(newTags, tag) {
			newTags = append(newTags, tag)
		}
	}

	machine.ForcedTags = newTags
	if err := np.UpdateACLRules(); err != nil && !errors.Is(err, ErrEmptyPolicy) {
		return err
	}

	if err := np.db.Save(machine).Error; err != nil {
		return fmt.Errorf("failed to update tags for machine in the database: %w", err)
	}

	return nil
}

func (np *Ninjapanda) ExpireMachine(machine *Machine) error {
	if !machine.isExpired() {
		nowInUtc := time.Now().UTC()
		machine.Expiry = &nowInUtc
	}
	// REVIEW: should the preAuthKey usedCount be decremented?
	machine.AuthKeyID = 0
	machine.AuthKey = nil

	np.SendMachineUpdate(machine)

	if err := np.db.Save(machine).Error; err != nil {
		return fmt.Errorf("failed to expire machine in the database: %w", err)
	}

	return nil
}

func (np *Ninjapanda) RenameMachine(
	machine *Machine,
	newName string,
) error {
	err := CheckForHostnameRules(
		newName,
	)
	if err != nil {
		log.Error().
			Caller().
			Interface(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Str(logtags.MakeTag("NewMachineName"), newName).
			Err(err)

		return err
	}

	machine.GivenName, _ = np.resolveNameCollisions(
		machine.MachineId,
		machine.NamespaceID,
		newName,
	)

	if err := np.db.Save(machine).Error; err != nil {
		return fmt.Errorf("failed to rename machine in the database: %w", err)
	}

	return nil
}

func (np *Ninjapanda) RefreshMachine(
	machine *Machine,
	expiry time.Time,
) error {
	nowInUtc := time.Now().UTC()

	machine.LastSuccessfulUpdate = &nowInUtc
	np.setMachineExpiry(machine, expiry)

	if err := np.db.Save(machine).Error; err != nil {
		return fmt.Errorf(
			"failed to refresh machine (update expiration) in the database: %w",
			err,
		)
	}

	return nil
}

func (np *Ninjapanda) DeleteMachine(machine *Machine) error {
	if machine == nil {
		return nil
	}

	np.DisassociateUserProfileByMachineId(machine.MachineId)
	np.DeleteMachineRoutes(machine)

	if err := np.db.Unscoped().Delete(&machine).Error; err != nil {
		return err
	}

	if np.kafkaClient.IsEnabled() {
		topic := "machine.delete"
		msg := MachineKafkaMessage{
			np:      np,
			Machine: machine,
		}
		err := np.kafkaClient.PushToTopic(
			topic,
			msg.Marshal(topic),
			machine.Namespace.ExternalId,
		)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("error pushing to kafka delete topic")
		}
	}

	return nil
}

func (np *Ninjapanda) TouchMachine(machine *Machine) {
	nowInUtc := time.Now().UTC()
	machine.LastSeen = &nowInUtc

	if np.kafkaClient.IsEnabled() {
		log.Trace().
			Caller().
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Time(logtags.GetTag(logtags.machine, "LastSeen"), *machine.LastSeen).
			Dur(logtags.GetTag(logtags.kafkaConfig, "UpdateInterval"), np.kafkaClient.UpdateInterval).
			Msg("Calling kafka machine.update")

		np.SendMachineUpdate(machine)
	}

	err := np.db.Updates(Machine{
		ID:                   machine.ID,
		LastSeen:             machine.LastSeen,
		LastSuccessfulUpdate: machine.LastSuccessfulUpdate,
	}).Error
	if err != nil {
		log.Warn().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Str(logtags.GetTag(logtags.machine, "MachineId"), machine.MachineId).
			Msg("failed to update machine LastSeen")
	}
}

func (np *Ninjapanda) HardDeleteMachine(
	machine *Machine,
	isConnected map[string]bool,
) error {
	// TODO: see if machine is connected..
	return np.DeleteMachine(machine)
}

func (machine *Machine) GetHostInfo() *ztcfg.Hostinfo {
	hi := ztcfg.Hostinfo(machine.HostInfo)
	return &hi
}

func (machine *Machine) GetNetInfo() *ztcfg.NetInfo {
	if machine.HostInfo.NetInfo == nil {
		return nil
	}

	netInfo := ztcfg.NetInfo(*machine.HostInfo.NetInfo)
	return &netInfo
}

func (machine *Machine) ApplyPeerChange(change *ztcfg.PeerChange) {
	if change.Key != nil {
		machine.NodeKey = NodePublicKeyStripPrefix(*change.Key)
	}

	if change.Endpoints != nil {
		machine.Endpoints = change.Endpoints
	}

	if change.RELAYRegion != 0 && machine.HostInfo.NetInfo != nil {
		machine.HostInfo.NetInfo.PreferredRELAY = change.RELAYRegion
	}

	machine.LastSeen = change.LastSeen
}

func (machine *Machine) PeerChangeFromMapRequest(
	req ztcfg.MapRequest,
) ztcfg.PeerChange {
	ret := ztcfg.PeerChange{
		NodeID: ztcfg.NodeID(machine.ID),
	}

	if machine.MachineKey != req.NodeKey.String() {
		ret.Key = &req.NodeKey
	}

	if req.Hostinfo.NetInfo != nil &&
		machine.HostInfo.NetInfo != nil &&
		machine.HostInfo.NetInfo.PreferredRELAY != req.Hostinfo.NetInfo.PreferredRELAY {
		ret.RELAYRegion = req.Hostinfo.NetInfo.PreferredRELAY
	}

	ret.Endpoints = req.Endpoints

	nowInUtc := time.Now().UTC()
	ret.LastSeen = &nowInUtc

	return ret
}

func (machine Machine) String() string {
	return machine.Hostname
}

func (machines Machines) String() string {
	temp := make([]string, len(machines))

	for indx, machine := range machines {
		temp[indx] = machine.String()
	}

	return fmt.Sprintf("[ %s ](%d)", strings.Join(temp, ", "), len(temp))
}

func (machines MachinesP) String() string {
	temp := make([]string, len(machines))

	for indx, machine := range machines {
		temp[indx] = machine.String()
	}

	return fmt.Sprintf("[ %s ](%d)", strings.Join(temp, ", "), len(temp))
}

func (machine Machine) hostnameToFQDN(
	baseDomain string,
	dnsConfig *ztcfg.DNSConfig,
) string {
	hostname := machine.GivenName

	if dnsConfig != nil && dnsConfig.Proxied { // MagicDNS
		givenName := machine.Hostname
		if len(machine.GivenName) > 0 {
			givenName = machine.GivenName
		}

		namespaceName := "ns-unknown"
		indx := strings.Index(givenName, "."+namespaceName)
		if indx > 0 {
			givenName = givenName[:indx]
		}

		if len(machine.Namespace.Name) > 0 {
			namespaceName = machine.Namespace.Name
		}
		hostname = fmt.Sprintf(
			"%s.%s.%s",
			givenName,
			namespaceName,
			baseDomain,
		)
		if len(hostname) > maxHostnameLength {
			log.Error().
				Caller().
				Str(logtags.MakeTag("DnsHostname"), hostname).
				Msg("Hostname too long, cannot exceed 255 ASCII chars")
			hostname = machine.GivenName
		}
	}

	return hostname
}

func (machine *Machine) sanitize() *Machine {
	// FIXME: this is stepping on the registrationCache contents
	// machine.MachineKey = ""
	// machine.NodeKey = ""
	// machine.SessionKey = ""

	return machine
}

func mapRegisterMethod(registerMethod string) string {
	switch registerMethod {
	case RegisterMethodAuthKey:
		return "REGISTER_METHOD_AUTH_KEY"

	case RegisterMethodOIDC:
		return "REGISTER_METHOD_OIDC"

	case RegisterMethodAPI:
		return "REGISTER_METHOD_API"

	case RegisterMethodCallback:
		return "REGISTER_METHOD_CALLBACK"
	}

	return "REGISTER_METHOD_UNSPECIFIED"
}

func (machine *Machine) toProto() *v1.Machine {
	registerMethod, _ := v1.RegisterMethod_value[mapRegisterMethod(machine.RegisterMethod)]

	machineName := machine.Hostname
	indx := strings.Index(machineName, ".")
	if indx > 0 {
		machineName = machineName[:indx]
	}

	machineProto := &v1.Machine{
		MachineId:  machine.MachineId,
		MachineKey: machine.MachineKey,

		NodeKey:         machine.NodeKey,
		SessionKey:      machine.SessionKey,
		IpAddresses:     machine.IPAddresses.ToStringSlice(),
		MachineLocation: machine.MachineLocation.toProto(),
		Name:            machineName,
		GivenName:       machine.GivenName,
		Namespace:       machine.Namespace.toProto(),
		ForcedTags:      machine.ForcedTags,
		Online:          machine.isOnline(),

		RegisterMethod: *v1.RegisterMethod(registerMethod).Enum(),

		Os:            machine.OS,
		OsVersion:     machine.OSVersion,
		Hostname:      machine.Hostname,
		ClientVersion: machine.ClientVersion,

		CreatedAt: FormatTime(&machine.CreatedAt),
	}

	if len(machine.Package) > 0 {
		machineProto.Package = &machine.Package
	}
	if len(machine.DeviceModel) > 0 {
		machineProto.DeviceModel = &machine.DeviceModel
	}

	if len(machine.Distro) > 0 {
		machineProto.Distro = &machine.Distro
	}
	if len(machine.DistroVersion) > 0 {
		machineProto.DistroVersion = &machine.DistroVersion
	}
	if len(machine.DistroCodeName) > 0 {
		machineProto.DistroCodeName = &machine.DistroCodeName
	}

	if machine.AuthKey != nil {
		machineProto.PreAuthKey = machine.AuthKey.toProto(false)
	}

	if machine.LastSeen != nil {
		t := FormatTime(machine.LastSeen)
		machineProto.LastSeen = &t
	}

	if machine.LastSuccessfulUpdate != nil {
		t := FormatTime(machine.LastSuccessfulUpdate)
		machineProto.LastSuccessfulUpdate = &t
	}

	if machine.Expiry != nil && !machine.Expiry.IsZero() {
		t := FormatTime(machine.Expiry)
		machineProto.Expiry = &t
	}

	return machineProto
}

func getTags(
	aclPolicy *ACLPolicy,
	machine Machine,
	stripEmailDomain bool,
) ([]string, []string) {
	validTags := make([]string, 0)
	invalidTags := make([]string, 0)
	if aclPolicy == nil {
		return validTags, invalidTags
	}
	validTagMap := make(map[string]bool)
	invalidTagMap := make(map[string]bool)
	for _, tag := range machine.HostInfo.RequestTags {
		owners, err := expandTagOwners(*aclPolicy, tag, stripEmailDomain)
		if errors.Is(err, ErrInvalidTag) {
			invalidTagMap[tag] = true

			continue
		}
		var found bool
		for _, owner := range owners {
			if machine.Namespace.Name == owner {
				found = true
			}
		}
		if found {
			validTagMap[tag] = true
		} else {
			invalidTagMap[tag] = true
		}
	}
	for tag := range invalidTagMap {
		invalidTags = append(invalidTags, tag)
	}
	for tag := range validTagMap {
		validTags = append(validTags, tag)
	}

	return validTags, invalidTags
}

func (np *Ninjapanda) RegisterMachineFromAuthCallback(
	correlationId string,
	namespaceName string,
	machineExpiry *time.Time,
	registrationMethod string,
) (*Machine, error) {
	log.Debug().
		Caller().
		Str(logtags.MakeTag("correlationId"), correlationId).
		Str(logtags.GetTag(logtags.namespace, "Name"), namespaceName).
		Str(logtags.MakeTag("registrationMethod"), registrationMethod).
		Str(logtags.GetTag(logtags.machine, "Expiry"), fmt.Sprintf("%v", machineExpiry)).
		Msg("Registering machine from API/CLI or auth callback")

	if registrationMachineStatus, ok := np.registrationCache.SearchMachineRegistration(context.Background(), correlationId); ok {
		log.Trace().
			Caller().
			Interface(logtags.MakeTag("registrationMachineStatus"), registrationMachineStatus).
			Msg("RegisterMachineFromAuthCallback registrationCache get")

		namespace, err := np.GetNamespace(namespaceName)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to find namespace of register machine from auth callback, %w",
				err,
			)
		}

		registrationMachine := registrationMachineStatus.Machine

		expiry := time.Now().UTC().Add(namespace.DefaultMachineKeyTtl)
		if machineExpiry != nil {
			expiry = *machineExpiry
		}
		registrationMachine.Expiry = &expiry

		// Prevent re-registration of machine with different namespace
		if registrationMachine.NamespaceID > 0 &&
			registrationMachine.NamespaceID != namespace.ID {
			return nil, ErrDifferentRegisteredNamespace
		}

		hostname := registrationMachine.HostInfo.Hostname
		if len(hostname) == 0 {
			hostname = registrationMachine.Hostname
		}

		givenName, err := np.GenerateGivenName(
			registrationMachine.MachineId,
			registrationMachine.NamespaceID,
			hostname,
		)
		if err != nil {
			log.Error().
				Caller().
				Str(logtags.GetTag(logtags.hostInfo, "Hostname"), registrationMachine.HostInfo.Hostname).
				Str(logtags.GetTag(logtags.machine, "Hostname"), registrationMachine.Hostname).
				Err(err).
				Msg("ignoring, will attempt to use hostname")

			givenName = registrationMachine.Hostname
		}

		nowInUtc := time.Now().UTC()
		machineToRegister := Machine{
			MachineId:  registrationMachine.MachineId,
			MachineKey: registrationMachine.MachineKey,
			NodeKey:    registrationMachine.NodeKey,
			SessionKey: registrationMachine.SessionKey,

			IPAddresses:     registrationMachine.IPAddresses,
			MachineLocation: registrationMachine.MachineLocation,

			Hostname:    registrationMachine.Hostname,
			GivenName:   givenName,
			NamespaceID: namespace.ID,
			Namespace:   *namespace,

			OS:          registrationMachine.OS,
			OSVersion:   registrationMachine.OSVersion,
			Package:     registrationMachine.Package,
			DeviceModel: registrationMachine.DeviceModel,

			ClientVersion: registrationMachine.ClientVersion,

			Distro:         registrationMachine.Distro,
			DistroVersion:  registrationMachine.DistroVersion,
			DistroCodeName: registrationMachine.DistroCodeName,

			RegisterMethod: registrationMethod,

			LastSeen: &nowInUtc,
			Expiry:   registrationMachine.Expiry,
		}

		log.Trace().
			Caller().
			Interface(logtags.GetTag(logtags.machine, ""), machineToRegister).
			Msg("Preparing to register machine")

		// see if the machine already exists...
		existingMachine, _ := np.GetMachineByMachineId(machineToRegister.MachineId)
		if existingMachine == nil {
			// ...then check if org is allowed another machine
			allowed, err := np.grpcCheckLicense(nil, &machineToRegister, MachinesPerOrg)
			if !allowed || err != nil {
				return nil, err
			}
		}

		machine, err := np.RegisterMachine(context.Background(), machineToRegister)
		if err == nil {
			log.Trace().
				Caller().
				Str(logtags.GetTag(logtags.machine, "MachineId"), machine.MachineId).
				Msg("Register machine success")

			np.registrationCache.StoreMachineRegistration(
				context.Background(),
				correlationId,
				MachineRegistrationStatus{
					Status:  "success",
					Machine: *machine,
				},
				registerCacheExpiration,
			)
		}

		return machine, err
	}

	return nil, ErrMachineNotFoundRegistrationCache
}

func (np *Ninjapanda) RegisterMachine(
	ctx context.Context,
	machine Machine,
) (*Machine, error) {
	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
		Str(logtags.GetTag(logtags.machine, "NodeKey"), machine.NodeKey).
		Str(logtags.GetTag(logtags.namespace, "Name"), machine.Namespace.Name).
		Msg("Registering machine")

	if len(machine.NodeKey) == 0 {
		return nil, fmt.Errorf(
			"RegisterMachine: machine missing node_key: %s",
			machine.Hostname,
		)
	}

	np.insertIVPartial(machine.MachineId, machine.NodeKey)

	existingMachine, err := np.GetMachineByMachineId(machine.MachineId)
	if err == nil {
		machine.ID = existingMachine.ID
	}

	if machine.Expiry == nil {
		machine.Expiry = &time.Time{}
	}

	np.setMachineExpiry(&machine, *machine.Expiry)

	// If the machine exists and we had already IPs for it, we just save it
	// so we store the machine.Expire and machine.Nodekey that has been set when
	// adding it to the registrationCache
	if len(machine.IPAddresses) > 0 {
		if err := np.db.Save(&machine).Error; err != nil {
			return nil, fmt.Errorf(
				"failed re-register of existing machine: %w",
				err,
			)
		}

		log.Trace().
			Caller().
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Str(logtags.GetTag(logtags.machine, "MachineKey"), machine.MachineKey).
			Str(logtags.GetTag(logtags.machine, "NodeKey"), machine.NodeKey).
			Str(logtags.GetTag(logtags.namespace, "Name"), machine.Namespace.Name).
			Msg("Machine authorized again")

		return &machine, nil
	}

	np.ipAllocationMutex.Lock()
	defer np.ipAllocationMutex.Unlock()

	ips, err := np.getAvailableIPs()
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Msg("Could not find IP for the new machine")

		return nil, err
	}
	sort.Slice(
		ips,
		func(i, j int) bool {
			return strings.Count(
				ips[i].String(),
				":",
			) < strings.Count(
				ips[j].String(),
				":",
			)
		},
	)
	machine.IPAddresses = ips

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

	if err := np.db.Save(&machine).Error; err != nil {
		return nil, fmt.Errorf("failed register(save) machine in the database: %w", err)
	}

	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Str(logtags.GetTag(logtags.machine, "IPAddresses"), strings.Join(ips.ToStringSlice(), ",")).
		Msg("Machine registered with the database")

	return &machine, nil
}

func (np *Ninjapanda) GetAdvertisedRoutes(
	machine *Machine,
) ([]netip.Prefix, error) {
	routes := []Route{}

	err := np.db.
		Where("machine_id = ? AND advertised = true", machine.MachineId).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Msg("Could not get advertised routes for machine")

		return nil, err
	}

	prefixes := []netip.Prefix{}
	for _, route := range routes {
		prefixes = append(prefixes, netip.Prefix(route.Prefix))
	}

	return prefixes, nil
}

func (np *Ninjapanda) GetEnabledRoutes(machine *Machine) Routes {
	routes := []Route{}

	err := np.db.
		Where(
			"machine_id = ? AND advertised = true AND enabled = true",
			machine.MachineId,
		).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Msg("Could not get enabled routes for machine")
	}

	return routes
}

func (np *Ninjapanda) EnableRoutes(
	machine *Machine,
	routeStrs ...string,
) (*StateUpdate, error) {
	newRoutes := make([]netip.Prefix, len(routeStrs))
	for indx, routeStr := range routeStrs {
		route, err := netip.ParsePrefix(routeStr)
		if err != nil {
			return nil, err
		}

		newRoutes[indx] = route
	}

	advertisedRoutes, err := np.GetAdvertisedRoutes(machine)
	if err != nil {
		return nil, err
	}

	for _, newRoute := range newRoutes {
		if !contains(advertisedRoutes, newRoute) {
			return nil, fmt.Errorf(
				"route (%s) is not available on node %s: %w",
				machine.Hostname,
				newRoute, ErrMachineRouteIsNotAvailable,
			)
		}
	}

	// Separate loop so we don't leave things in a half-updated state
	for _, prefix := range newRoutes {
		route := Route{}
		err := np.db.
			Where("machine_id = ? AND prefix = ?", machine.MachineId, IPPrefix(prefix)).
			First(&route).Error
		if err == nil {
			route.Enabled = true

			// Mark already as primary if there is only this node offering this subnet
			// (and is not an exit route)
			if !route.IsExitRoute() {
				route.IsPrimary = np.isUniquePrefix(route)
			}

			err = np.db.Save(&route).Error
			if err != nil {
				return nil, fmt.Errorf("failed to enable route: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to find route: %w", err)
		}
	}

	//machineRoutes, err := np.GetMachineRoutes(machine)
	//if err != nil {
	//return nil, fmt.Errorf("route read back failed: %w", err)
	//}

	// machine.Routes = machineRoutes

	return &StateUpdate{
		Type:            StatePeerChanged,
		ChangedMachines: Machines{*machine},
		Message:         "enableRoutes create routes",
	}, nil
}

func (np *Ninjapanda) EnableAutoApprovedRoutes(
	machine *Machine,
) (*StateUpdate, error) {
	if len(machine.IPAddresses) == 0 {
		return nil, nil // This machine has no IPAddresses, so can't possibly match any autoApprovers ACLs
	}

	routes := []Route{}
	err := np.db.
		Where(
			"machine_id = ? AND advertised = true AND enabled = false",
			machine.MachineId,
		).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
			Msg("Could not get advertised routes for machine")

		return nil, err
	}

	approvedRoutes := []Route{}

	for _, advertisedRoute := range routes {
		routeApprovers, err := np.aclPolicy.AutoApprovers.GetRouteApprovers(
			netip.Prefix(advertisedRoute.Prefix),
		)
		if err != nil {
			log.Err(err).
				Interface(logtags.GetTag(logtags.route, ""), advertisedRoute).
				Str(logtags.GetTag(logtags.machine, "MachineId"), machine.MachineId).
				Msg("Failed to resolve autoApprovers for advertised route")

			return nil, err
		}

		for _, approvedAlias := range routeApprovers {
			if approvedAlias == machine.Namespace.Name {
				approvedRoutes = append(approvedRoutes, advertisedRoute)
			} else {
				approvedIps, err := expandAlias([]Machine{*machine}, *np.aclPolicy, approvedAlias, np.cfg.OIDC.StripEmaildomain)
				if err != nil {
					log.Err(err).
						Str(logtags.MakeTag("alias"), approvedAlias).
						Msg("Failed to expand alias when processing autoApprovers policy")

					return nil, err
				}

				// approvedIPs should contain all of machine's IPs if it matches the rule, so check for first
				if contains(approvedIps, machine.IPAddresses[0].String()) {
					approvedRoutes = append(approvedRoutes, advertisedRoute)
				}
			}
		}
	}

	update := &StateUpdate{
		Type:            StatePeerChanged,
		ChangedMachines: Machines{},
		Message:         "EnableAutoApprovedRoutes create route",
	}

	for indx, approvedRoute := range approvedRoutes {
		hostUpdate, err := np.EnableRoute(approvedRoutes[indx].RouteId)
		if err != nil {
			log.Err(err).
				Interface(logtags.GetTag(logtags.route, ""), approvedRoute).
				Str(logtags.GetTag(logtags.machine, "MachineId"), machine.MachineId).
				Msg("Failed to enable approved route")

			return nil, err
		}

		update.ChangedMachines = append(
			update.ChangedMachines,
			hostUpdate.ChangedMachines...)
	}

	return update, nil
}

func (np *Ninjapanda) generateGivenName(
	suppliedName string,
	suffix string,
) (string, error) {
	if len(suppliedName) < 1 {
		return "", fmt.Errorf(
			"unable to generate given name: no supplied hostname provided",
		)
	}

	normalizedHostname, err := NormalizeToFQDNRules(
		suppliedName,
		np.cfg.OIDC.StripEmaildomain,
	)
	if err != nil {
		return "", err
	}

	if len(suffix) > 0 {
		// Trim if a hostname will be longer than 63 chars after adding the suffix.
		trimmedHostnameLength := labelHostnameLength - MachineGivenNameHashLength - MachineGivenNameTrimSize
		if len(normalizedHostname) > trimmedHostnameLength {
			normalizedHostname = normalizedHostname[:trimmedHostnameLength]
		}

		normalizedHostname += "-" + suffix
	}

	return normalizedHostname, nil
}

func (np *Ninjapanda) GenerateGivenName(
	machineId string,
	namespaceID uint,
	suppliedName string,
) (string, error) {
	log.Info().
		Caller().
		Bool(logtags.GetTag(logtags.config, "NameCollisionEnabled"), np.cfg.NameCollisionEnabled).
		Msgf("request to generate given name from supplied name %s", suppliedName)

	givenName, err := np.generateGivenName(suppliedName, "")
	if err != nil {
		return "", err
	}

	if !np.cfg.NameCollisionEnabled {
		log.Info().
			Caller().
			Msgf("generate given name returning normalized name as %s", givenName)
		return givenName, nil
	}

	// consider machine registration is in-flight...
	if len(machineId) == 0 || namespaceID == 0 {
		log.Info().
			Caller().
			Msgf("generate given name returning normalized name as %s for inflight registration", givenName)
		return givenName, nil
	}

	// if this machine already exists, re-use the assigned given name
	/* REVIEW: disabling temporarily
	machine, _ := np.GetMachineByMachineId(machineId)
	if machine != nil {
		log.Info().
			Caller().
			Str(logtags.GetTag(logtags.machine, "MachineId"), machine.MachineId).
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Msg("generate given name returning previously assigned name as machine_id exists")
		return machine.GivenName, nil
	}
	*/

	return np.resolveNameCollisions(machineId, namespaceID, givenName)
}

func (np *Ninjapanda) resolveNameCollisions(
	machineId string, namespaceID uint, givenName string,
) (string, error) {
	if !np.cfg.NameCollisionEnabled {
		return givenName, nil
	}

	log.Info().
		Caller().
		Msgf("normalized given name, testing for name collisions %s", givenName)

	if strings.Contains(givenName, "."+np.cfg.BaseDomain) {
		tuples := strings.Split(givenName, ".")

		// the first tuple is the hostname.
		givenName = tuples[0]

		log.Info().
			Caller().
			Msgf("normalized given name, dropping domain tuple %s", givenName)
	}

	// look for baseName-#suffix (e.g., dweezil-3)
	// note: breaks 'iphone-13' ¯\_(ツ)_/¯
	matches := machineNameWithSuffix.FindAllStringSubmatch(givenName, -1)

	if len(matches) > 0 && len(matches[0]) > 1 {
		// matches follows the form
		//  [[givename][baseName][suffix]]
		givenName = matches[0][1]

		log.Info().
			Caller().
			Msgf("normalized given name, dropping previous suffix %s", givenName)
	}

	log.Info().Str("Given_Name", givenName).Msg("Looking for machines with givenName")
	machines, err := np.ListMachinesLikeGivenName(givenName, namespaceID, machineId)
	if err != nil {
		return "", err
	}

	numCollisions := len(machines)

	if numCollisions > 0 {
		resolvedNameCollision := false
		for !resolvedNameCollision {
			postfixedName, err := np.generateGivenName(
				givenName,
				strconv.Itoa(numCollisions),
			)
			if err != nil {
				return "", err
			}

			machines, _ := np.ListMachinesByGivenName(postfixedName, machineId)
			if len(machines) > 0 {
				numCollisions++
				continue
			}

			resolvedNameCollision = true

			log.Info().
				Caller().
				Str(logtags.GetTag(logtags.machine, "MachineId"), machineId).
				Str(logtags.MakeTag("postfixedName"), postfixedName).
				Msg("Detected given name collision, resolving")

			givenName = postfixedName
		}
	} else {
		log.Info().
			Caller().
			Str(logtags.GetTag(logtags.machine, "MachineId"), machineId).
			Str(logtags.GetTag(logtags.machine, "GivenName"), givenName).
			Msg("No name collision detected")
	}

	return givenName, nil
}

// Sets the time until the specified machine's key is to expire.
// If the "expiry" argument is zero, then the machine's expiry time
// will assume that of the default key TTL of the machine's namespace.
func (np *Ninjapanda) setMachineExpiry(
	machine *Machine,
	expiry time.Time,
) {
	if expiry.IsZero() {
		namespace, err := np.GetNamespaceByID(uint64(machine.NamespaceID))
		if err != nil {
			log.Error().
				Caller().
				Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
				Str(logtags.GetTag(logtags.namespace, "Name"), machine.Namespace.Name).
				Msg("Could not lookup machine namespace -> setting infinite expire time")

			return
		}

		if namespace.DefaultMachineKeyTtl == 0 {
			machine.Expiry = &time.Time{}
			log.Info().
				Caller().
				Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
				Msg("Setting infinite machine expiration")

			return
		}

		expiry := time.Now().UTC().Add(namespace.DefaultMachineKeyTtl)
		machine.Expiry = &expiry
		log.Info().
			Caller().
			Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
			Time(logtags.GetTag(logtags.machine, "Expiry"), expiry).
			Dur(logtags.GetTag(logtags.namespace, "DefaultMachineKeyTtl"), namespace.DefaultMachineKeyTtl).
			Msg("Setting machine's expiry based on namespace default")

		return
	}

	machine.Expiry = &expiry
	log.Info().
		Caller().
		Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
		Time(logtags.GetTag(logtags.machine, "Expiry"), expiry).
		Msg("Set machine expiry")

	if machine.isExpired() {
		np.SendMachineUpdate(machine)
	}
}

func (np *Ninjapanda) getUserProfileForMachine(
	machineId string,
) *ztcfg.UserProfile {
	userProfile, err := np.GetUserProfileByMachineId(machineId, IncludeTaggedDevice)
	if err != nil {
		log.Warn().
			Caller().
			Str(logtags.GetTag(logtags.machine, "MachineId"), machineId).
			Msg("failed to get user profile")
		return nil
	}

	return &ztcfg.UserProfile{
		ID:          ztcfg.UserID(userProfile.ID),
		LoginName:   userProfile.LoginName,
		FirstName:   userProfile.FirstName,
		LastName:    userProfile.LastName,
		DisplayName: userProfile.DisplayName,
	}
}

func (np *Ninjapanda) getUserForMachine(
	machineId string,
) *ztcfg.User {
	userProfile, err := np.GetUserProfileByMachineId(machineId, IncludeTaggedDevice)
	if err != nil {
		return &ztcfg.User{}
	}

	return &ztcfg.User{
		ID:          ztcfg.UserID(userProfile.ID),
		LoginName:   userProfile.LoginName,
		DisplayName: userProfile.DisplayName,
		Domain:      np.cfg.BaseDomain,
		Logins:      []ztcfg.LoginID{},
		Created:     userProfile.CreatedAt,
	}
}

func (np *Ninjapanda) getLoginForMachine(
	machineId string,
) *ztcfg.Login {
	userProfile, err := np.GetUserProfileByMachineId(machineId, IncludeTaggedDevice)
	if err != nil {
		return &ztcfg.Login{}
	}

	return &ztcfg.Login{
		ID:          ztcfg.LoginID(userProfile.ID),
		LoginName:   userProfile.LoginName,
		DisplayName: userProfile.DisplayName,
		Domain:      np.cfg.BaseDomain,
	}
}

func (machines Machines) IDMap() map[uint64]*Machine {
	ret := map[uint64]*Machine{}

	for _, machine := range machines {
		machineCopy := machine
		ret[machineCopy.ID] = &machineCopy
	}

	return ret
}

func (i MachineRegistrationStatus) MarshalBinary() ([]byte, error) {
	return json.Marshal(i)
}
