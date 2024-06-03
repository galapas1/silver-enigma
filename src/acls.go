package ninjapanda

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"gopkg.in/yaml.v3"

	"github.com/Optm-Main/ztmesh-core/envknob"
	"github.com/Optm-Main/ztmesh-core/ztcfg"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

const (
	ErrEmptyPolicy            = Error("empty policy")
	ErrInvalidAction          = Error("invalid action")
	ErrInvalidGroup           = Error("invalid group")
	ErrInvalidTag             = Error("invalid tag")
	ErrInvalidPortFormat      = Error("invalid port format")
	ErrInvalidMachineIdFormat = Error("invalid machine format")
	ErrWildcardIsNeeded       = Error("wildcard as port is required for the protocol")
)

const (
	Base8              = 8
	Base10             = 10
	BitSize16          = 16
	BitSize32          = 32
	BitSize64          = 64
	portRangeBegin     = 0
	portRangeEnd       = 65535
	expectedTokenItems = 2
)

// For some reason golang.org/x/net/internal/iana is an internal package.
const (
	protocolICMP     = 1   // Internet Control Message
	protocolIGMP     = 2   // Internet Group Management
	protocolIPv4     = 4   // IPv4 encapsulation
	protocolTCP      = 6   // Transmission Control
	protocolEGP      = 8   // Exterior Gateway Protocol
	protocolIGP      = 9   // any private interior gateway (used by Cisco for their IGRP)
	protocolUDP      = 17  // User Datagram
	protocolGRE      = 47  // Generic Routing Encapsulation
	protocolESP      = 50  // Encap Security Payload
	protocolAH       = 51  // Authentication Header
	protocolIPv6ICMP = 58  // ICMP for IPv6
	protocolSCTP     = 132 // Stream Control Transmission Protocol
	ProtocolFC       = 133 // Fibre Channel
)

var featureEnableSSH = envknob.RegisterBool("NINJA_SSH_FEATURE")

func (np *Ninjapanda) UpdateACLPolicy(policy ACLPolicy) error {
	if policy.IsZero() {
		log.Debug().
			Caller().
			Interface(logtags.GetTag(logtags.policy, ""), policy).
			Msg("ACL policy is zero")
	}

	np.aclPolicy = &policy

	err := np.UpdateACLRules()

	return err
}

// LoadACLPolicy loads the ACL policy from the specify path, and generates the ACL rules.
func (np *Ninjapanda) LoadACLPolicy(path string) error {
	policyFile, err := os.Open(path)
	if err != nil {
		return err
	}
	defer policyFile.Close()

	var policy ACLPolicy
	policyBytes, err := io.ReadAll(policyFile)
	if err != nil {
		return err
	}

	switch filepath.Ext(path) {
	case ".yml", ".yaml":
		err := yaml.Unmarshal(policyBytes, &policy)
		if err != nil {
			return err
		}

	default:
		err = json.Unmarshal(policyBytes, &policy)
		if err != nil {
			return err
		}
	}

	if policy.IsZero() {
		return ErrEmptyPolicy
	}

	np.aclPolicy = &policy

	return np.UpdateACLRules()
}

func (np *Ninjapanda) UpdateACLRules() error {
	machines, err := np.ListMachines()
	if err != nil {
		return err
	}

	if np.aclPolicy == nil {
		return ErrEmptyPolicy
	}

	log.Debug().
		Caller().
		Msg("generating packet filter rules for all machines")

	rules := generateACLRules(
		machines,
		*np.aclPolicy,
		np.cfg.OIDC.StripEmaildomain,
	)

	np.aclRules = rules

	if featureEnableSSH() {
		panic("ssh feature not implemented")
	} else if np.aclPolicy != nil && len(np.aclPolicy.SSHs) > 0 {
		log.Info().Caller().
			Msg("SSH ACLs has been defined, but NINJA_SSH_FEATURE is not enabled")
	}

	log.Trace().
		Caller().
		Interface(logtags.GetTag(logtags.aclRule, ""), rules).
		Msg("ACL rules generated")

	return nil
}

func generateACLRules(
	machines []Machine,
	aclPolicy ACLPolicy,
	stripEmaildomain bool,
) []ztcfg.FilterRule {
	actions := []string{"accept", "deny"}
	rules := []ztcfg.FilterRule{}

	for _, acl := range aclPolicy.ACLs {
		log.Trace().
			Caller().
			Interface("acl", acl).
			Msg("[ACL DEBUG] evaluating acl")

		if !contains(actions, acl.Action) {
			log.Warn().
				Caller().
				Err(ErrInvalidAction).
				Interface(logtags.GetTag(logtags.acl, ""), acl).
				Str(logtags.GetTag(logtags.acl, "Action"), acl.Action).
				Msg("failed to parse acl, action unknown")

			continue
		}

		newSrcIPs := []string{}
		for _, src := range acl.Sources {
			log.Trace().
				Caller().
				Str("src", src).
				Msg("[ACL DEBUG] expanding source")

			srcs, err := generateACLPolicySrcIP(
				machines,
				aclPolicy,
				src,
				stripEmaildomain,
			)
			if err != nil {
				log.Debug().
					Caller().
					Err(err).
					Interface(logtags.GetTag(logtags.acl, ""), acl).
					Str(logtags.GetTag(logtags.acl, "Sources"), src).
					Msg("acl source unavailable (not a peer or invalid machine)...ignoring")

				continue
			}

			log.Trace().
				Caller().
				Interface("srcs", srcs).
				Msg("[ACL DEBUG] expanded source")

			for _, ip := range srcs {
				if !containsStr(newSrcIPs, ip) {
					newSrcIPs = append(newSrcIPs, ip)
				}
			}
		}

		log.Trace().
			Caller().
			Str("protocol", acl.Protocol).
			Msg("[ACL DEBUG] expanding protocol")

		protocols, needsWildcard, err := ParseProtocol(acl.Protocol)
		if err != nil {
			log.Warn().
				Caller().
				Err(err).
				Interface(logtags.GetTag(logtags.acl, ""), acl).
				Str(logtags.GetTag(logtags.acl, "Protocol"), acl.Protocol).
				Msg("failed to parse acl, protocol unknown")

			continue
		}

		log.Trace().
			Caller().
			Interface("protocols", protocols).
			Msg("[ACL DEBUG] expanded protocols")

		newDestPorts := []ztcfg.NetPortRange{}
		for _, dest := range acl.Destinations {
			log.Trace().
				Caller().
				Str("destination", dest).
				Msg("[ACL DEBUG] expanding destination")

			dests, err := generateACLPolicyDest(
				machines,
				aclPolicy,
				dest,
				needsWildcard,
				stripEmaildomain,
			)
			if err != nil {
				log.Debug().
					Caller().
					Err(err).
					Interface(logtags.GetTag(logtags.acl, ""), acl).
					Str(logtags.GetTag(logtags.acl, "Destinations"), dest).
					Msg("acl destination unavailable (not a peer or invalid machine)... ignoring")

				continue
			}

			log.Trace().
				Caller().
				Interface("destinations", dests).
				Msg("[ACL DEBUG] expanded destinations")

			if len(dests) > 0 {
				newDestPorts = append(newDestPorts, dests...)
			}
		}

		uniqueDests := map[string]ztcfg.NetPortRange{}
		for _, dst := range newDestPorts {
			b, err := json.Marshal(dst)
			if err != nil {
			}
			jsonStr := string(b)
			if _, ok := uniqueDests[jsonStr]; !ok {
				uniqueDests[jsonStr] = dst
			}
		}

		newDestPorts = []ztcfg.NetPortRange{}
		for _, dst := range uniqueDests {
			newDestPorts = append(newDestPorts, dst)
		}

		if acl.Action == "accept" {
			log.Trace().
				Caller().
				Msg("[ACL DEBUG] processing accept action")

			if len(newSrcIPs) > 0 && len(newDestPorts) > 0 {
				rule := ztcfg.FilterRule{
					SrcIPs:   newSrcIPs,
					DstPorts: newDestPorts,
					IPProto:  protocols,
				}
				log.Trace().
					Caller().
					Interface("rule", rule).
					Msg("[ACL DEBUG] adding rule")
				rules = append(rules, rule)
			} else if len(newSrcIPs) == 0 && len(newDestPorts) == 0 {
				log.Trace().
					Caller().
					Msg("[ACL DEBUG] dropping rule - no src ips and no dest ports")
			} else if len(newSrcIPs) == 0 {
				log.Trace().
					Caller().
					Msg("[ACL DEBUG] dropping rule - no src ips")
			} else {
				log.Trace().
					Caller().
					Msg("[ACL DEBUG] dropping rule - no dest ports")
			}
		} else {
			log.Trace().
				Caller().
				Msg("[ACL DEBUG] processing deny action")
			var deniedDstIPs []string
			deniedDstPortMapByIP := make(map[string]ztcfg.PortRange)

			for _, d := range newDestPorts {
				deniedDstIPs = append(deniedDstIPs, d.IP)
				deniedDstPortMapByIP[d.IP] = d.Ports
			}
			for rIndx, rule := range rules {
				var ruleDestIPs []string
				for _, d := range rule.DstPorts {
					ruleDestIPs = append(ruleDestIPs, d.IP)
				}
				// first filter by IP
				if MatchSourceAndDestinationWithRule(
					rule.SrcIPs,
					ruleDestIPs,
					newSrcIPs,
					deniedDstIPs,
				) {
					// find destination IP for deny rule
					var allowDstPorts []ztcfg.NetPortRange
					for _, pendingDstPort := range rule.DstPorts {
						if contains(deniedDstIPs, pendingDstPort.IP) {
							// see if this pendingDstPort has port range overlap
							deniedPorts := deniedDstPortMapByIP[pendingDstPort.IP]

							prunedPortRange := manglePortRange(pendingDstPort, deniedPorts)
							if len(prunedPortRange) > 0 {
								allowDstPorts = append(allowDstPorts, prunedPortRange...)
							}

							log.Debug().
								Caller().
								Str(logtags.GetTag(logtags.aclRule, "DstPorts"), pendingDstPort.IP).
								Interface(logtags.GetTag(logtags.aclRule, ""), rule).
								Msg("Deny IP, removing from rule")
						} else {
							allowDstPorts = append(allowDstPorts, pendingDstPort)
						}
					}

					rules[rIndx].DstPorts = allowDstPorts
				}
			}
		}
	}

	log.Trace().
		Caller().
		Interface("rules", rules).
		Msg("[ACL DEBUG] resulting rules")

	return rules
}

func removePortFromRange(
	destPortRange ztcfg.NetPortRange,
	portToRemove uint16,
) []ztcfg.NetPortRange {
	newDestPortRange := []ztcfg.NetPortRange{}

	if destPortRange.Ports.First == portToRemove &&
		destPortRange.Ports.Last == portToRemove {
		// wholesale remove portToRemove from the destPortRange by returning an empty slice
		return newDestPortRange
	}

	if destPortRange.Ports.First > portToRemove {
		// nothing to do... portToRemove is not in the range
		return []ztcfg.NetPortRange{destPortRange}
	}
	if destPortRange.Ports.Last < portToRemove {
		// nothing to do... portToRemove is not in the range
		return []ztcfg.NetPortRange{destPortRange}
	}

	if destPortRange.Ports.First == portToRemove {
		newDestPortRange = append(newDestPortRange,
			ztcfg.NetPortRange{
				IP: destPortRange.IP,
				Ports: ztcfg.PortRange{
					First: portToRemove + 1,
					Last:  destPortRange.Ports.Last,
				},
			})
	}

	if destPortRange.Ports.Last == portToRemove {
		newDestPortRange = append(newDestPortRange,
			ztcfg.NetPortRange{
				IP: destPortRange.IP,
				Ports: ztcfg.PortRange{
					First: destPortRange.Ports.First,
					Last:  portToRemove - 1,
				},
			})
		newDestPortRange = append(newDestPortRange,
			ztcfg.NetPortRange{
				IP: destPortRange.IP,
				Ports: ztcfg.PortRange{
					First: portToRemove + 1,
					Last:  destPortRange.Ports.Last - 1,
				},
			})
	}

	if destPortRange.Ports.First < portToRemove {
		newDestPortRange = append(newDestPortRange,
			ztcfg.NetPortRange{
				IP: destPortRange.IP,
				Ports: ztcfg.PortRange{
					First: destPortRange.Ports.First,
					Last:  portToRemove - 1,
				},
			})
		newDestPortRange = append(newDestPortRange,
			ztcfg.NetPortRange{
				IP: destPortRange.IP,
				Ports: ztcfg.PortRange{
					First: portToRemove + 1,
					Last:  destPortRange.Ports.Last,
				},
			})
	}

	return newDestPortRange
}

func manglePortRange(
	destPortRange ztcfg.NetPortRange,
	disallowedPorts ztcfg.PortRange,
) []ztcfg.NetPortRange {
	newDestPortRange := []ztcfg.NetPortRange{}

	// handle removal of one port...
	if disallowedPorts.First == disallowedPorts.Last {
		return removePortFromRange(destPortRange, disallowedPorts.First)
	}

	// or handle removal of a range...
	if destPortRange.Ports.First == destPortRange.Ports.Last {
		destPort := destPortRange.Ports.First
		if disallowedPorts.First <= destPort || disallowedPorts.Last >= destPort {
			// destPortRange (single port value) in disallowed range
			return newDestPortRange
		}
		// destPortRange (single port value) not in disallowed range
		return []ztcfg.NetPortRange{destPortRange}
	}

	if destPortRange.Ports.First > disallowedPorts.Last {
		// disallowedPorts not within destPortRange
		return []ztcfg.NetPortRange{destPortRange}
	}
	if destPortRange.Ports.Last < disallowedPorts.First {
		// disallowedPorts not within destPortRange
		return []ztcfg.NetPortRange{destPortRange}
	}

	// disallowedPorts lies fully within destPortRange
	newDestPortRange = append(newDestPortRange,
		ztcfg.NetPortRange{
			IP: destPortRange.IP,
			Ports: ztcfg.PortRange{
				First: destPortRange.Ports.First,
				Last:  disallowedPorts.First - 1,
			},
		})
	newDestPortRange = append(newDestPortRange,
		ztcfg.NetPortRange{
			IP: destPortRange.IP,
			Ports: ztcfg.PortRange{
				First: disallowedPorts.Last + 1,
				Last:  destPortRange.Ports.Last,
			},
		})

	return newDestPortRange
}

func generateACLPolicySrcIP(
	machines []Machine,
	aclPolicy ACLPolicy,
	src string,
	stripEmaildomain bool,
) ([]string, error) {
	return expandAlias(machines, aclPolicy, src, stripEmaildomain)
}

func generateACLPolicyDest(
	machines []Machine,
	aclPolicy ACLPolicy,
	dest string,
	needsWildcard bool,
	stripEmaildomain bool,
) ([]ztcfg.NetPortRange, error) {
	tokens := strings.Split(dest, ":")
	if len(tokens) < expectedTokenItems || len(tokens) > 3 {
		return nil, ErrInvalidPortFormat
	}

	var alias string
	// We can have here stuff like:
	// git-server:*
	// 192.168.1.0/24:22
	// tag:montreal-webserver:80,443
	// tag:api-server:443
	// example-host-1:*
	if len(tokens) == expectedTokenItems {
		alias = tokens[0]
	} else {
		alias = fmt.Sprintf("%s:%s", tokens[0], tokens[1])
	}

	expanded, err := expandAlias(
		machines,
		aclPolicy,
		alias,
		stripEmaildomain,
	)
	if err != nil {
		return nil, err
	}
	ports, err := expandPorts(tokens[len(tokens)-1], needsWildcard)
	if err != nil {
		return nil, err
	}

	dests := []ztcfg.NetPortRange{}
	for _, d := range expanded {
		for _, p := range *ports {
			pr := ztcfg.NetPortRange{
				IP:    d,
				Ports: p,
			}
			dests = append(dests, pr)
		}
	}

	return dests, nil
}

// ParseProtocol reads the proto field of the ACL and generates a list of
// protocols that will be allowed, following the IANA IP protocol number
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
//
// If the ACL proto field is empty, it allows ICMPv4, ICMPv6, TCP, and UDP,
// as per client behaviour (see ztcfg.FilterRule).
//
// Also returns a boolean indicating if the protocol
// requires all the destinations to use wildcard as port number (only TCP,
// UDP and SCTP support specifying ports).
func ParseProtocol(protocol string) ([]int, bool, error) {
	switch protocol {
	case "":
		return nil, false, nil
	case "igmp":
		return []int{protocolIGMP}, true, nil
	case "ipv4", "ip-in-ip":
		return []int{protocolIPv4}, true, nil
	case "tcp":
		return []int{protocolTCP}, false, nil
	case "egp":
		return []int{protocolEGP}, true, nil
	case "igp":
		return []int{protocolIGP}, true, nil
	case "udp":
		return []int{protocolUDP}, false, nil
	case "gre":
		return []int{protocolGRE}, true, nil
	case "esp":
		return []int{protocolESP}, true, nil
	case "ah":
		return []int{protocolAH}, true, nil
	case "sctp":
		return []int{protocolSCTP}, false, nil
	case "icmp":
		return []int{protocolICMP, protocolIPv6ICMP}, true, nil
	case "tcp,udp":
		return []int{protocolTCP, protocolUDP}, false, nil

	default:
		protocolNumber, err := strconv.Atoi(protocol)
		if err != nil {
			return nil, false, err
		}
		needsWildcard := protocolNumber != protocolTCP &&
			protocolNumber != protocolUDP &&
			protocolNumber != protocolSCTP

		return []int{protocolNumber}, needsWildcard, nil
	}
}

// expandalias has an input of either
// - a namespace
// - a group
// - a tag
// and transform these in IPAddresses.
func expandAlias(
	machines []Machine,
	aclPolicy ACLPolicy,
	alias string,
	stripEmailDomain bool,
) ([]string, error) {
	ips := []string{}
	if alias == "*" {
		return []string{"*"}, nil
	}

	if strings.HasPrefix(alias, "machine:") {
		node, err := resolveMachineById(machines, alias)
		if err != nil {
			return ips, err
		}
		return node.IPAddresses.ToStringSlice(), nil
	}

	if strings.HasPrefix(alias, "group:") {
		gs, err := expandGroup(aclPolicy, alias, stripEmailDomain)
		if err != nil {
			return ips, err
		}

		for _, n := range gs {
			if strings.HasPrefix(n, "machine:") {
				node, err := resolveMachineById(machines, n)
				if err != nil {
					return ips, err
				}
				ips = append(ips, node.IPAddresses.ToStringSlice()...)

			} else {
				nodes := filterMachinesByNamespace(machines, n)
				for _, node := range nodes {
					ips = append(ips, node.IPAddresses.ToStringSlice()...)
				}
			}
		}

		return ips, nil
	}

	if strings.HasPrefix(alias, "tag:") {
		// check for forced tags
		for _, machine := range machines {
			if contains(machine.ForcedTags, alias) {
				ips = append(ips, machine.IPAddresses.ToStringSlice()...)
			}
		}

		// find tag owners
		owners, err := expandTagOwners(aclPolicy, alias, stripEmailDomain)
		if err != nil {
			if errors.Is(err, ErrInvalidTag) {
				if len(ips) == 0 {
					return ips, fmt.Errorf(
						"%w. %v isn't owned by a TagOwner and no forced tags are defined",
						ErrInvalidTag,
						alias,
					)
				}

				return ips, nil
			}
			return ips, err
		}

		// filter out machines per tag owner
		for _, namespace := range owners {
			machines := filterMachinesByNamespace(machines, namespace)
			for _, machine := range machines {
				hi := machine.GetHostInfo()
				if contains(hi.RequestTags, alias) {
					ips = append(ips, machine.IPAddresses.ToStringSlice()...)
				}
			}
		}

		return ips, nil
	}

	// if alias is a namespace
	nodes := filterMachinesByNamespace(machines, alias)
	nodes = excludeCorrectlyTaggedNodes(
		aclPolicy,
		nodes,
		alias,
		stripEmailDomain,
	)

	for _, n := range nodes {
		ips = append(ips, n.IPAddresses.ToStringSlice()...)
	}
	if len(ips) > 0 {
		return ips, nil
	}

	// if alias is an host
	if h, ok := aclPolicy.Hosts[alias]; ok {
		return []string{h.String()}, nil
	}

	// if alias is an IP
	ip, err := netip.ParseAddr(alias)
	if err == nil {
		return []string{ip.String()}, nil
	}

	// if alias is an CIDR
	cidr, err := netip.ParsePrefix(alias)
	if err == nil {
		return []string{cidr.String()}, nil
	}

	log.Debug().
		Caller().
		Str("alias", alias).
		Msg("No IPs found for the alias")

	return ips, nil
}

// excludeCorrectlyTaggedNodes will remove from the list of input nodes the ones
// that are correctly tagged since they should not be listed as being in the namespace
// we assume in this function that we only have nodes from 1 namespace.
func excludeCorrectlyTaggedNodes(
	aclPolicy ACLPolicy,
	nodes []Machine,
	namespace string,
	stripEmailDomain bool,
) []Machine {
	out := []Machine{}
	tags := []string{}
	for tag := range aclPolicy.TagOwners {
		owners, _ := expandTagOwners(aclPolicy, namespace, stripEmailDomain)
		ns := append(owners, namespace)
		if contains(ns, namespace) {
			tags = append(tags, tag)
		}
	}
	// for each machine if tag is in tags list, don't append it.
	for _, machine := range nodes {
		hi := machine.GetHostInfo()

		found := false
		for _, t := range hi.RequestTags {
			if contains(tags, t) {
				found = true

				break
			}
		}
		if len(machine.ForcedTags) > 0 {
			found = true
		}
		if !found {
			out = append(out, machine)
		}
	}

	return out
}

func expandPorts(portsStr string, needsWildcard bool) (*[]ztcfg.PortRange, error) {
	if portsStr == "*" {
		return &[]ztcfg.PortRange{
			{First: portRangeBegin, Last: portRangeEnd},
		}, nil
	}

	if needsWildcard {
		return nil, ErrWildcardIsNeeded
	}

	ports := []ztcfg.PortRange{}
	for _, portStr := range strings.Split(portsStr, ",") {
		rang := strings.Split(portStr, "-")
		switch len(rang) {
		case 1:
			port, err := strconv.ParseUint(rang[0], Base10, BitSize16)
			if err != nil {
				return nil, err
			}
			ports = append(ports, ztcfg.PortRange{
				First: uint16(port),
				Last:  uint16(port),
			})

		case expectedTokenItems:
			start, err := strconv.ParseUint(rang[0], Base10, BitSize16)
			if err != nil {
				return nil, err
			}
			last, err := strconv.ParseUint(rang[1], Base10, BitSize16)
			if err != nil {
				return nil, err
			}
			ports = append(ports, ztcfg.PortRange{
				First: uint16(start),
				Last:  uint16(last),
			})

		default:
			return nil, ErrInvalidPortFormat
		}
	}

	return &ports, nil
}

func filterMachinesByNamespace(
	machines []Machine,
	namespace string,
) []Machine {
	out := []Machine{}
	for _, machine := range machines {
		if machine.Namespace.Name == namespace {
			out = append(out, machine)
		}
	}

	return out
}

// expandTagOwners will return a list of namespace. An owner can be either a namespace or a group
// a group cannot be composed of groups.
func expandTagOwners(
	aclPolicy ACLPolicy,
	tag string,
	stripEmailDomain bool,
) ([]string, error) {
	var owners []string
	ows, ok := aclPolicy.TagOwners[tag]
	if !ok {
		return []string{}, fmt.Errorf(
			"%w. %v isn't owned by a TagOwner.",
			ErrInvalidTag,
			tag,
		)
	}
	for _, owner := range ows {
		if strings.HasPrefix(owner, "group:") {
			gs, err := expandGroup(aclPolicy, owner, stripEmailDomain)
			if err != nil {
				return []string{}, err
			}
			owners = append(owners, gs...)
		} else {
			owners = append(owners, owner)
		}
	}

	return owners, nil
}

// resolveMachineById will return the ip of the machine maching the
// machine:<id>
func resolveMachineById(
	machines []Machine,
	alias string,
) (*Machine, error) {
	tokens := strings.Split(alias, ":")
	if len(tokens) != 2 {
		return nil, ErrInvalidMachineIdFormat
	}

	machineId := tokens[1]
	if len(machineId) == 0 {
		return nil, ErrInvalidMachineIdFormat
	}

	for _, machine := range machines {
		if machineId == machine.MachineId {
			return &machine, nil
		}
	}

	return nil, ErrMachineNotFound
}

// expandGroup will return the list of members inside the group
// after some validation.
func expandGroup(
	aclPolicy ACLPolicy,
	group string,
	stripEmailDomain bool,
) ([]string, error) {
	outGroups := []string{}
	aclGroups, ok := aclPolicy.Groups[group]
	if !ok {
		return []string{}, fmt.Errorf(
			"group %v isn't registered. %w",
			group,
			ErrInvalidGroup,
		)
	}
	for _, group := range aclGroups {
		if strings.HasPrefix(group, "machine:") {
			outGroups = append(outGroups, group)
			continue
		}
		if strings.HasPrefix(group, "group:") {
			return []string{}, fmt.Errorf(
				"%w. A group cannot be composed of groups.",
				ErrInvalidGroup,
			)
		}
		grp, err := NormalizeToFQDNRules(group, stripEmailDomain)
		if err != nil {
			return []string{}, fmt.Errorf(
				"failed to normalize group %q, err: %w",
				group,
				ErrInvalidGroup,
			)
		}
		outGroups = append(outGroups, grp)
	}

	return outGroups, nil
}

// GetACLPolicyByACLPolicyID finds an ACL Policy by ID and returns the ACL Policy struct.
func (np *Ninjapanda) GetACLPolicyByACLPolicyID(
	aclPolicyKey string,
) (*ACLPolicy, error) {
	a := ACLPolicy{}
	if result := np.db.First(&a, "acl_policy_key = ?", aclPolicyKey); result.Error != nil {
		return nil, result.Error
	}

	return &a, nil
}

// CreateACLPolicy persists and returns the ACL Policy struct.
func (np *Ninjapanda) CreateACLPolicy(
	aclPolicy *ACLPolicy,
) (*ACLPolicy, error) {
	if err := np.db.Create(&aclPolicy).Error; err != nil {
		log.Error().
			Caller().
			Err(err).
			Send()

		return nil, err
	}

	return aclPolicy, np.LoadACLPolicyFromDB()
}

func (np *Ninjapanda) UpdateAclPolicy(
	aclPolicy *ACLPolicy,
) (*ACLPolicy, error) {
	a := ACLPolicy{}
	if result := np.db.First(&a, "acl_policy_key = ?", aclPolicy.ACLPolicyKey); result.Error != nil {
		return nil, result.Error
	}

	aclPolicy.ID = a.ID
	if result := np.db.Save(aclPolicy); result.Error != nil {
		return nil, result.Error
	}

	return aclPolicy, np.LoadACLPolicyFromDB()
}

func (np *Ninjapanda) DeleteAclPolicy(
	aclPolicy *ACLPolicy,
) error {
	a := ACLPolicy{}
	if result := np.db.First(&a, "acl_policy_key = ?", aclPolicy.ACLPolicyKey); result.Error != nil {
		return result.Error
	}

	if result := np.db.Unscoped().Delete(&a); result.Error != nil {
		return result.Error
	}

	return np.LoadACLPolicyFromDB()
}

// Aggregate all ACL Policies and apply them
func (np *Ninjapanda) LoadACLPolicyFromDB() error {
	aclPolicies := ACLPolicies{}
	if result := np.db.Find(&aclPolicies); result.Error != nil {
		return result.Error
	}

	sort.Slice(aclPolicies, func(p, q int) bool {
		return aclPolicies[p].Order < aclPolicies[q].Order
	})

	aclPolicy := ACLPolicy{
		Groups:    make(Groups),
		Hosts:     make(Hosts),
		TagOwners: make(TagOwners),
		ACLs:      make([]ACL, 0),
		Tests:     make([]ACLTest, 0),
	}

	for _, v := range aclPolicies {
		// sort rules within a policy
		sort.Slice(v.ACLs, func(p, q int) bool {
			return v.ACLs[p].Order < v.ACLs[q].Order
		})
		for k, g := range v.Groups {
			aclPolicy.Groups[k] = append(aclPolicy.Groups[k], g...)
		}
		for k, h := range v.Hosts {
			aclPolicy.Hosts[k] = h
		}
		for k, t := range v.TagOwners {
			aclPolicy.TagOwners[k] = append(aclPolicy.TagOwners[k], t...)
		}
		for _, a := range v.ACLs {
			aclPolicy.ACLs = append(aclPolicy.ACLs, a)
		}
		for _, t := range v.Tests {
			aclPolicy.Tests = append(aclPolicy.Tests, t)
		}
	}

	return np.UpdateACLPolicy(aclPolicy)
}

func (np *Ninjapanda) GenerateFilterAndSSHRules(
	policy *ACLPolicy,
	machine *Machine,
	peers Machines,
) ([]ztcfg.FilterRule, *ztcfg.SSHPolicy, error) {
	if policy == nil {
		return FilterDenyAll, &ztcfg.SSHPolicy{}, nil
	}

	log.Debug().
		Caller().
		Msg("generating packet filter rules for peers")

	rules := generateACLRules(
		append(peers, *machine),
		*np.aclPolicy,
		np.cfg.OIDC.StripEmaildomain,
	)

	sshPolicy := &ztcfg.SSHPolicy{}
	if featureEnableSSH() {
		panic("ssh feature not implemented")
	}

	return rules, sshPolicy, nil
}

func ReduceFilterRules(
	machine *Machine,
	rules []ztcfg.FilterRule,
) []ztcfg.FilterRule {
	ret := []ztcfg.FilterRule{}

	for _, rule := range rules {
		log.Trace().
			Caller().
			Interface("rule", rule).
			Msg("[ACL DEBUG] filtering rule")

		dests := []ztcfg.NetPortRange{}

		for _, dest := range rule.DstPorts {
			expanded, err := ParseIPSet(dest.IP, nil)
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Interface("dest_ip", dest.IP).
					Msg("[ACL DEBUG] failed to parse")
				continue
			}

			if machine.IPAddresses.InIPSet(expanded) {
				dests = append(dests, dest)

				continue
			} else {
				log.Trace().
					Caller().
					Interface("expanded_ips", expanded).
					Interface("machine_ips", machine.IPAddresses).
					Msg("[ACL DEBUG] machine ips not in expanded ip set")
			}

			if len(machine.HostInfo.RoutableIPs) > 0 {
				doAppend := false
				for _, routableIP := range machine.HostInfo.RoutableIPs {
					if expanded.ContainsPrefix(routableIP) {
						doAppend = true

						break
					}
				}
				if doAppend {
					dests = append(dests, dest)
				}
			}
		}

		if len(dests) > 0 {
			rule := ztcfg.FilterRule{
				SrcIPs:   rule.SrcIPs,
				DstPorts: dests,
				IPProto:  rule.IPProto,
			}
			log.Trace().
				Caller().
				Interface("filtered_rule", rule).
				Msg("[ACL DEBUG] including rule")
			ret = append(ret, rule)
		}
	}

	return ret
}

func (aclPolicy *ACLPolicy) toProto() *v1.ACLPolicy {
	aclPolicyProto := &v1.ACLPolicy{
		AclpolicyId: aclPolicy.ACLPolicyKey,
		Order:       aclPolicy.Order,
		Hosts:       make(map[string]string),
		Groups:      make([]*v1.MapFieldEntry, 0),
		Acls:        make([]*v1.ACL, 0),
		Tests:       make([]*v1.ACLTest, 0),
	}
	for k, v := range aclPolicy.Groups {
		mapFieldEntry := &v1.MapFieldEntry{
			Key:    k,
			Values: make([]string, 0),
		}
		mapFieldEntry.Values = append(mapFieldEntry.Values, v...)
		aclPolicyProto.Groups = append(aclPolicyProto.Groups, mapFieldEntry)
	}
	for k, v := range aclPolicy.Hosts {
		aclPolicyProto.GetHosts()[k] = v.String()
	}
	for k, v := range aclPolicy.TagOwners {
		mapFieldEntry := &v1.MapFieldEntry{
			Key:    k,
			Values: make([]string, 0),
		}
		mapFieldEntry.Values = append(mapFieldEntry.Values, v...)
		aclPolicyProto.Tags = append(aclPolicyProto.Tags, mapFieldEntry)
	}
	for _, v := range aclPolicy.ACLs {
		acl := &v1.ACL{
			Order:        v.Order,
			Action:       v.Action,
			Protocol:     v.Protocol,
			Sources:      make([]string, 0),
			Destinations: make([]string, 0),
		}
		for _, s := range v.Sources {
			acl.Sources = append(acl.Sources, s)
		}
		for _, d := range v.Destinations {
			tokens := strings.Split(d, ":")
			if len(tokens) > 1 {
				acl.Port = tokens[len(tokens)-1]
			}
			acl.Destinations = append(
				acl.Destinations,
				strings.Join(tokens[:len(tokens)-1], ":"),
			)
		}
		aclPolicyProto.Acls = append(aclPolicyProto.Acls, acl)
	}

	return aclPolicyProto
}
