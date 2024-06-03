package ninjapanda

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"google.golang.org/grpc/peer"

	"github.com/Optm-Main/ztmesh-core/ztcfg"

	structs "optm.com/ninja-panda/src/internal/structs"
)

var (
	matchFirstCap = regexp.MustCompile("(.)([A-Z][a-z]+)")
	matchAllCap   = regexp.MustCompile("([a-z0-9])([A-Z])")
)

type LogTags struct {
	acl              *structs.Struct
	aclPolicy        *structs.Struct
	aclRule          *structs.Struct
	config           *structs.Struct
	dnsConfig        *structs.Struct
	hostInfo         *structs.Struct
	httpResponse     *structs.Struct
	httpRequest      *structs.Struct
	kafkaConfig      *structs.Struct
	kv               *structs.Struct
	machine          *structs.Struct
	machineLocation  *structs.Struct
	mapRequest       *structs.Struct
	namespace        *structs.Struct
	nameserver       *structs.Struct
	peer             *structs.Struct
	policy           *structs.Struct
	preAuthKey       *structs.Struct
	relayConfig      *structs.Struct
	registerRequest  *structs.Struct
	registerResponse *structs.Struct
	route            *structs.Struct
	sshPolicy        *structs.Struct
	stateUpdate      *structs.Struct
	userProfile      *structs.Struct
	url              *structs.Struct
}

func NewLogTags() *LogTags {
	var acl ACL
	var aclPolicy ACLPolicy
	var config Config
	var dnsConfig DNSConfig
	var httpResponse http.Response
	var httpRequest http.Request
	var kv KV
	var kafkaConfig KafkaConfig
	var machine Machine
	var machineLocation MachineLocation
	var namespace Namespace
	var nameserver netip.Addr
	var peer peer.Peer
	var policy ACLPolicy
	var preAuthKey PreAuthKey
	var relayConfig RELAYConfig
	var route Route
	var userProfile UserProfile
	var url url.URL

	var aclRule ztcfg.FilterRule
	var hostInfo ztcfg.Hostinfo
	var mapRequest ztcfg.MapRequest
	var registerRequest ztcfg.RegisterRequest
	var registerResponse ztcfg.RegisterResponse
	var sshPolicy ztcfg.SSHPolicy
	var stateUpdate StateUpdate

	logTags := &LogTags{
		acl:             structs.New(&acl),
		aclPolicy:       structs.New(&aclPolicy),
		config:          structs.New(&config),
		dnsConfig:       structs.New(&dnsConfig),
		httpResponse:    structs.New(&httpResponse),
		httpRequest:     structs.New(&httpRequest),
		kafkaConfig:     structs.New(&kafkaConfig),
		kv:              structs.New(&kv),
		machine:         structs.New(&machine),
		machineLocation: structs.New(&machineLocation),
		namespace:       structs.New(&namespace),
		nameserver:      structs.New(&nameserver),
		peer:            structs.New(&peer),
		policy:          structs.New(&policy),
		preAuthKey:      structs.New(&preAuthKey),
		relayConfig:     structs.New(&relayConfig),
		route:           structs.New(&route),
		userProfile:     structs.New(&userProfile),
		url:             structs.New(&url),

		aclRule:          structs.New(&aclRule),
		hostInfo:         structs.New(&hostInfo),
		mapRequest:       structs.New(&mapRequest),
		registerRequest:  structs.New(&registerRequest),
		registerResponse: structs.New(&registerResponse),
		sshPolicy:        structs.New(&sshPolicy),
		stateUpdate:      structs.New(&stateUpdate),
	}

	return logTags
}

func (l *LogTags) MakeTag(name string) string {
	return toSnakeCase(name)
}

func (l *LogTags) GetFieldName(s *structs.Struct, name string) string {
	if len(name) > 0 {
		name = toCamelCase(name)
		f, ok := s.FieldOk(name)
		if ok {
			return f.Name()
		}
	}

	panic(
		fmt.Sprintf(
			"internal error: field '%s' does not exist in '%s'",
			name, s.Name(),
		),
	)
}

func (l *LogTags) GetTag(s *structs.Struct, name string) string {
	tag := s.Name()
	if len(name) > 0 {
		f, ok := s.FieldOk(name)
		if ok {
			tag = f.Name()
		} else {
			tag += "_undef!"
		}
	}

	return toSnakeCase(tag)
}

func toSnakeCase(str string) string {
	snake := matchFirstCap.ReplaceAllString(str, "${1}_${2}")
	snake = matchAllCap.ReplaceAllString(snake, "${1}_${2}")

	return strings.ToLower(snake)
}

func toCamelCase(s string) string {
	s = regexp.MustCompile("[^a-zA-Z0-9_ ]+").ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "_", " ")

	s = cases.Title(language.AmericanEnglish, cases.NoLower).String(s)
	s = strings.ReplaceAll(s, " ", "")

	return s
}
