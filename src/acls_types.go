package ninjapanda

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ErrGroupsInvalid        = Error("failed to parse groups")
	ErrHostsInvalid         = Error("failed to parse hosts")
	ErrTagOwnersInvalid     = Error("failed to parse tag owners")
	ErrStringSliceInvalid   = Error("failed to parse string slice")
	ErrAclSliceInvalid      = Error("failed to parse acl slice")
	ErrAclTestSliceInvalid  = Error("failed to parse acl test slice")
	ErrSshSliceInvalid      = Error("failed to parse ssh slice")
	ErrAutoApproversInvalid = Error("failed to parse auto approvers")
)

// ACLPolicy represents an ACL Policy.
type ACLPolicy struct {
	ID            uint64        `gorm:"primary_key"`
	Order         uint64        `gorm:"default:0"`
	ACLPolicyKey  string        `gorm:"type:varchar(64);unique" json:"aclpolicy_id"  yaml:"aclpolicy_id"`
	Groups        Groups        `                               json:"groups"        yaml:"groups"`
	Hosts         Hosts         `gorm:"type:text"               json:"hosts"         yaml:"hosts"`
	TagOwners     TagOwners     `gorm:"type:text"               json:"tagOwners"     yaml:"tagOwners"`
	ACLs          AclSlice      `gorm:"type:text;column:acls"   json:"acls"          yaml:"acls"`
	Tests         AclTestSlice  `gorm:"type:text"               json:"tests"         yaml:"tests"`
	AutoApprovers AutoApprovers `gorm:"type:text"               json:"autoApprovers" yaml:"autoApprovers"`
	SSHs          SshSlice      `                               json:"ssh"           yaml:"ssh"`
}

type (
	ACLPolicies  []ACLPolicy
	ACLPoliciesP []*ACLPolicy
)

// Groups references a series of alias in the ACL rules.
type Groups map[string][]string

// Scan value into json, implements sql.Scanner interface
func (g *Groups) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		return json.Unmarshal([]byte(value), g)
	case []byte:
		return json.Unmarshal(value, g)
	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrGroupsInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (g Groups) Value() (driver.Value, error) {
	bytes, err := json.Marshal(g)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to encode %s", ErrGroupsInvalid, err.Error())
	}
	return string(bytes), nil
}

// Hosts are alias for IP addresses or subnets.
type Hosts map[string]netip.Prefix

func (hv *Hosts) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		return json.Unmarshal([]byte(value), hv)
	case []byte:
		return json.Unmarshal(value, hv)
	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrHostsInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (hv Hosts) Value() (driver.Value, error) {
	bytes, err := json.Marshal(hv)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to encode %s", ErrHostsInvalid, err.Error())
	}
	return string(bytes), nil
}

// TagOwners specify what users (namespaces?) are allow to use certain tags.
type TagOwners map[string][]string

// Scan value into json, implements sql.Scanner interface
func (to *TagOwners) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		return json.Unmarshal([]byte(value), to)
	case []byte:
		return json.Unmarshal(value, to)
	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrTagOwnersInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (to TagOwners) Value() (driver.Value, error) {
	bytes, err := json.Marshal(to)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: failed to encode %s",
			ErrTagOwnersInvalid,
			err.Error(),
		)
	}
	return string(bytes), nil
}

type StringSlice []string

func (s *StringSlice) Scan(destination interface{}) error {
	str, ok := destination.(string)
	if !ok {
		return fmt.Errorf("%w: %T", ErrStringSliceInvalid, destination)
	}
	*s = strings.Split(str, ",")
	return nil
}

func (s StringSlice) Value() (driver.Value, error) {
	if s == nil || len(s) == 0 {
		return nil, nil
	}
	return strings.Join(s, ","), nil
}

// ACL is a basic rule for the ACL Policy.
type ACL struct {
	Order        uint64      `gorm:"default:0"`
	Action       string      `                 json:"action" yaml:"action"`
	Protocol     string      `                 json:"proto"  yaml:"proto"`
	Sources      StringSlice `gorm:"type:text" json:"src"    yaml:"src"`
	Destinations StringSlice `gorm:"type:text" json:"dst"    yaml:"dst"`
}

type AclSlice []ACL

func (s *AclSlice) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		return json.Unmarshal([]byte(value), s)
	case []byte:
		return json.Unmarshal(value, s)
	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrAclSliceInvalid, destination)
	}
}

func (s AclSlice) Value() (driver.Value, error) {
	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: failed to encode %s",
			ErrAclSliceInvalid,
			err.Error(),
		)
	}
	return string(bytes), nil
}

// ACLTest is not implemented, but should be use to check if a certain rule is allowed.
type ACLTest struct {
	Source string      `json:"src"            yaml:"src"`
	Accept StringSlice `json:"accept"         yaml:"accept"         gorm:"type:text"`
	Deny   StringSlice `json:"deny,omitempty" yaml:"deny,omitempty" gorm:"type:text"`
}

type AclTestSlice []ACLTest

func (s *AclTestSlice) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		return json.Unmarshal([]byte(value), s)
	case []byte:
		return json.Unmarshal(value, s)
	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrAclTestSliceInvalid, destination)
	}
}

func (s AclTestSlice) Value() (driver.Value, error) {
	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: failed to encode %s",
			ErrAclTestSliceInvalid,
			err.Error(),
		)
	}
	return string(bytes), nil
}

// AutoApprovers specify which users (namespaces?), groups or tags have their advertised routes
// or exit node status automatically enabled.
type AutoApprovers struct {
	Routes   map[string][]string `json:"routes"   yaml:"routes"`
	ExitNode []string            `json:"exitNode" yaml:"exitNode"`
}

// Scan value into json, implements sql.Scanner interface
func (a *AutoApprovers) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		return json.Unmarshal([]byte(value), a)
	case []byte:
		return json.Unmarshal(value, a)
	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrAutoApproversInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (a AutoApprovers) Value() (driver.Value, error) {
	bytes, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: failed to encode %s",
			ErrAutoApproversInvalid,
			err.Error(),
		)
	}
	return string(bytes), nil
}

// Returns the list of autoApproving namespaces, groups or tags for a given IPPrefix.
func (autoApprovers *AutoApprovers) GetRouteApprovers(
	prefix netip.Prefix,
) ([]string, error) {
	if prefix.Bits() == 0 {
		return autoApprovers.ExitNode, nil // 0.0.0.0/0, ::/0 or equivalent
	}

	approverAliases := []string{}

	for autoApprovedPrefix, autoApproverAliases := range autoApprovers.Routes {
		autoApprovedPrefix, err := netip.ParsePrefix(autoApprovedPrefix)
		if err != nil {
			return nil, err
		}

		if prefix.Bits() >= autoApprovedPrefix.Bits() &&
			autoApprovedPrefix.Contains(prefix.Masked().Addr()) {
			approverAliases = append(approverAliases, autoApproverAliases...)
		}
	}

	return approverAliases, nil
}

type SSH struct {
	Action       string      `json:"action"                yaml:"action"`
	Sources      StringSlice `json:"src"                   yaml:"src"`
	Destinations StringSlice `json:"dst"                   yaml:"dst"`
	Users        StringSlice `json:"users"                 yaml:"users"`
	CheckPeriod  string      `json:"checkPeriod,omitempty" yaml:"checkPeriod,omitempty"`
}
type SshSlice []SSH

func (s *SshSlice) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		return json.Unmarshal([]byte(value), s)
	case []byte:
		return json.Unmarshal(value, s)
	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrSshSliceInvalid, destination)
	}
}

func (s SshSlice) Value() (driver.Value, error) {
	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: failed to encode %s",
			ErrSshSliceInvalid,
			err.Error(),
		)
	}
	return string(bytes), nil
}

// UnmarshalJSON allows to parse the Hosts directly into netip objects.
func (hosts *Hosts) UnmarshalJSON(data []byte) error {
	newHosts := Hosts{}
	hostIPPrefixMap := make(map[string]string)

	err := json.Unmarshal(data, &hostIPPrefixMap)
	if err != nil {
		return err
	}
	for host, prefixStr := range hostIPPrefixMap {
		if !strings.Contains(prefixStr, "/") {
			prefixStr += "/32"
		}
		prefix, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			return err
		}
		newHosts[host] = prefix
	}
	*hosts = newHosts

	return nil
}

// UnmarshalYAML allows to parse the Hosts directly into netip objects.
func (hosts *Hosts) UnmarshalYAML(data []byte) error {
	newHosts := Hosts{}
	hostIPPrefixMap := make(map[string]string)

	err := yaml.Unmarshal(data, &hostIPPrefixMap)
	if err != nil {
		return err
	}
	for host, prefixStr := range hostIPPrefixMap {
		prefix, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			return err
		}
		newHosts[host] = prefix
	}
	*hosts = newHosts

	return nil
}

// IsZero is perhaps a bit naive here.
func (policy ACLPolicy) IsZero() bool {
	if len(policy.Groups) == 0 && len(policy.Hosts) == 0 && len(policy.ACLs) == 0 {
		return true
	}

	return false
}
