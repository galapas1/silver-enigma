package ninjapanda

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"

	"github.com/rs/zerolog/log"

	"go4.org/netipx"
	"gorm.io/gorm"

	"github.com/Optm-Main/ztmesh-core/types/dnstype"
	"github.com/Optm-Main/ztmesh-core/util/dnsname"
	"github.com/Optm-Main/ztmesh-core/ztcfg"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

const (
	ByteSize = 8
)

const (
	ipv4AddressLength = 32
	ipv6AddressLength = 128
)

const (
	nextDNSDoHPrefix = "https://dns.nextdns.io"
)

const (
	ErrRestrictedNameserversInvalid = Error("failed to parse restricted nameservers")
	ErrNameserversInvalid           = Error("failed to parse nameservers")
	ErrDNSConfigNotFound            = Error("DNSConfig not found")
)

// DNSConfig represents dynamic client DNSConfig settings
type DNSConfig struct {
	ID uint64 `gorm:"primary_key"`

	NamespaceID uint
	Namespace   Namespace `gorm:"foreignKey:NamespaceID"`

	OverrideLocalDNS bool
	MagicDNS         bool

	Nameservers           Nameservers `gorm:"type:text"`
	RestrictedNameservers RestrictedNameservers
}

type Nameservers []netip.Addr

func (n Nameservers) ToStringSlice() []string {
	strSlice := make([]string, 0, len(n))
	for _, addr := range n {
		strSlice = append(strSlice, addr.String())
	}

	return strSlice
}

func (n *Nameservers) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		addresses := strings.Split(value, ",")
		*n = (*n)[:0]
		for _, addr := range addresses {
			if len(addr) < 1 {
				continue
			}
			parsed, err := netip.ParseAddr(addr)
			if err != nil {
				return err
			}
			*n = append(*n, parsed)
		}

		return nil

	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrNameserversInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (n Nameservers) Value() (driver.Value, error) {
	addresses := strings.Join(n.ToStringSlice(), ",")

	return addresses, nil
}

type RestrictedNameservers map[string]Nameservers

// Scan value into json, implements sql.Scanner interface
func (r *RestrictedNameservers) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		return json.Unmarshal([]byte(value), r)
	case []byte:
		return json.Unmarshal(value, r)
	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrRestrictedNameserversInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (r RestrictedNameservers) Value() (driver.Value, error) {
	bytes, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: failed to encode %s",
			ErrRestrictedNameserversInvalid,
			err.Error(),
		)
	}
	return string(bytes), nil
}

func (np *Ninjapanda) SaveDNSConfig(
	dnsConfig DNSConfig,
) (*DNSConfig, error) {
	log.Debug().
		Caller().
		Interface(logtags.GetTag(logtags.dnsConfig, ""), dnsConfig).
		Send()

	if err := np.db.Save(&dnsConfig).Error; err != nil {
		return nil, fmt.Errorf("failed save dns config in the database: %w", err)
	}

	return &dnsConfig, nil
}

func (np *Ninjapanda) GetDNSConfigByNamespace(
	name string,
) (*DNSConfig, error) {
	namespace, err := np.GetNamespace(name)
	if err != nil {
		return nil, err
	}

	dnsConfig := DNSConfig{}
	if result := np.db.First(&dnsConfig, "namespace_id = ?", namespace.ID); result.Error != nil {
		if result.Error != gorm.ErrRecordNotFound {
			log.Error().
				Caller().
				Str(logtags.GetTag(logtags.namespace, "Name"), name).
				Err(result.Error).
				Send()
		}
		return nil, result.Error
	}

	dnsConfig.Namespace = *namespace

	return &dnsConfig, nil
}

// generateMagicDNSRootDomains generates a list of DNS entries to be included in `Routes` in `MapResponse`.
// This list of reverse DNS entries instructs the OS on what subnets and domains embedded DNS
// server (listening in 100.100.100.100 udp/53) should be used for.
//
// Includes in the list:
// - the `BaseDomain` of the user
// - the reverse DNS entry for IPv6 (0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa., see below more on IPv6)
// - the reverse DNS entries for the IPv4 subnets covered by the user's `IPPrefix`.
//   In the public SaaS this is [64-127].100.in-addr.arpa.
//
// The main purpose of this function is then generating the list of IPv4 entries. For the 100.64.0.0/10, this
// is clear, and could be hardcoded. But we are allowing any range as `IPPrefix`, so we need to find out the
// subnets when we have 172.16.0.0/16 (i.e., [0-255].16.172.in-addr.arpa.), or any other subnet.
//
// How IN-ADDR.ARPA domains work is defined in RFC1035 (section 3.5). We seem to adhere to this,
// and do not make use of RFC2317 ("Classless IN-ADDR.ARPA delegation") - hence generating the entries for the next
// class block only.

// From the netmask we can find out the wildcard bits (the bits that are not set in the netmask).
// This allows us to then calculate the subnets included in the subsequent class block and generate the entries.
func generateMagicDNSRootDomains(ipPrefixes []netip.Prefix) []dnsname.FQDN {
	fqdns := make([]dnsname.FQDN, 0, len(ipPrefixes))
	for _, ipPrefix := range ipPrefixes {
		var generateDNSRoot func(netip.Prefix) []dnsname.FQDN
		switch ipPrefix.Addr().BitLen() {
		case ipv4AddressLength:
			generateDNSRoot = generateIPv4DNSRootDomain

		case ipv6AddressLength:
			generateDNSRoot = generateIPv6DNSRootDomain

		default:
			generateDNSRoot = func(p netip.Prefix) []dnsname.FQDN {
				return []dnsname.FQDN{}
			}
		}

		fqdns = append(fqdns, generateDNSRoot(ipPrefix)...)
	}

	return fqdns
}

// If any nextdns DoH resolvers are present in the list of resolvers it will
// take metadata from the machine metadata and instruct client to add it
// to the requests. This makes it possible to identify from which device the
// requests come in the NextDNS dashboard.
//
// This will produce a resolver like:
// `https://dns.nextdns.io/<nextdns-id>?device_name=node-name&device_model=linux&device_ip=100.64.0.1`
func addNextDNSMetadata(resolvers []*dnstype.Resolver, machine Machine) {
	for _, resolver := range resolvers {
		if strings.HasPrefix(resolver.Addr, nextDNSDoHPrefix) {
			attrs := url.Values{
				"device_name":  []string{machine.Hostname},
				"device_model": []string{machine.HostInfo.OS},
			}

			if len(machine.IPAddresses) > 0 {
				attrs.Add("device_ip", machine.IPAddresses[0].String())
			}

			resolver.Addr = fmt.Sprintf("%s?%s", resolver.Addr, attrs.Encode())
		}
	}
}

func generateIPv4DNSRootDomain(ipPrefix netip.Prefix) []dnsname.FQDN {
	// Conversion to the std lib net.IPnet, a bit easier to operate
	netRange := netipx.PrefixIPNet(ipPrefix)
	maskBits, _ := netRange.Mask.Size()

	// lastOctet is the last IP byte covered by the mask
	lastOctet := maskBits / ByteSize

	// wildcardBits is the number of bits not under the mask in the lastOctet
	wildcardBits := ByteSize - maskBits%ByteSize

	// min is the value in the lastOctet byte of the IP
	// max is basically 2^wildcardBits - i.e., the value when all the wildcardBits are set to 1
	min := uint(netRange.IP[lastOctet])
	max := (min + 1<<uint(wildcardBits)) - 1

	// here we generate the base domain (e.g., 100.in-addr.arpa., 16.172.in-addr.arpa., etc.)
	rdnsSlice := []string{}
	for i := lastOctet - 1; i >= 0; i-- {
		rdnsSlice = append(rdnsSlice, fmt.Sprintf("%d", netRange.IP[i]))
	}
	rdnsSlice = append(rdnsSlice, "in-addr.arpa.")
	rdnsBase := strings.Join(rdnsSlice, ".")

	fqdns := make([]dnsname.FQDN, 0, max-min+1)
	for i := min; i <= max; i++ {
		fqdn, err := dnsname.ToFQDN(fmt.Sprintf("%d.%s", i, rdnsBase))
		if err != nil {
			continue
		}
		fqdns = append(fqdns, fqdn)
	}

	return fqdns
}

func generateIPv6DNSRootDomain(ipPrefix netip.Prefix) []dnsname.FQDN {
	const nibbleLen = 4

	maskBits, _ := netipx.PrefixIPNet(ipPrefix).Mask.Size()
	expanded := ipPrefix.Addr().StringExpanded()
	nibbleStr := strings.Map(func(r rune) rune {
		if r == ':' {
			return -1
		}

		return r
	}, expanded)

	// TODO?: that does not look the most efficient implementation,
	// but the inputs are not so long as to cause problems,
	// and from what I can see, the generateMagicDNSRootDomains
	// function is called only once over the lifetime of a server process.
	prefixConstantParts := []string{}
	for i := 0; i < maskBits/nibbleLen; i++ {
		prefixConstantParts = append(
			[]string{string(nibbleStr[i])},
			prefixConstantParts...)
	}

	makeDomain := func(variablePrefix ...string) (dnsname.FQDN, error) {
		prefix := strings.Join(append(variablePrefix, prefixConstantParts...), ".")

		return dnsname.ToFQDN(fmt.Sprintf("%s.ip6.arpa", prefix))
	}

	var fqdns []dnsname.FQDN
	if maskBits%4 == 0 {
		dom, _ := makeDomain()
		fqdns = append(fqdns, dom)
	} else {
		domCount := 1 << (maskBits % nibbleLen)
		fqdns = make([]dnsname.FQDN, 0, domCount)
		for i := 0; i < domCount; i++ {
			varNibble := fmt.Sprintf("%x", i)
			dom, err := makeDomain(varNibble)
			if err != nil {
				continue
			}
			fqdns = append(fqdns, dom)
		}
	}

	return fqdns
}

func getMapResponseDNSConfig(
	dnsConfigOrig *ztcfg.DNSConfig,
	baseDomain string,
	machine Machine,
	peers Machines,
) *ztcfg.DNSConfig {
	var dnsConfig *ztcfg.DNSConfig = dnsConfigOrig.Clone()
	if dnsConfigOrig != nil && dnsConfigOrig.Proxied { // if MagicDNS is enabled
		// Only inject the Search Domain of the current namespace - shared nodes should use their full FQDN
		dnsConfig.Domains = append(
			dnsConfig.Domains,
			fmt.Sprintf(
				"%s.%s",
				machine.Namespace.Name,
				baseDomain,
			),
		)

		namespaceSet := mapset.NewSet[Namespace]()
		namespaceSet.Add(machine.Namespace)
		for _, p := range peers {
			namespaceSet.Add(p.Namespace)
		}
		for _, namespace := range namespaceSet.ToSlice() {
			dnsRoute := fmt.Sprintf("%v.%v", namespace.Name, baseDomain)
			dnsConfig.Routes[dnsRoute] = nil
		}
	} else {
		dnsConfig = dnsConfigOrig
	}

	addNextDNSMetadata(dnsConfig.Resolvers, machine)

	return dnsConfig
}

// TODO: cache DNS Config for Namespace
func (np *Ninjapanda) DNSConfigForNamespace(
	namespace string,
) *ztcfg.DNSConfig {
	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.namespace, "Name"), namespace).
		Send()

	nsDnsConfig, err := np.GetDNSConfigByNamespace(namespace)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// TODO: Log and perhaps rate-limit this?
			return np.cfg.DNSConfig
		}
		log.Error().
			Caller().
			Str(logtags.GetTag(logtags.namespace, "Name"), namespace).
			Err(err).
			Msgf("Failed to fetch dns config from the database")

		return np.cfg.DNSConfig
	}

	dnsConfig := np.cfg.DNSConfig.Clone()
	log.Debug().
		Caller().
		Str(logtags.GetTag(logtags.namespace, "Name"), namespace).
		Interface(logtags.GetTag(logtags.dnsConfig, ""), dnsConfig).
		Msg("constructing dns config for namespace")

	dnsConfig.Resolvers = nil
	dnsConfig.FallbackResolvers = nil

	dnsConfig.Routes = make(map[string][]*dnstype.Resolver)
	dnsConfig.Nameservers = nsDnsConfig.Nameservers

	resolvers := []*dnstype.Resolver{}
	if len(nsDnsConfig.Nameservers) > 0 {
		for _, ns := range nsDnsConfig.Nameservers {
			resolvers = append(resolvers, &dnstype.Resolver{
				Addr: ns.String(),
			})
		}
	}
	if nsDnsConfig.OverrideLocalDNS {
		dnsConfig.Resolvers = resolvers
	} else {
		dnsConfig.FallbackResolvers = resolvers
	}

	dnsConfig.Proxied = nsDnsConfig.MagicDNS
	if dnsConfig.Proxied {
		magicDNSDomains := generateMagicDNSRootDomains(np.cfg.IPPrefixes)
		for _, d := range magicDNSDomains {
			dnsConfig.Routes[d.WithoutTrailingDot()] = nil
		}
	}

	for domain, restrictedNameservers := range nsDnsConfig.RestrictedNameservers {
		restrictedResolvers := make(
			[]*dnstype.Resolver,
			len(restrictedNameservers),
		)
		for index, nameserver := range restrictedNameservers {
			restrictedResolvers[index] = &dnstype.Resolver{
				Addr: nameserver.String(),
			}
		}
		dnsConfig.Routes[domain] = restrictedResolvers
	}

	log.Debug().
		Caller().
		Str(logtags.GetTag(logtags.namespace, "Name"), namespace).
		Interface(logtags.GetTag(logtags.dnsConfig, ""), dnsConfig).
		Msg("tailored dns config for namespace")

	return dnsConfig
}

func (np *Ninjapanda) DeleteDnsConfig(namespaceId uint) error {
	d := DNSConfig{}
	if result := np.db.First(&d, "namespace_id = ?", namespaceId); result.Error != nil {
		return result.Error
	}

	if result := np.db.Unscoped().Delete(&d); result.Error != nil {
		return result.Error
	}

	return nil
}

func (dnsConfig *DNSConfig) toProto() *v1.DNSConfig {
	dnsConfigProto := &v1.DNSConfig{
		Namespace:         dnsConfig.Namespace.Name,
		UseLocal:          dnsConfig.OverrideLocalDNS,
		EnableMagicDns:    dnsConfig.MagicDNS,
		NameserverIpAddrs: dnsConfig.Nameservers.ToStringSlice(),
		SearchDomainNs:    make([]*v1.MapFieldEntry, 0),
	}

	for k, v := range dnsConfig.RestrictedNameservers {
		mapFieldEntry := &v1.MapFieldEntry{
			Key:    k,
			Values: make([]string, 0),
		}
		for _, ip := range v {
			mapFieldEntry.Values = append(mapFieldEntry.Values, ip.String())
		}
		dnsConfigProto.SearchDomainNs = append(
			dnsConfigProto.SearchDomainNs,
			mapFieldEntry,
		)
	}

	return dnsConfigProto
}
