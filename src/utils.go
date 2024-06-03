package ninjapanda

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"

	"go4.org/netipx"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Optm-Main/ztmesh-core/types/key"
)

const (
	ErrCannotDecryptResponse = Error("cannot decrypt response")
	ErrCouldNotAllocateIP    = Error("could not find any suitable IP")

	// These constants are copied from the upstream github.com/Optm-Main/ztmesh-core/types/key
	// library, because they are not exported.

	// nodePublicHexPrefix is the prefix used to identify a
	// hex-encoded node public key.
	//
	// This prefix is used in the control protocol, so cannot be
	// changed.
	nodePublicHexPrefix = "nodekey:"

	// machinePublicHexPrefix is the prefix used to identify a
	// hex-encoded machine public key.
	//
	// This prefix is used in the control protocol, so cannot be
	// changed.
	machinePublicHexPrefix = "mkey:"

	// sessionPublicHexPrefix is the prefix used to identify a
	// hex-encoded session public key.
	//
	// This prefix is used in the control protocol, so cannot be
	// changed.
	sessionPublicHexPrefix = "sessionkey:"

	// privateKey prefix.
	privateHexPrefix = "privkey:"

	PermissionFallback = 0o700

	ZstdCompression = "zstd"

	timeFormat = time.RFC3339Nano

	maxSeconds = int64(10000 * 365.25 * 24 * 60 * 60)
	minSeconds = -maxSeconds
)

var (
	NodePublicKeyRegex = regexp.MustCompile("nodekey:[a-fA-F0-9]+")
	zeroIP4            = netip.AddrFrom4([4]byte{})
	zeroIP6            = netip.AddrFrom16([16]byte{})
)

func MachinePublicKeyStripPrefix(machineKey key.MachinePublic) string {
	return strings.TrimPrefix(machineKey.String(), machinePublicHexPrefix)
}

func NodePublicKeyStripPrefix(nodeKey key.NodePublic) string {
	return strings.TrimPrefix(nodeKey.String(), nodePublicHexPrefix)
}

func SessionPublicKeyStripPrefix(sessionKey key.SessionPublic) string {
	return strings.TrimPrefix(sessionKey.String(), sessionPublicHexPrefix)
}

func MachinePublicKeyEnsurePrefix(machineKey string) string {
	if !strings.HasPrefix(machineKey, machinePublicHexPrefix) {
		return machinePublicHexPrefix + machineKey
	}

	return machineKey
}

func NodePublicKeyEnsurePrefix(nodeKey string) string {
	if !strings.HasPrefix(nodeKey, nodePublicHexPrefix) {
		return nodePublicHexPrefix + nodeKey
	}

	return nodeKey
}

func SessionPublicKeyEnsurePrefix(sessionKey string) string {
	if !strings.HasPrefix(sessionKey, sessionPublicHexPrefix) {
		return sessionPublicHexPrefix + sessionKey
	}

	return sessionKey
}

func PrivateKeyEnsurePrefix(privateKey string) string {
	if !strings.HasPrefix(privateKey, privateHexPrefix) {
		return privateHexPrefix + privateKey
	}

	return privateKey
}

// Error is used to compare errors as per https://dave.cheney.net/2016/04/07/constant-errors
type Error string

func (e Error) Error() string { return string(e) }

func decode(
	msg []byte,
	output interface{},
	pubKey *key.MachinePublic,
	privKey *key.MachinePrivate,
) error {
	decrypted, ok := privKey.OpenFrom(*pubKey, msg)
	if !ok {
		return ErrCannotDecryptResponse
	}

	if err := json.Unmarshal(decrypted, output); err != nil {
		return err
	}

	return nil
}

func (np *Ninjapanda) getAvailableIPs() (MachineAddresses, error) {
	var ips MachineAddresses
	var err error
	ipPrefixes := np.cfg.IPPrefixes
	for _, ipPrefix := range ipPrefixes {
		var ip *netip.Addr
		ip, err = np.getAvailableIP(ipPrefix)
		if err != nil {
			return ips, err
		}
		ips = append(ips, *ip)
	}

	return ips, err
}

func GetIPPrefixEndpoints(na netip.Prefix) (netip.Addr, netip.Addr) {
	var network, broadcast netip.Addr
	ipRange := netipx.RangeOfPrefix(na)
	network = ipRange.From()
	broadcast = ipRange.To()

	return network, broadcast
}

func (np *Ninjapanda) getAvailableIP(ipPrefix netip.Prefix) (*netip.Addr, error) {
	usedIps, err := np.getUsedIPs()
	if err != nil {
		return nil, err
	}

	ipPrefixNetworkAddress, ipPrefixBroadcastAddress := GetIPPrefixEndpoints(ipPrefix)

	// Get the first IP in our prefix
	ip := ipPrefixNetworkAddress.Next()

	for {
		if !ipPrefix.Contains(ip) {
			return nil, ErrCouldNotAllocateIP
		}

		switch {
		case ip.Compare(ipPrefixBroadcastAddress) == 0:
			fallthrough
		case usedIps.Contains(ip):
			fallthrough
		case ip == netip.Addr{} || ip.IsLoopback():
			ip = ip.Next()

			continue

		default:
			return &ip, nil
		}
	}
}

func (np *Ninjapanda) getUsedIPs() (*netipx.IPSet, error) {
	// FIXME: This really deserves a better data model,
	// but this was quick to get running and it should be enough
	// to begin experimenting with a dual stack ztnet.
	var addressesSlices []string
	np.db.Model(&Machine{}).Pluck("ip_addresses", &addressesSlices)

	var ips netipx.IPSetBuilder
	for _, slice := range addressesSlices {
		var machineAddresses MachineAddresses
		err := machineAddresses.Scan(slice)
		if err != nil {
			return &netipx.IPSet{}, fmt.Errorf(
				"failed to read ip from database: %w",
				err,
			)
		}

		for _, ip := range machineAddresses {
			ips.Add(ip)
		}
	}

	ipSet, err := ips.IPSet()
	if err != nil {
		return &netipx.IPSet{}, fmt.Errorf(
			"failed to build IP Set: %w",
			err,
		)
	}

	return ipSet, nil
}

func GrpcSocketDialer(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer

	return d.DialContext(ctx, "unix", addr)
}

func stringToIPPrefix(prefixes []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, len(prefixes))

	for index, prefixStr := range prefixes {
		prefix, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			return []netip.Prefix{}, err
		}

		result[index] = prefix
	}

	return result, nil
}

func containsStr(ts []string, t string) bool {
	for _, v := range ts {
		if v == t {
			return true
		}
	}

	return false
}

func contains[T string | netip.Prefix](ts []T, t T) bool {
	for _, v := range ts {
		if reflect.DeepEqual(v, t) {
			return true
		}
	}

	return false
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)

	// Note that err == nil only if we read len(b) bytes.
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}

	return bytes, nil
}

// GenerateRandomStringURLSafe returns a URL-safe, base64 encoded
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomStringURLSafe(n int) (string, error) {
	b, err := GenerateRandomBytes(n)

	return base64.RawURLEncoding.EncodeToString(b), err
}

// GenerateRandomStringDNSSafe returns a DNS-safe
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomStringDNSSafe(size int) (string, error) {
	var str string
	var err error
	for len(str) < size {
		str, err = GenerateRandomStringURLSafe(size)
		if err != nil {
			return "", err
		}
		str = strings.ToLower(
			strings.ReplaceAll(strings.ReplaceAll(str, "_", ""), "-", ""),
		)
	}

	return str[:size], nil
}

func IsStringInSlice(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}

	return false
}

func AbsolutePathFromConfigPath(path string) string {
	// If a relative path is provided, prefix it with the directory where
	// the config file was found.
	if (path != "") && !strings.HasPrefix(path, string(os.PathSeparator)) {
		dir, _ := filepath.Split(viper.ConfigFileUsed())
		if dir != "" {
			path = filepath.Join(dir, path)
		}
	}

	return path
}

func GetFileMode(key string) fs.FileMode {
	modeStr := viper.GetString(key)

	mode, err := strconv.ParseInt(modeStr, Base8, BitSize64)
	if err == nil {
		if mode > 0 && mode <= math.MaxUint32 {
			return fs.FileMode(mode)
		}
	}

	return PermissionFallback
}

func FormatTime(t *time.Time) string {
	if t == nil {
		return ""
	}

	return t.Format(timeFormat)
}

func ParseTime(str string) *timestamppb.Timestamp {
	if len(str) > 0 {
		t, err := time.Parse(timeFormat, str)
		if err == nil {
			return timestamppb.New(t)
		}
	}

	return timestamppb.New(time.Time{})
}

func startEmitTimer() func(string) {
	startTime := time.Now()
	return func(status string) {
		machineMapRequests.With(
			prometheus.Labels{
				"status": status,
			},
		).Observe(time.Since(startTime).Seconds())
	}
}

func count[T any](slice []T, f func(T) bool) int {
	cnt := 0
	for _, s := range slice {
		if f(s) {
			cnt++
		}
	}
	return cnt
}

func Duration(dur *durationpb.Duration) (time.Duration, error) {
	if err := validateDuration(dur); err != nil {
		return 0, err
	}

	d := time.Duration(dur.Seconds) * time.Second

	if int64(d/time.Second) != dur.Seconds {
		return 0, fmt.Errorf("duration: %v is out of range for time.Duration", dur)
	}

	if dur.Nanos != 0 {
		d += time.Duration(dur.Nanos) * time.Nanosecond
		if (d < 0) != (dur.Nanos < 0) {
			return 0, fmt.Errorf("duration: %v is out of range for time.Duration", dur)
		}
	}

	return d, nil
}

func validateDuration(dur *durationpb.Duration) error {
	if dur == nil {
		return errors.New("duration: nil Duration")
	}
	if dur.Seconds < minSeconds || dur.Seconds > maxSeconds {
		return fmt.Errorf("duration: %v: seconds out of range", dur)
	}
	if dur.Nanos <= -1e9 || dur.Nanos >= 1e9 {
		return fmt.Errorf("duration: %v: nanos out of range", dur)
	}
	// Seconds and Nanos must have the same sign, unless d.Nanos is zero.
	if (dur.Seconds < 0 && dur.Nanos > 0) || (dur.Seconds > 0 && dur.Nanos < 0) {
		return fmt.Errorf("duration: %v: seconds and nanos have different signs", dur)
	}

	return nil
}

//
//   - an IP address (IPv4 or IPv6)
//   - the string "*" to match everything (both IPv4 & IPv6)
//   - a CIDR (e.g. "192.168.0.0/16")
//   - a range of two IPs, inclusive, separated by hyphen ("2eff::1-2eff::0800")
//
// bits, if non-nil, is the legacy SrcBits CIDR length to make a IP
// address (without a slash) treated as a CIDR of *bits length.
// nolint
func ParseIPSet(arg string, bits *int) (*netipx.IPSet, error) {
	var ipSet netipx.IPSetBuilder
	if arg == "*" {
		ipSet.AddPrefix(netip.PrefixFrom(zeroIP4, 0))
		ipSet.AddPrefix(netip.PrefixFrom(zeroIP6, 0))

		return ipSet.IPSet()
	}
	if strings.Contains(arg, "/") {
		pfx, err := netip.ParsePrefix(arg)
		if err != nil {
			return nil, err
		}
		if pfx != pfx.Masked() {
			return nil, fmt.Errorf("%v contains non-network bits set", pfx)
		}

		ipSet.AddPrefix(pfx)

		return ipSet.IPSet()
	}
	if strings.Count(arg, "-") == 1 {
		ip1s, ip2s, _ := strings.Cut(arg, "-")

		ip1, err := netip.ParseAddr(ip1s)
		if err != nil {
			return nil, err
		}

		ip2, err := netip.ParseAddr(ip2s)
		if err != nil {
			return nil, err
		}

		r := netipx.IPRangeFrom(ip1, ip2)
		if !r.IsValid() {
			return nil, fmt.Errorf("invalid IP range %q", arg)
		}

		for _, prefix := range r.Prefixes() {
			ipSet.AddPrefix(prefix)
		}

		return ipSet.IPSet()
	}
	ip, err := netip.ParseAddr(arg)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address %q", arg)
	}
	bits8 := uint8(ip.BitLen())
	if bits != nil {
		if *bits < 0 || *bits > int(bits8) {
			return nil, fmt.Errorf("invalid CIDR size %d for IP %q", *bits, arg)
		}
		bits8 = uint8(*bits)
	}

	ipSet.AddPrefix(netip.PrefixFrom(ip, int(bits8)))

	return ipSet.IPSet()
}
