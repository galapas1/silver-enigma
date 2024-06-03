package integration

import (
	"net/netip"
	"net/url"

	"github.com/Optm-Main/ztmesh-core/ztn/ztnstate"
)

// nolint
type ZTClient interface {
	Hostname() string
	Shutdown() error
	Version() string
	Execute(command []string) (string, string, error)
	Up(loginServer, authKey string) error
	UpWithLoginURL(loginServer string) (*url.URL, error)
	Logout() error
	IPs() ([]netip.Addr, error)
	FQDN() (string, error)
	Status() (*ztnstate.Status, error)
	WaitForReady() error
	WaitForLogout() error
	WaitForPeers(expected int) error
	Ping(hostnameOrIP string) error
	ID() string
}
