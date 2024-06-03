package tsic

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"net/url"
	"strings"

	"github.com/Optm-Main/ztmesh-core/ztn/ztnstate"
	"github.com/cenkalti/backoff/v4"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"

	"optm.com/ninja-panda/integration/dockertestutil"
	"optm.com/ninja-panda/integration/integrationutil"
	ninjapanda "optm.com/ninja-panda/src"
)

const (
	tsicHashLength     = 6
	dockerContextPath  = "../."
	ninjapandaCertPath = "/usr/local/share/ca-certificates/ninjapanda.crt"
)

var (
	errClientPingFailed             = errors.New("ping failed")
	errClientNotLoggedIn            = errors.New("client not logged in")
	errClientWrongPeerCount         = errors.New("wrong peer count")
	errClientCannotUpWithoutAuthkey = errors.New("cannot up without authkey")
	errClientNotConnected           = errors.New("client not connected")
	errClientNotLoggedOut           = errors.New("client not logged out")
)

type ZTClientInContainer struct {
	version  string
	hostname string

	pool      *dockertest.Pool
	container *dockertest.Resource
	network   *dockertest.Network

	// "cache"
	ips  []netip.Addr
	fqdn string

	// optional config
	ninjapandaCert     []byte
	ninjapandaHostname string
	withSSH            bool
}

type Option = func(c *ZTClientInContainer)

func WithNinjapandaTLS(cert []byte) Option {
	return func(tsic *ZTClientInContainer) {
		tsic.ninjapandaCert = cert
	}
}

func WithOrCreateNetwork(network *dockertest.Network) Option {
	return func(tsic *ZTClientInContainer) {
		if network != nil {
			tsic.network = network

			return
		}

		network, err := dockertestutil.GetFirstOrCreateNetwork(
			tsic.pool,
			fmt.Sprintf("%s-network", tsic.hostname),
		)
		if err != nil {
			log.Fatalf("failed to create network: %s", err)
		}

		tsic.network = network
	}
}

func WithNinjapandaName(hsName string) Option {
	return func(tsic *ZTClientInContainer) {
		tsic.ninjapandaHostname = hsName
	}
}

func WithSSH() Option {
	return func(tsic *ZTClientInContainer) {
		tsic.withSSH = true
	}
}

func New(
	pool *dockertest.Pool,
	version string,
	network *dockertest.Network,
	opts ...Option,
) (*ZTClientInContainer, error) {
	hash, err := ninjapanda.GenerateRandomStringDNSSafe(tsicHashLength)
	if err != nil {
		return nil, err
	}

	hostname := fmt.Sprintf("ts-%s-%s", strings.ReplaceAll(version, ".", "-"), hash)

	tsic := &ZTClientInContainer{
		version:  version,
		hostname: hostname,

		pool:    pool,
		network: network,
	}

	for _, opt := range opts {
		opt(tsic)
	}

	clientOptions := &dockertest.RunOptions{
		Name:     hostname,
		Networks: []*dockertest.Network{network},
		// Cmd: []string{
		// 	"clientd", "--tun=tsdev",
		// },
		Entrypoint: []string{
			"/bin/bash",
			"-c",
			"/bin/sleep 3 ; update-ca-certificates ; clientd --tun=tsdev",
		},
	}

	if tsic.ninjapandaHostname != "" {
		clientOptions.ExtraHosts = []string{
			"host.docker.internal:host-gateway",
			fmt.Sprintf("%s:host-gateway", tsic.ninjapandaHostname),
		}
	}

	// dockertest isnt very good at handling containers that has already
	// been created, this is an attempt to make sure this container isnt
	// present.
	err = pool.RemoveContainerByName(hostname)
	if err != nil {
		return nil, err
	}

	container, err := pool.BuildAndRunWithBuildOptions(
		createClientBuildOptions(version),
		clientOptions,
		dockertestutil.DockerRestartPolicy,
		dockertestutil.DockerAllowLocalIPv6,
		dockertestutil.DockerAllowNetworkAdministration,
	)
	if err != nil {
		return nil, fmt.Errorf("could not start client container: %w", err)
	}
	log.Printf("Created %s container\n", hostname)

	tsic.container = container

	if tsic.hasTLS() {
		err = tsic.WriteFile(ninjapandaCertPath, tsic.ninjapandaCert)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to write TLS certificate to container: %w",
				err,
			)
		}
	}

	return tsic, nil
}

func (t *ZTClientInContainer) hasTLS() bool {
	return len(t.ninjapandaCert) != 0
}

func (t *ZTClientInContainer) Shutdown() error {
	return t.pool.Purge(t.container)
}

func (t *ZTClientInContainer) Hostname() string {
	return t.hostname
}

func (t *ZTClientInContainer) Version() string {
	return t.version
}

func (t *ZTClientInContainer) ID() string {
	return t.container.Container.ID
}

func (t *ZTClientInContainer) Execute(
	command []string,
) (string, string, error) {
	stdout, stderr, err := dockertestutil.ExecuteCommand(
		t.container,
		command,
		[]string{},
	)
	if err != nil {
		log.Printf("command stderr: %s\n", stderr)

		if stdout != "" {
			log.Printf("command stdout: %s\n", stdout)
		}

		if strings.Contains(stderr, "NeedsLogin") {
			return stdout, stderr, errClientNotLoggedIn
		}

		return stdout, stderr, err
	}

	return stdout, stderr, nil
}

func (t *ZTClientInContainer) Up(
	loginServer, authKey string,
) error {
	command := []string{
		"client",
		"up",
		"-login-server",
		loginServer,
		"--authkey",
		authKey,
		"--hostname",
		t.hostname,
	}

	if t.withSSH {
		command = append(command, "--ssh")
	}

	if _, _, err := t.Execute(command); err != nil {
		return fmt.Errorf("failed to join client client: %w", err)
	}

	return nil
}

func (t *ZTClientInContainer) UpWithLoginURL(
	loginServer string,
) (*url.URL, error) {
	command := []string{
		"client",
		"up",
		"-login-server",
		loginServer,
		"--hostname",
		t.hostname,
	}

	_, stderr, err := t.Execute(command)
	if errors.Is(err, errClientNotLoggedIn) {
		return nil, errClientCannotUpWithoutAuthkey
	}

	urlStr := strings.ReplaceAll(stderr, "\nTo authenticate, visit:\n\n\t", "")
	urlStr = strings.TrimSpace(urlStr)

	// parse URL
	loginURL, err := url.Parse(urlStr)
	if err != nil {
		log.Printf("Could not parse login URL: %s", err)
		log.Printf("Original join command result: %s", stderr)

		return nil, err
	}

	return loginURL, nil
}

func (t *ZTClientInContainer) Logout() error {
	_, _, err := t.Execute([]string{"client", "logout"})
	if err != nil {
		return err
	}

	return nil
}

func (t *ZTClientInContainer) IPs() ([]netip.Addr, error) {
	if t.ips != nil && len(t.ips) != 0 {
		return t.ips, nil
	}

	ips := make([]netip.Addr, 0)

	command := []string{
		"client",
		"ip",
	}

	result, _, err := t.Execute(command)
	if err != nil {
		return []netip.Addr{}, fmt.Errorf("failed to join client client: %w", err)
	}

	for _, address := range strings.Split(result, "\n") {
		address = strings.TrimSuffix(address, "\n")
		if len(address) < 1 {
			continue
		}
		ip, err := netip.ParseAddr(address)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

func (t *ZTClientInContainer) Status() (*ztnstate.Status, error) {
	command := []string{
		"ztclient",
		"status",
		"--json",
	}

	result, _, err := t.Execute(command)
	if err != nil {
		return nil, fmt.Errorf("failed to execute client status command: %w", err)
	}

	var status ztnstate.Status
	err = json.Unmarshal([]byte(result), &status)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal client status: %w", err)
	}

	return &status, err
}

func (t *ZTClientInContainer) FQDN() (string, error) {
	if t.fqdn != "" {
		return t.fqdn, nil
	}

	status, err := t.Status()
	if err != nil {
		return "", fmt.Errorf("failed to get FQDN: %w", err)
	}

	return status.Self.DNSName, nil
}

func (t *ZTClientInContainer) WaitForReady() error {
	return t.pool.Retry(func() error {
		status, err := t.Status()
		if err != nil {
			return fmt.Errorf("failed to fetch ztclient status: %w", err)
		}

		if status.CurrentZTnet != nil {
			return nil
		}

		return errClientNotConnected
	})
}

func (t *ZTClientInContainer) WaitForLogout() error {
	return t.pool.Retry(func() error {
		status, err := t.Status()
		if err != nil {
			return fmt.Errorf("failed to fetch ztclient status: %w", err)
		}

		if status.CurrentZTnet == nil {
			return nil
		}

		return errClientNotLoggedOut
	})
}

func (t *ZTClientInContainer) WaitForPeers(expected int) error {
	return t.pool.Retry(func() error {
		status, err := t.Status()
		if err != nil {
			return fmt.Errorf("failed to fetch client status: %w", err)
		}

		if peers := status.Peers(); len(peers) != expected {
			return errClientWrongPeerCount
		}

		return nil
	})
}

// TODO(kradalby): Make multiping, go routine magic.
func (t *ZTClientInContainer) Ping(hostnameOrIP string) error {
	return t.pool.Retry(func() error {
		command := []string{
			"client", "ping",
			"--timeout=1s",
			"--c=10",
			"--until-direct=true",
			hostnameOrIP,
		}

		result, _, err := t.Execute(command)
		if err != nil {
			log.Printf(
				"failed to run ping command from %s to %s, err: %s",
				t.Hostname(),
				hostnameOrIP,
				err,
			)

			return err
		}

		if !strings.Contains(result, "pong") && !strings.Contains(result, "is local") {
			return backoff.Permanent(errClientPingFailed)
		}

		return nil
	})
}

func (t *ZTClientInContainer) WriteFile(path string, data []byte) error {
	return integrationutil.WriteFileToContainer(t.pool, t.container, path, data)
}

func createClientBuildOptions(version string) *dockertest.BuildOptions {
	var clientBuildOptions *dockertest.BuildOptions
	switch version {
	case "head":
		clientBuildOptions = &dockertest.BuildOptions{
			Dockerfile: "Dockerfile.client-HEAD",
			ContextDir: dockerContextPath,
			BuildArgs:  []docker.BuildArg{},
		}
	case "unstable":
		clientBuildOptions = &dockertest.BuildOptions{
			Dockerfile: "Dockerfile.client",
			ContextDir: dockerContextPath,
			BuildArgs: []docker.BuildArg{
				{
					Name:  "NINJAPANDA_VERSION",
					Value: "*", // Installs the latest version https://askubuntu.com/a/824926
				},
				{
					Name:  "NINJAPANDA_CHANNEL",
					Value: "unstable",
				},
			},
		}
	default:
		clientBuildOptions = &dockertest.BuildOptions{
			Dockerfile: "Dockerfile.client",
			ContextDir: dockerContextPath,
			BuildArgs: []docker.BuildArg{
				{
					Name:  "NINJAPANDA_VERSION",
					Value: version,
				},
				{
					Name:  "NINJAPANDA_CHANNEL",
					Value: "stable",
				},
			},
		}
	}

	return clientBuildOptions
}
