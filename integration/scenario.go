package integration

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/puzpuzpuz/xsync/v2"

	"optm.com/ninja-panda/integration/dockertestutil"
	"optm.com/ninja-panda/integration/hsic"
	"optm.com/ninja-panda/integration/tsic"
	"optm.com/ninja-panda/src"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

const (
	scenarioHashLength = 6
	maxWait            = 60 * time.Second
)

var (
	errNoNinjapandaAvailable = errors.New("no ninjapanda available")
	errNoNamespaceAvailable  = errors.New("no namespace available")

	ClientVersions = []string{
		"head",
	}
)

type Namespace struct {
	Clients map[string]ZTClient

	createWaitGroup sync.WaitGroup
	joinWaitGroup   sync.WaitGroup
	syncWaitGroup   sync.WaitGroup
}

type Scenario struct {
	controlServers *xsync.MapOf[string, ControlServer]

	namespaces map[string]*Namespace

	pool    *dockertest.Pool
	network *dockertest.Network

	ninjapandaLock sync.Mutex
}

func NewScenario() (*Scenario, error) {
	hash, err := ninjapanda.GenerateRandomStringDNSSafe(scenarioHashLength)
	if err != nil {
		return nil, err
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		return nil, fmt.Errorf("could not connect to docker: %w", err)
	}

	pool.MaxWait = maxWait

	networkName := fmt.Sprintf("np-%s", hash)
	if overrideNetworkName := os.Getenv("NINJAPANDA_TEST_NETWORK_NAME"); overrideNetworkName != "" {
		networkName = overrideNetworkName
	}

	network, err := dockertestutil.GetFirstOrCreateNetwork(pool, networkName)
	if err != nil {
		return nil, fmt.Errorf("failed to create or get network: %w", err)
	}

	// We run the test suite in a docker container that calls a couple of endpoints for
	// readiness checks, this ensures that we can run the tests with individual networks
	// and have the client reach the different containers
	err = dockertestutil.AddContainerToNetwork(pool, network, "ninjapanda-test-suite")
	if err != nil {
		return nil, fmt.Errorf("failed to add test suite container to network: %w", err)
	}

	return &Scenario{
		controlServers: xsync.NewMapOf[ControlServer](),
		namespaces:     make(map[string]*Namespace),

		pool:    pool,
		network: network,
	}, nil
}

func (s *Scenario) Shutdown() error {
	s.controlServers.Range(func(_ string, control ControlServer) bool {
		err := control.Shutdown()
		if err != nil {
			log.Printf(
				"Failed to shut down control: %s",
				fmt.Errorf("failed to tear down control: %w", err),
			)
		}

		return true
	})

	for namespaceName, namespace := range s.namespaces {
		for _, client := range namespace.Clients {
			log.Printf(
				"removing client %s in namespace %s",
				client.Hostname(),
				namespaceName,
			)
			err := client.Shutdown()
			if err != nil {
				return fmt.Errorf("failed to tear down client: %w", err)
			}
		}
	}

	if err := s.pool.RemoveNetwork(s.network); err != nil {
		return fmt.Errorf("failed to remove network: %w", err)
	}

	return nil
}

func (s *Scenario) Namespaces() []string {
	namespaces := make([]string, 0)
	for namespace := range s.namespaces {
		namespaces = append(namespaces, namespace)
	}

	return namespaces
}

/// Ninjapanda related stuff
// Note: These functions assume that there is a _single_ ninjapanda instance for now

// TODO: make port and ninjapanda configurable, multiple instances support?
func (s *Scenario) Ninjapanda(opts ...hsic.Option) (ControlServer, error) {
	s.ninjapandaLock.Lock()
	defer s.ninjapandaLock.Unlock()

	if ninjapanda, ok := s.controlServers.Load("ninjapanda"); ok {
		return ninjapanda, nil
	}

	ninjapanda, err := hsic.New(s.pool, s.network, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create ninjapanda container: %w", err)
	}

	err = ninjapanda.WaitForReady()
	if err != nil {
		return nil, fmt.Errorf("failed reach ninjapanda container: %w", err)
	}

	s.controlServers.Store("ninjapanda", ninjapanda)

	return ninjapanda, nil
}

func (s *Scenario) CreatePreAuthKey(
	namespace string,
	reusable bool,
	ephemeral bool,
) (*v1.PreAuthKey, error) {
	if ninjapanda, err := s.Ninjapanda(); err == nil {
		key, err := ninjapanda.CreateAuthKey(namespace, reusable, ephemeral)
		if err != nil {
			return nil, fmt.Errorf("failed to create namespace: %w", err)
		}

		return key, nil
	}

	return nil, fmt.Errorf("failed to create namespace: %w", errNoNinjapandaAvailable)
}

func (s *Scenario) CreateNamespace(namespace string) error {
	if ninjapanda, err := s.Ninjapanda(); err == nil {
		err := ninjapanda.CreateNamespace(namespace)
		if err != nil {
			return fmt.Errorf("failed to create namespace: %w", err)
		}

		s.namespaces[namespace] = &Namespace{
			Clients: make(map[string]ZTClient),
		}

		return nil
	}

	return fmt.Errorf("failed to create namespace: %w", errNoNinjapandaAvailable)
}

/// Client related stuff

func (s *Scenario) CreateNodesInNamespace(
	namespaceStr string,
	requestedVersion string,
	count int,
	opts ...tsic.Option,
) error {
	if namespace, ok := s.namespaces[namespaceStr]; ok {
		for i := 0; i < count; i++ {
			version := requestedVersion
			if requestedVersion == "all" {
				version = ClientVersions[i%len(ClientVersions)]
			}

			ninjapanda, err := s.Ninjapanda()
			if err != nil {
				return fmt.Errorf("failed to create node: %w", err)
			}

			cert := ninjapanda.GetCert()
			hostname := ninjapanda.GetHostname()

			namespace.createWaitGroup.Add(1)

			opts = append(opts,
				tsic.WithNinjapandaTLS(cert),
				tsic.WithNinjapandaName(hostname),
			)

			go func() {
				defer namespace.createWaitGroup.Done()

				// TODO: error handle this
				ztClient, err := tsic.New(
					s.pool,
					version,
					s.network,
					opts...,
				)
				if err != nil {
					log.Printf("failed to create node: %s", err)
				}

				err = ztClient.WaitForReady()
				if err != nil {
					log.Printf("failed to wait for client: %s", err)
				}

				namespace.Clients[ztClient.Hostname()] = ztClient
			}()
		}
		namespace.createWaitGroup.Wait()

		return nil
	}

	return fmt.Errorf("failed to add node: %w", errNoNamespaceAvailable)
}

func (s *Scenario) RunZTClientUp(
	namespaceStr, loginServer, authKey string,
) error {
	if namespace, ok := s.namespaces[namespaceStr]; ok {
		for _, client := range namespace.Clients {
			namespace.joinWaitGroup.Add(1)

			go func(c ZTClient) {
				defer namespace.joinWaitGroup.Done()

				// TODO: error handle this
				_ = c.Up(loginServer, authKey)
			}(client)

			err := client.WaitForReady()
			if err != nil {
				log.Printf(
					"error waiting for client %s to be ready: %s",
					client.Hostname(),
					err,
				)
			}
		}

		namespace.joinWaitGroup.Wait()

		return nil
	}

	return fmt.Errorf("failed to up node: %w", errNoNamespaceAvailable)
}

func (s *Scenario) CountZTClient() int {
	count := 0

	for _, namespace := range s.namespaces {
		count += len(namespace.Clients)
	}

	return count
}

func (s *Scenario) WaitForClientSync() error {
	ztCount := s.CountZTClient()

	for _, namespace := range s.namespaces {
		for _, client := range namespace.Clients {
			namespace.syncWaitGroup.Add(1)

			go func(c ZTClient) {
				defer namespace.syncWaitGroup.Done()

				// TODO: error handle this
				_ = c.WaitForPeers(ztCount)
			}(client)
		}
		namespace.syncWaitGroup.Wait()
	}

	return nil
}

func (s *Scenario) CreateNinjapandaEnv(
	namespaces map[string]int,
	ztOpts []tsic.Option,
	opts ...hsic.Option,
) error {
	ninjapanda, err := s.Ninjapanda(opts...)
	if err != nil {
		return err
	}

	for namespaceName, clientCount := range namespaces {
		err = s.CreateNamespace(namespaceName)
		if err != nil {
			return err
		}

		err = s.CreateNodesInNamespace(
			namespaceName,
			"all",
			clientCount,
			ztOpts...)
		if err != nil {
			return err
		}

		key, err := s.CreatePreAuthKey(namespaceName, true, false)
		if err != nil {
			return err
		}

		err = s.RunZTClientUp(namespaceName, ninjapanda.GetEndpoint(), key.GetKey())
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Scenario) GetIPs(namespace string) ([]netip.Addr, error) {
	var ips []netip.Addr
	if ns, ok := s.namespaces[namespace]; ok {
		for _, client := range ns.Clients {
			clientIps, err := client.IPs()
			if err != nil {
				return ips, fmt.Errorf("failed to get ips: %w", err)
			}
			ips = append(ips, clientIps...)
		}

		return ips, nil
	}

	return ips, fmt.Errorf("failed to get ips: %w", errNoNamespaceAvailable)
}

func (s *Scenario) GetClients(namespace string) ([]ZTClient, error) {
	var clients []ZTClient
	if ns, ok := s.namespaces[namespace]; ok {
		for _, client := range ns.Clients {
			clients = append(clients, client)
		}

		return clients, nil
	}

	return clients, fmt.Errorf("failed to get clients: %w", errNoNamespaceAvailable)
}

func (s *Scenario) ListZTClients(
	namespaces ...string,
) ([]ZTClient, error) {
	var allClients []ZTClient

	if len(namespaces) == 0 {
		namespaces = s.Namespaces()
	}

	for _, namespace := range namespaces {
		clients, err := s.GetClients(namespace)
		if err != nil {
			return nil, err
		}

		allClients = append(allClients, clients...)
	}

	return allClients, nil
}

func (s *Scenario) ListZTClientsIPs(namespaces ...string) ([]netip.Addr, error) {
	var allIps []netip.Addr

	if len(namespaces) == 0 {
		namespaces = s.Namespaces()
	}

	for _, namespace := range namespaces {
		ips, err := s.GetIPs(namespace)
		if err != nil {
			return nil, err
		}

		allIps = append(allIps, ips...)
	}

	return allIps, nil
}

func (s *Scenario) ListZTClientsFQDNs(namespaces ...string) ([]string, error) {
	allFQDNs := make([]string, 0)

	clients, err := s.ListZTClients(namespaces...)
	if err != nil {
		return nil, err
	}

	for _, client := range clients {
		fqdn, err := client.FQDN()
		if err != nil {
			return nil, err
		}

		allFQDNs = append(allFQDNs, fqdn)
	}

	return allFQDNs, nil
}

func (s *Scenario) WaitForZTClientLogout() {
	for _, namespace := range s.namespaces {
		for _, client := range namespace.Clients {
			namespace.syncWaitGroup.Add(1)

			go func(c ZTClient) {
				defer namespace.syncWaitGroup.Done()

				// TODO: error handle this
				_ = c.WaitForLogout()
			}(client)
		}
		namespace.syncWaitGroup.Wait()
	}
}
