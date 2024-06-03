// nolint
package ninjapanda

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ccding/go-stun/stun"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

const (
	ninjapandaRelayHostname = "ninjapanda-relay"
	namespaceName           = "relaynamespace"
	totalContainers         = 3
)

type IntegrationRELAYTestSuite struct {
	suite.Suite
	stats *suite.SuiteInformation

	pool              dockertest.Pool
	network           dockertest.Network
	containerNetworks map[int]dockertest.Network // so we keep the containers isolated
	ninjapanda        dockertest.Resource
	saveLogs          bool
	relays            map[string]dockertest.Resource
	joinWaitGroup     sync.WaitGroup
}

func TestIntegrationRELAYTestSuite(t *testing.T) {
	t.Skip("This fails on GitHub CI/CD, disabling for now")
	if testing.Short() {
		t.Skip("skipping integration tests due to short flag")
	}

	saveLogs, err := GetEnvBool("NINJAPANDA_INTEGRATION_SAVE_LOG")
	if err != nil {
		saveLogs = false
	}

	s := new(IntegrationRELAYTestSuite)

	s.relays = make(map[string]dockertest.Resource)
	s.containerNetworks = make(map[int]dockertest.Network)
	s.saveLogs = saveLogs

	suite.Run(t, s)

	// HandleStats, which allows us to check if we passed and save logs
	// is called after TearDown, so we cannot tear down containers before
	// we have potentially saved the logs.
	if s.saveLogs {
		for _, relay := range s.relays {
			if err := s.pool.Purge(&relay); err != nil {
				log.Printf("Could not purge resource: %s\n", err)
			}
		}

		if !s.stats.Passed() {
			err := s.saveLog(&s.ninjapanda, "test_output")
			if err != nil {
				log.Printf("Could not save log: %s\n", err)
			}
		}
		if err := s.pool.Purge(&s.ninjapanda); err != nil {
			log.Printf("Could not purge resource: %s\n", err)
		}

		for _, network := range s.containerNetworks {
			if err := network.Close(); err != nil {
				log.Printf("Could not close network: %s\n", err)
			}
		}
	}
}

func (s *IntegrationRELAYTestSuite) SetupSuite() {
	if ppool, err := dockertest.NewPool(""); err == nil {
		s.pool = *ppool
	} else {
		s.FailNow(fmt.Sprintf("Could not connect to docker: %s", err), "")
	}

	network, err := GetFirstOrCreateNetwork(&s.pool, ninjapandaNetwork)
	if err != nil {
		s.FailNow(fmt.Sprintf("Failed to create or get network: %s", err), "")
	}
	s.network = network

	for i := 0; i < totalContainers; i++ {
		if pnetwork, err := s.pool.CreateNetwork(fmt.Sprintf("ninjapanda-relay-%d", i)); err == nil {
			s.containerNetworks[i] = *pnetwork
		} else {
			s.FailNow(fmt.Sprintf("Could not create network: %s", err), "")
		}
	}

	ninjapandaBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile",
		ContextDir: "..",
	}

	currentPath, err := os.Getwd()
	if err != nil {
		s.FailNow(fmt.Sprintf("Could not determine current path: %s", err), "")
	}

	ninjapandaOptions := &dockertest.RunOptions{
		Name: ninjapandaRelayHostname,
		Mounts: []string{
			fmt.Sprintf(
				"%s/integration_test/etc_embedded_relay:/etc/ninjapanda",
				currentPath,
			),
		},
		Cmd:          []string{"ninjapanda", "serve"},
		Networks:     []*dockertest.Network{&s.network},
		ExposedPorts: []string{"8443/tcp", "3478/udp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"8443/tcp": {{HostPort: "8443"}},
			"3478/udp": {{HostPort: "3478"}},
		},
	}

	err = s.pool.RemoveContainerByName(ninjapandaRelayHostname)
	if err != nil {
		s.FailNow(
			fmt.Sprintf(
				"Could not remove existing container before building test: %s",
				err,
			),
			"",
		)
	}

	log.Println("Creating ninjapanda container for RELAY integration tests")
	if pninjapanda, err := s.pool.BuildAndRunWithBuildOptions(ninjapandaBuildOptions, ninjapandaOptions, DockerRestartPolicy); err == nil {
		s.ninjapanda = *pninjapanda
	} else {
		s.FailNow(fmt.Sprintf("Could not start ninjapanda container: %s", err), "")
	}
	log.Println("Created ninjapanda container for embedded RELAY tests")

	log.Println("Creating relay containers for embedded RELAY tests")

	for i := 0; i < totalContainers; i++ {
		version := clientVersions[i%len(clientVersions)]
		hostname, container := s.relayContainer(
			fmt.Sprint(i),
			version,
			s.containerNetworks[i],
		)
		s.relays[hostname] = *container
	}

	log.Println("Waiting for ninjapanda to be ready for embedded RELAY tests")
	hostEndpoint := fmt.Sprintf("%s:%s",
		// TBD: Need to deep-dive into this and see why the local networks are not routable.
		"localhost", // s.ninjapanda.GetIPInNetwork(&s.network),
		s.ninjapanda.GetPort("8443/tcp"))

	if err := s.pool.Retry(func() error {
		url := fmt.Sprintf("https://%s/health", hostEndpoint)
		insecureTransport := http.DefaultTransport.(*http.Transport).Clone()
		insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client := &http.Client{Transport: insecureTransport}
		resp, err := client.Get(url)
		if err != nil {
			fmt.Printf("ninjapanda for embedded RELAY tests is not ready: %s\n", err)
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status code not OK")
		}

		return nil
	}); err != nil {
		// TODO: If we cannot access ninjapanda, or any other fatal error during
		// test setup, we need to abort and tear down. However, testify does not seem to
		// support that at the moment:
		// https://github.com/stretchr/testify/issues/849
		return // fmt.Errorf("Could not connect to ninjapanda: %s", err)
	}
	log.Println("ninjapanda container is ready for embedded RELAY tests")

	log.Printf("Creating ninjapanda namespace: %s\n", namespaceName)
	result, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{"ninjapanda", "namespaces", "create", namespaceName},
		[]string{},
	)
	log.Println("ninjapanda create namespace result: ", result)
	assert.Nil(s.T(), err)

	log.Printf("Creating pre auth key for %s\n", namespaceName)
	preAuthResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"--namespace",
			namespaceName,
			"preauthkeys",
			"create",
			"--reuseCount=0",
			"--expiration",
			"24h",
			"--output",
			"json",
		},
		[]string{"LOG_LEVEL=error"},
	)
	assert.Nil(s.T(), err)

	var preAuthKey v1.PreAuthKey
	err = json.Unmarshal([]byte(preAuthResult), &preAuthKey)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), preAuthKey.ReuseCount, 0)

	ninjapandaEndpoint := fmt.Sprintf(
		"https://ninjapanda:%s",
		s.ninjapanda.GetPort("8443/tcp"),
	)

	log.Printf(
		"Joining relay containers to ninjapanda at %s\n",
		ninjapandaEndpoint,
	)
	for hostname, relay := range s.relays {
		s.joinWaitGroup.Add(1)
		go s.Join(ninjapandaEndpoint, *preAuthKey.Key, hostname, relay)
	}

	s.joinWaitGroup.Wait()

	// The nodes need a bit of time to get their updated maps from ninjapanda
	// TODO: See if we can have a more deterministic wait here.
	time.Sleep(60 * time.Second)
}

func (s *IntegrationRELAYTestSuite) Join(
	endpoint, key, hostname string,
	relay dockertest.Resource,
) {
	defer s.joinWaitGroup.Done()

	command := []string{
		"relay",
		"up",
		"-login-server",
		endpoint,
		"--authkey",
		key,
		"--hostname",
		hostname,
	}

	log.Println("Join command:", command)
	log.Printf("Running join command for %s\n", hostname)
	_, _, err := ExecuteCommand(
		&relay,
		command,
		[]string{},
	)
	assert.Nil(s.T(), err)
	log.Printf("%s joined\n", hostname)
}

func (s *IntegrationRELAYTestSuite) relayContainer(
	identifier, version string,
	network dockertest.Network,
) (string, *dockertest.Resource) {
	relayBuildOptions := getDockerBuildOptions(version)

	hostname := fmt.Sprintf(
		"relay-%s-%s",
		strings.Replace(version, ".", "-", -1),
		identifier,
	)
	relayOptions := &dockertest.RunOptions{
		Name:     hostname,
		Networks: []*dockertest.Network{&network},
		Cmd: []string{
			"relayd", "--tun=tsdev",
		},

		// expose the host IP address, so we can access it from inside the container
		ExtraHosts: []string{
			"host.docker.internal:host-gateway",
			"ninjapanda:host-gateway",
		},
	}

	pts, err := s.pool.BuildAndRunWithBuildOptions(
		relayBuildOptions,
		relayOptions,
		DockerRestartPolicy,
		DockerAllowLocalIPv6,
		DockerAllowNetworkAdministration,
	)
	if err != nil {
		log.Fatalf("Could not start relay container version %s: %s", version, err)
	}
	log.Printf("Created %s container\n", hostname)

	return hostname, pts
}

func (s *IntegrationRELAYTestSuite) TearDownSuite() {
	if !s.saveLogs {
		for _, relay := range s.relays {
			if err := s.pool.Purge(&relay); err != nil {
				log.Printf("Could not purge resource: %s\n", err)
			}
		}

		if err := s.pool.Purge(&s.ninjapanda); err != nil {
			log.Printf("Could not purge resource: %s\n", err)
		}

		for _, network := range s.containerNetworks {
			if err := network.Close(); err != nil {
				log.Printf("Could not close network: %s\n", err)
			}
		}
	}
}

func (s *IntegrationRELAYTestSuite) HandleStats(
	suiteName string,
	stats *suite.SuiteInformation,
) {
	s.stats = stats
}

func (s *IntegrationRELAYTestSuite) saveLog(
	resource *dockertest.Resource,
	basePath string,
) error {
	err := os.MkdirAll(basePath, os.ModePerm)
	if err != nil {
		return err
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err = s.pool.Client.Logs(
		docker.LogsOptions{
			Context:      context.TODO(),
			Container:    resource.Container.ID,
			OutputStream: &stdout,
			ErrorStream:  &stderr,
			Tail:         "all",
			RawTerminal:  false,
			Stdout:       true,
			Stderr:       true,
			Follow:       false,
			Timestamps:   false,
		},
	)
	if err != nil {
		return err
	}

	log.Printf("Saving logs for %s to %s\n", resource.Container.Name, basePath)

	err = os.WriteFile(
		path.Join(basePath, resource.Container.Name+".stdout.log"),
		[]byte(stdout.String()),
		0o644,
	)
	if err != nil {
		return err
	}

	err = os.WriteFile(
		path.Join(basePath, resource.Container.Name+".stderr.log"),
		[]byte(stdout.String()),
		0o644,
	)
	if err != nil {
		return err
	}

	return nil
}

// TBD: Investigate this test.
func (s *IntegrationRELAYTestSuite) tbdTestPingAllPeersByHostname() {
	hostnames, err := getDNSNames(&s.ninjapanda)
	assert.Nil(s.T(), err)

	log.Printf("Hostnames: %#v\n", hostnames)

	for hostname, relay := range s.relays {
		for _, peername := range hostnames {
			if strings.Contains(peername, hostname) {
				continue
			}
			s.T().Run(fmt.Sprintf("%s-%s", hostname, peername), func(t *testing.T) {
				command := []string{
					"relay", "ping",
					"--timeout=10s",
					"--c=5",
					"--until-direct=false",
					peername,
				}

				log.Printf(
					"Pinging using hostname from %s to %s\n",
					hostname,
					peername,
				)
				log.Println(command)
				result, _, err := ExecuteCommand(
					&relay,
					command,
					[]string{},
				)
				assert.Nil(t, err)
				log.Printf("Result for %s: %s\n", hostname, result)
				assert.Contains(t, result, "via RELAY(ninjapanda)")
			})
		}
	}
}

func (s *IntegrationRELAYTestSuite) TestRELAYSTUN() {
	ninjapandaSTUNAddr := fmt.Sprintf("%s:%s",
		// TBD: Need to deep-dive into this and see why the local networks are not routable.
		"localhost", // s.ninjapanda.GetIPInNetwork(&s.network),
		s.ninjapanda.GetPort("3478/udp"))
	client := stun.NewClient()
	client.SetVerbose(true)
	client.SetVVerbose(true)
	client.SetServerAddr(ninjapandaSTUNAddr)
	_, _, err := client.Discover()
	assert.Nil(s.T(), err)
}
