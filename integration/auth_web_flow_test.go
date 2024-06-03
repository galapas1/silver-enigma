package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"optm.com/ninja-panda/integration/hsic"
)

var errParseAuthPage = errors.New("failed to parse auth page")

type AuthWebFlowScenario struct {
	*Scenario
}

func TestAuthWebFlowAuthenticationPingAll(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	baseScenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	scenario := AuthWebFlowScenario{
		Scenario: baseScenario,
	}

	spec := map[string]int{
		"namespace1": len(ClientVersions),
		"namespace2": len(ClientVersions),
	}

	err = scenario.CreateNinjapandaEnv(spec, hsic.WithTestName("webauthping"))
	if err != nil {
		t.Errorf("failed to create ninjapanda environment: %s", err)
	}

	allClients, err := scenario.ListZTClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allIps, err := scenario.ListZTClientsIPs()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForClientSync()
	if err != nil {
		t.Errorf("failed wait for client clients to be in sync: %s", err)
	}

	success := 0
	for _, client := range allClients {
		for _, ip := range allIps {
			err := client.Ping(ip.String())
			if err != nil {
				t.Errorf("failed to ping %s from %s: %s", ip, client.Hostname(), err)
			} else {
				success++
			}
		}
	}

	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestAuthWebFlowLogoutAndRelogin(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	baseScenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	scenario := AuthWebFlowScenario{
		Scenario: baseScenario,
	}

	spec := map[string]int{
		"namespace1": len(ClientVersions),
		"namespace2": len(ClientVersions),
	}

	err = scenario.CreateNinjapandaEnv(spec, hsic.WithTestName("weblogout"))
	if err != nil {
		t.Errorf("failed to create ninjapanda environment: %s", err)
	}

	allClients, err := scenario.ListZTClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allIps, err := scenario.ListZTClientsIPs()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForClientSync()
	if err != nil {
		t.Errorf("failed wait for client clients to be in sync: %s", err)
	}

	success := 0
	for _, client := range allClients {
		for _, ip := range allIps {
			err := client.Ping(ip.String())
			if err != nil {
				t.Errorf("failed to ping %s from %s: %s", ip, client.Hostname(), err)
			} else {
				success++
			}
		}
	}

	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	clientIPs := make(map[ZTClient][]netip.Addr)
	for _, client := range allClients {
		ips, err := client.IPs()
		if err != nil {
			t.Errorf("failed to get IPs for client %s: %s", client.Hostname(), err)
		}
		clientIPs[client] = ips
	}

	for _, client := range allClients {
		err := client.Logout()
		if err != nil {
			t.Errorf("failed to logout client %s: %s", client.Hostname(), err)
		}
	}

	scenario.WaitForZTClientLogout()

	t.Logf("all clients logged out")

	ninjapanda, err := scenario.Ninjapanda()
	if err != nil {
		t.Errorf("failed to get ninjapanda server: %s", err)
	}

	for namespaceName := range spec {
		err = scenario.runClientUp(namespaceName, ninjapanda.GetEndpoint())
		if err != nil {
			t.Errorf("failed to run client up: %s", err)
		}
	}

	t.Logf("all clients logged in again")

	allClients, err = scenario.ListZTClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allIps, err = scenario.ListZTClientsIPs()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	success = 0
	for _, client := range allClients {
		for _, ip := range allIps {
			err := client.Ping(ip.String())
			if err != nil {
				t.Errorf("failed to ping %s from %s: %s", ip, client.Hostname(), err)
			} else {
				success++
			}
		}
	}

	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	for _, client := range allClients {
		ips, err := client.IPs()
		if err != nil {
			t.Errorf("failed to get IPs for client %s: %s", client.Hostname(), err)
		}

		// lets check if the IPs are the same
		if len(ips) != len(clientIPs[client]) {
			t.Errorf("IPs changed for client %s", client.Hostname())
		}

		for _, ip := range ips {
			found := false
			for _, oldIP := range clientIPs[client] {
				if ip == oldIP {
					found = true

					break
				}
			}

			if !found {
				t.Errorf(
					"IPs changed for client %s. Used to be %v now %v",
					client.Hostname(),
					clientIPs[client],
					ips,
				)
			}
		}
	}

	t.Logf("all clients IPs are the same")

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func (s *AuthWebFlowScenario) CreateNinjapandaEnv(
	namespaces map[string]int,
	opts ...hsic.Option,
) error {
	ninjapanda, err := s.Ninjapanda(opts...)
	if err != nil {
		return err
	}

	err = ninjapanda.WaitForReady()
	if err != nil {
		return err
	}

	for namespaceName, clientCount := range namespaces {
		log.Printf("creating namespace %s with %d clients", namespaceName, clientCount)
		err = s.CreateNamespace(namespaceName)
		if err != nil {
			return err
		}

		err = s.CreateNodesInNamespace(namespaceName, "all", clientCount)
		if err != nil {
			return err
		}

		err = s.runClientUp(namespaceName, ninjapanda.GetEndpoint())
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *AuthWebFlowScenario) runClientUp(
	namespaceStr, loginServer string,
) error {
	log.Printf("running client up for namespace %s", namespaceStr)
	if namespace, ok := s.namespaces[namespaceStr]; ok {
		for _, client := range namespace.Clients {
			namespace.joinWaitGroup.Add(1)

			go func(c ZTClient) {
				defer namespace.joinWaitGroup.Done()

				// TODO: error handle this
				loginURL, err := c.UpWithLoginURL(loginServer)
				if err != nil {
					log.Printf("failed to run client up: %s", err)
				}

				err = s.runNinjapandaRegister(namespaceStr, loginURL)
				if err != nil {
					log.Printf("failed to register client: %s", err)
				}
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

	return fmt.Errorf("failed to up client node: %w", errNoNamespaceAvailable)
}

func (s *AuthWebFlowScenario) runNinjapandaRegister(
	namespaceStr string,
	loginURL *url.URL,
) error {
	ninjapanda, err := s.Ninjapanda()
	if err != nil {
		return err
	}

	log.Printf("loginURL: %s", loginURL)
	loginURL.Host = fmt.Sprintf("%s:8080", ninjapanda.GetIP())
	loginURL.Scheme = "http"

	httpClient := &http.Client{}
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, loginURL.String(), nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// see api.go HTML template
	codeSep := strings.Split(string(body), "</code>")
	if len(codeSep) != 2 {
		return errParseAuthPage
	}

	keySep := strings.Split(codeSep[0], "key ")
	if len(keySep) != 2 {
		return errParseAuthPage
	}
	key := keySep[1]
	log.Printf("registering node %s", key)

	if ninjapanda, err := s.Ninjapanda(); err == nil {
		_, err = ninjapanda.Execute(
			[]string{
				"ninjapanda",
				"-n",
				namespaceStr,
				"nodes",
				"register",
				"--key",
				key,
			},
		)
		if err != nil {
			log.Printf("failed to register node: %s", err)

			return err
		}

		return nil
	}

	return fmt.Errorf("failed to find ninjapanda: %w", errNoNinjapandaAvailable)
}
