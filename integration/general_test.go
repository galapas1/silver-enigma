package integration

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog/log"

	"optm.com/ninja-panda/integration/hsic"
	"optm.com/ninja-panda/integration/tsic"
)

func TestPingAllByIP(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"namespace1": len(ClientVersions),
		"namespace2": len(ClientVersions),
	}

	err = scenario.CreateNinjapandaEnv(
		spec,
		[]tsic.Option{},
		hsic.WithTestName("pingallbyip"),
	)
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

func TestAuthKeyLogoutAndRelogin(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"namespace1": len(ClientVersions),
		"namespace2": len(ClientVersions),
	}

	err = scenario.CreateNinjapandaEnv(
		spec,
		[]tsic.Option{},
		hsic.WithTestName("pingallbyip"),
	)
	if err != nil {
		t.Errorf("failed to create ninjapanda environment: %s", err)
	}

	allClients, err := scenario.ListZTClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForClientSync()
	if err != nil {
		t.Errorf("failed wait for client clients to be in sync: %s", err)
	}

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
		key, err := scenario.CreatePreAuthKey(namespaceName, true, false)
		if err != nil {
			t.Errorf(
				"failed to create pre-auth key for namespace %s: %s",
				namespaceName,
				err,
			)
		}

		err = scenario.RunZTClientUp(
			namespaceName,
			ninjapanda.GetEndpoint(),
			key.GetKey(),
		)
		if err != nil {
			t.Errorf(
				"failed to run client up for namespace %s: %s",
				namespaceName,
				err,
			)
		}
	}

	err = scenario.WaitForClientSync()
	if err != nil {
		t.Errorf("failed wait for client clients to be in sync: %s", err)
	}

	allClients, err = scenario.ListZTClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allIps, err := scenario.ListZTClientsIPs()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
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

func TestEphemeral(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"namespace1": len(ClientVersions),
		"namespace2": len(ClientVersions),
	}

	ninjapanda, err := scenario.Ninjapanda(hsic.WithTestName("ephemeral"))
	if err != nil {
		t.Errorf("failed to create ninjapanda environment: %s", err)
	}

	for namespaceName, clientCount := range spec {
		err = scenario.CreateNamespace(namespaceName)
		if err != nil {
			t.Errorf("failed to create namespace %s: %s", namespaceName, err)
		}

		err = scenario.CreateNodesInNamespace(
			namespaceName,
			"all",
			clientCount,
			[]tsic.Option{}...)
		if err != nil {
			t.Errorf(
				"failed to create client nodes in namespace %s: %s",
				namespaceName,
				err,
			)
		}

		key, err := scenario.CreatePreAuthKey(namespaceName, true, true)
		if err != nil {
			t.Errorf(
				"failed to create pre-auth key for namespace %s: %s",
				namespaceName,
				err,
			)
		}

		err = scenario.RunZTClientUp(
			namespaceName,
			ninjapanda.GetEndpoint(),
			key.GetKey(),
		)
		if err != nil {
			t.Errorf(
				"failed to run client up for namespace %s: %s",
				namespaceName,
				err,
			)
		}
	}

	err = scenario.WaitForClientSync()
	if err != nil {
		t.Errorf("failed wait for client clients to be in sync: %s", err)
	}

	allClients, err := scenario.ListZTClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allIps, err := scenario.ListZTClientsIPs()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
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

	for _, client := range allClients {
		err := client.Logout()
		if err != nil {
			t.Errorf("failed to logout client %s: %s", client.Hostname(), err)
		}
	}

	scenario.WaitForZTClientLogout()

	t.Logf("all clients logged out")

	for namespaceName := range spec {
		machines, err := ninjapanda.ListMachinesInNamespace(namespaceName)
		if err != nil {
			log.Error().
				Err(err).
				Str("namespace", namespaceName).
				Msg("Error listing machines in namespace")

			return
		}

		if len(machines) != 0 {
			t.Errorf(
				"expected no machines, got %d in namespace %s",
				len(machines),
				namespaceName,
			)
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestPingAllByHostname(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		// Omit 1.16.2 (-1) because it does not have the FQDN field
		"namespace3": len(ClientVersions) - 1,
		"namespace4": len(ClientVersions) - 1,
	}

	err = scenario.CreateNinjapandaEnv(
		spec,
		[]tsic.Option{},
		hsic.WithTestName("pingallbyname"),
	)
	if err != nil {
		t.Errorf("failed to create ninjapanda environment: %s", err)
	}

	allClients, err := scenario.ListZTClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForClientSync()
	if err != nil {
		t.Errorf("failed wait for client clients to be in sync: %s", err)
	}

	allHostnames, err := scenario.ListZTClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	success := 0

	for _, client := range allClients {
		for _, hostname := range allHostnames {
			err := client.Ping(hostname)
			if err != nil {
				t.Errorf(
					"failed to ping %s from %s: %s",
					hostname,
					client.Hostname(),
					err,
				)
			} else {
				success++
			}
		}
	}

	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allClients))

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

// If subtests are parallel, then they will start before setup is run.
// This might mean we approach setup slightly wrong, but for now, ignore
// the linter
// nolint:tparallel
func TestTaildrop(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	retry := func(times int, sleepInverval time.Duration, doWork func() error) error {
		var err error
		for attempts := 0; attempts < times; attempts++ {
			err = doWork()
			if err == nil {
				return nil
			}
			time.Sleep(sleepInverval)
		}

		return err
	}

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		// Omit 1.16.2 (-1) because it does not have the FQDN field
		"taildrop": len(ClientVersions) - 1,
	}

	err = scenario.CreateNinjapandaEnv(
		spec,
		[]tsic.Option{},
		hsic.WithTestName("taildrop"),
	)
	if err != nil {
		t.Errorf("failed to create ninjapanda environment: %s", err)
	}

	allClients, err := scenario.ListZTClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForClientSync()
	if err != nil {
		t.Errorf("failed wait for client clients to be in sync: %s", err)
	}

	// This will essentially fetch and cache all the FQDNs
	_, err = scenario.ListZTClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	for _, client := range allClients {
		command := []string{
			"touch",
			fmt.Sprintf("/tmp/file_from_%s", client.Hostname()),
		}

		if _, _, err := client.Execute(command); err != nil {
			t.Errorf(
				"failed to create taildrop file on %s, err: %s",
				client.Hostname(),
				err,
			)
		}

		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			// It is safe to ignore this error as we handled it when caching it
			peerFQDN, _ := peer.FQDN()

			t.Run(
				fmt.Sprintf("%s-%s", client.Hostname(), peer.Hostname()),
				func(t *testing.T) {
					command := []string{
						"client", "file", "cp",
						fmt.Sprintf("/tmp/file_from_%s", client.Hostname()),
						fmt.Sprintf("%s:", peerFQDN),
					}

					err := retry(10, 1*time.Second, func() error {
						t.Logf(
							"Sending file from %s to %s\n",
							client.Hostname(),
							peer.Hostname(),
						)
						_, _, err := client.Execute(command)

						return err
					})
					if err != nil {
						t.Errorf(
							"failed to send taildrop file on %s, err: %s",
							client.Hostname(),
							err,
						)
					}
				},
			)
		}
	}

	for _, client := range allClients {
		command := []string{
			"client", "file",
			"get",
			"/tmp/",
		}
		if _, _, err := client.Execute(command); err != nil {
			t.Errorf(
				"failed to get taildrop file on %s, err: %s",
				client.Hostname(),
				err,
			)
		}

		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			t.Run(
				fmt.Sprintf("%s-%s", client.Hostname(), peer.Hostname()),
				func(t *testing.T) {
					command := []string{
						"ls",
						fmt.Sprintf("/tmp/file_from_%s", peer.Hostname()),
					}
					log.Printf(
						"Checking file in %s from %s\n",
						client.Hostname(),
						peer.Hostname(),
					)

					result, _, err := client.Execute(command)
					if err != nil {
						t.Errorf("failed to execute command to ls taildrop: %s", err)
					}

					log.Printf("Result for %s: %s\n", peer.Hostname(), result)
					if fmt.Sprintf("/tmp/file_from_%s\n", peer.Hostname()) != result {
						t.Errorf(
							"taildrop result is not correct %s, wanted %s",
							result,
							fmt.Sprintf("/tmp/file_from_%s\n", peer.Hostname()),
						)
					}
				},
			)
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestResolveMagicDNS(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		// Omit 1.16.2 (-1) because it does not have the FQDN field
		"magicdns1": len(ClientVersions) - 1,
		"magicdns2": len(ClientVersions) - 1,
	}

	err = scenario.CreateNinjapandaEnv(
		spec,
		[]tsic.Option{},
		hsic.WithTestName("magicdns"),
	)
	if err != nil {
		t.Errorf("failed to create ninjapanda environment: %s", err)
	}

	allClients, err := scenario.ListZTClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForClientSync()
	if err != nil {
		t.Errorf("failed wait for client clients to be in sync: %s", err)
	}

	// Poor mans cache
	_, err = scenario.ListZTClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	_, err = scenario.ListZTClientsIPs()
	if err != nil {
		t.Errorf("failed to get IPs: %s", err)
	}

	for _, client := range allClients {
		for _, peer := range allClients {
			// It is safe to ignore this error as we handled it when caching it
			peerFQDN, _ := peer.FQDN()

			command := []string{
				"client",
				"ip", peerFQDN,
			}
			result, _, err := client.Execute(command)
			if err != nil {
				t.Errorf(
					"failed to execute resolve/ip command %s from %s: %s",
					peerFQDN,
					client.Hostname(),
					err,
				)
			}

			ips, err := peer.IPs()
			if err != nil {
				t.Errorf(
					"failed to get ips for %s: %s",
					peer.Hostname(),
					err,
				)
			}

			for _, ip := range ips {
				if !strings.Contains(result, ip.String()) {
					t.Errorf("ip %s is not found in \n%s\n", ip.String(), result)
				}
			}
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}
