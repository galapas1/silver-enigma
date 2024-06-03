package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"optm.com/ninja-panda/integration/hsic"
	"optm.com/ninja-panda/integration/tsic"
	"optm.com/ninja-panda/src"
)

var retry = func(times int, sleepInterval time.Duration,
	doWork func() (string, string, error),
) (string, string, error) {
	var result string
	var stderr string
	var err error

	for attempts := 0; attempts < times; attempts++ {
		tempResult, tempStderr, err := doWork()

		result += tempResult
		stderr += tempStderr

		if err == nil {
			return result, stderr, nil
		}

		// If we get a permission denied error, we can fail immediately
		// since that is something we wont recover from by retrying.
		if err != nil && strings.Contains(stderr, "Permission denied (client)") {
			return result, stderr, err
		}

		time.Sleep(sleepInterval)
	}

	return result, stderr, err
}

func TestSSHOneNamespaceAllToAll(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"namespace1": len(ClientVersions) - 5,
	}

	err = scenario.CreateNinjapandaEnv(spec,
		[]tsic.Option{tsic.WithSSH()},
		hsic.WithACLPolicy(
			&ninjapanda.ACLPolicy{
				Groups: map[string][]string{
					"group:integration-test": {"namespace1"},
				},
				ACLs: []ninjapanda.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				SSHs: []ninjapanda.SSH{
					{
						Action:       "accept",
						Sources:      []string{"group:integration-test"},
						Destinations: []string{"group:integration-test"},
						Users:        []string{"ssh-it-user"},
					},
				},
			},
		),
		hsic.WithConfigEnv(map[string]string{
			"NINJAPANDA_EXPERIMENTAL_FEATURE_SSH": "1",
		}),
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

	_, err = scenario.ListZTClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	for _, client := range allClients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHHostname(t, client, peer)
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestSSHMultipleNamespacesAllToAll(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"namespace1": len(ClientVersions) - 5,
		"namespace2": len(ClientVersions) - 5,
	}

	err = scenario.CreateNinjapandaEnv(spec,
		[]tsic.Option{tsic.WithSSH()},
		hsic.WithACLPolicy(
			&ninjapanda.ACLPolicy{
				Groups: map[string][]string{
					"group:integration-test": {"namespace1", "namespace2"},
				},
				ACLs: []ninjapanda.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				SSHs: []ninjapanda.SSH{
					{
						Action:       "accept",
						Sources:      []string{"group:integration-test"},
						Destinations: []string{"group:integration-test"},
						Users:        []string{"ssh-it-user"},
					},
				},
			},
		),
		hsic.WithConfigEnv(map[string]string{
			"NINJAPANDA_EXPERIMENTAL_FEATURE_SSH": "1",
		}),
	)
	if err != nil {
		t.Errorf("failed to create ninjapanda environment: %s", err)
	}

	nsOneClients, err := scenario.ListZTClients("namespace1")
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	nsTwoClients, err := scenario.ListZTClients("namespace2")
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForClientSync()
	if err != nil {
		t.Errorf("failed wait for client clients to be in sync: %s", err)
	}

	_, err = scenario.ListZTClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	testInterNamespaceSSH := func(sourceClients []ZTClient, targetClients []ZTClient) {
		for _, client := range sourceClients {
			for _, peer := range targetClients {
				assertSSHHostname(t, client, peer)
			}
		}
	}

	testInterNamespaceSSH(nsOneClients, nsTwoClients)
	testInterNamespaceSSH(nsTwoClients, nsOneClients)

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestSSHNoSSHConfigured(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"namespace1": len(ClientVersions) - 5,
	}

	err = scenario.CreateNinjapandaEnv(spec,
		[]tsic.Option{tsic.WithSSH()},
		hsic.WithACLPolicy(
			&ninjapanda.ACLPolicy{
				Groups: map[string][]string{
					"group:integration-test": {"namespace1"},
				},
				ACLs: []ninjapanda.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				SSHs: []ninjapanda.SSH{},
			},
		),
		hsic.WithTestName("sshnoneconfigured"),
		hsic.WithConfigEnv(map[string]string{
			"NINJAPANDA_EXPERIMENTAL_FEATURE_SSH": "1",
		}),
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

	_, err = scenario.ListZTClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	for _, client := range allClients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHPermissionDenied(t, client, peer)
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestSSHIsBlockedInACL(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"namespace1": len(ClientVersions) - 5,
	}

	err = scenario.CreateNinjapandaEnv(spec,
		[]tsic.Option{tsic.WithSSH()},
		hsic.WithACLPolicy(
			&ninjapanda.ACLPolicy{
				Groups: map[string][]string{
					"group:integration-test": {"namespace1"},
				},
				ACLs: []ninjapanda.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:80"},
					},
				},
				SSHs: []ninjapanda.SSH{
					{
						Action:       "accept",
						Sources:      []string{"group:integration-test"},
						Destinations: []string{"group:integration-test"},
						Users:        []string{"ssh-it-user"},
					},
				},
			},
		),
		hsic.WithTestName("sshisblockedinacl"),
		hsic.WithConfigEnv(map[string]string{
			"NINJAPANDA_EXPERIMENTAL_FEATURE_SSH": "1",
		}),
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

	_, err = scenario.ListZTClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	for _, client := range allClients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHTimeout(t, client, peer)
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestSSNamespaceOnlyIsolation(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"namespaceacl1": len(ClientVersions) - 5,
		"namespaceacl2": len(ClientVersions) - 5,
	}

	err = scenario.CreateNinjapandaEnv(spec,
		[]tsic.Option{tsic.WithSSH()},
		hsic.WithACLPolicy(
			&ninjapanda.ACLPolicy{
				Groups: map[string][]string{
					"group:ssh1": {"namespaceacl1"},
					"group:ssh2": {"namespaceacl2"},
				},
				ACLs: []ninjapanda.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				SSHs: []ninjapanda.SSH{
					{
						Action:       "accept",
						Sources:      []string{"group:ssh1"},
						Destinations: []string{"group:ssh1"},
						Users:        []string{"ssh-it-user"},
					},
					{
						Action:       "accept",
						Sources:      []string{"group:ssh2"},
						Destinations: []string{"group:ssh2"},
						Users:        []string{"ssh-it-user"},
					},
				},
			},
		),
		hsic.WithTestName("sshtwonamespaceaclblock"),
		hsic.WithConfigEnv(map[string]string{
			"NINJAPANDA_EXPERIMENTAL_FEATURE_SSH": "1",
		}),
	)
	if err != nil {
		t.Errorf("failed to create ninjapanda environment: %s", err)
	}

	ssh1Clients, err := scenario.ListZTClients("namespaceacl1")
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	ssh2Clients, err := scenario.ListZTClients("namespaceacl2")
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForClientSync()
	if err != nil {
		t.Errorf("failed wait for client clients to be in sync: %s", err)
	}

	_, err = scenario.ListZTClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	// TODO: ACLs do currently not cover reject
	// cases properly, and currently will accept all incomming connections
	// as long as a rule is present.
	//
	// for _, client := range ssh1Clients {
	// 	for _, peer := range ssh2Clients {
	// 		if client.Hostname() == peer.Hostname() {
	// 			continue
	// 		}
	//
	// 		assertSSHPermissionDenied(t, client, peer)
	// 	}
	// }
	//
	// for _, client := range ssh2Clients {
	// 	for _, peer := range ssh1Clients {
	// 		if client.Hostname() == peer.Hostname() {
	// 			continue
	// 		}
	//
	// 		assertSSHPermissionDenied(t, client, peer)
	// 	}
	// }

	for _, client := range ssh1Clients {
		for _, peer := range ssh1Clients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHHostname(t, client, peer)
		}
	}

	for _, client := range ssh2Clients {
		for _, peer := range ssh2Clients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHHostname(t, client, peer)
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func doSSH(
	t *testing.T,
	client ZTClient,
	peer ZTClient,
) (string, string, error) {
	t.Helper()

	peerFQDN, _ := peer.FQDN()

	command := []string{
		"ssh", "-o StrictHostKeyChecking=no", "-o ConnectTimeout=1",
		fmt.Sprintf("%s@%s", "ssh-it-user", peerFQDN),
		"'hostname'",
	}

	return retry(10, 1*time.Second, func() (string, string, error) {
		return client.Execute(command)
	})
}

func assertSSHHostname(t *testing.T, client ZTClient, peer ZTClient) {
	t.Helper()

	result, _, err := doSSH(t, client, peer)
	assert.NoError(t, err)

	assert.Contains(t, peer.ID(), strings.ReplaceAll(result, "\n", ""))
}

func assertSSHPermissionDenied(
	t *testing.T,
	client ZTClient,
	peer ZTClient,
) {
	t.Helper()

	result, stderr, err := doSSH(t, client, peer)
	assert.Error(t, err)

	assert.Empty(t, result)

	assert.Contains(t, stderr, "Permission denied (client)")
}

func assertSSHTimeout(t *testing.T, client ZTClient, peer ZTClient) {
	t.Helper()

	result, stderr, err := doSSH(t, client, peer)
	assert.NoError(t, err)

	assert.Empty(t, result)

	assert.Contains(t, stderr, "Connection timed out")
}
