package integration

import (
	"testing"

	"optm.com/ninja-panda/integration/dockertestutil"
)

func IntegrationSkip(t *testing.T) {
	t.Helper()

	if !dockertestutil.IsRunningInContainer() {
		t.Skip("not running in docker, skipping")
	}

	if testing.Short() {
		t.Skip("skipping integration tests due to short flag")
	}
}

// If subtests are parallel, then they will start before setup is run.
// This might mean we approach setup slightly wrong, but for now, ignore
// the linter
// nolint:tparallel
func TestNinjapanda(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	var err error

	namespace := "test-space"

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	t.Run("start-ninjapanda", func(t *testing.T) {
		ninjapanda, err := scenario.Ninjapanda()
		if err != nil {
			t.Errorf("failed to start ninjapanda: %s", err)
		}

		err = ninjapanda.WaitForReady()
		if err != nil {
			t.Errorf("ninjapanda failed to become ready: %s", err)
		}
	})

	t.Run("create-namespace", func(t *testing.T) {
		err := scenario.CreateNamespace(namespace)
		if err != nil {
			t.Errorf("failed to create namespace: %s", err)
		}

		if _, ok := scenario.namespaces[namespace]; !ok {
			t.Errorf("namespace is not in scenario")
		}
	})

	t.Run("create-auth-key", func(t *testing.T) {
		_, err := scenario.CreatePreAuthKey(namespace, true, false)
		if err != nil {
			t.Errorf("failed to create preauthkey: %s", err)
		}
	})

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

// If subtests are parallel, then they will start before setup is run.
// This might mean we approach setup slightly wrong, but for now, ignore
// the linter
// nolint:tparallel
func TestCreateClient(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	namespace := "only-create-containers"

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	scenario.namespaces[namespace] = &Namespace{
		Clients: make(map[string]ZTClient),
	}

	t.Run("create-client", func(t *testing.T) {
		err := scenario.CreateNodesInNamespace(namespace, "all", 3)
		if err != nil {
			t.Errorf("failed to add client nodes: %s", err)
		}

		if clients := len(scenario.namespaces[namespace].Clients); clients != 3 {
			t.Errorf("wrong number of client clients: %d != %d", clients, 3)
		}

		// TODO: Test "all" version logic
	})

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

// If subtests are parallel, then they will start before setup is run.
// This might mean we approach setup slightly wrong, but for now, ignore
// the linter
// nolint:tparallel
func TestNodesJoiningNinjapanda(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	var err error

	namespace := "join-node-test"

	count := 1

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	t.Run("start-ninjapanda", func(t *testing.T) {
		ninjapanda, err := scenario.Ninjapanda()
		if err != nil {
			t.Errorf("failed to start ninjapanda: %s", err)
		}

		err = ninjapanda.WaitForReady()
		if err != nil {
			t.Errorf("ninjapanda failed to become ready: %s", err)
		}
	})

	t.Run("create-namespace", func(t *testing.T) {
		err := scenario.CreateNamespace(namespace)
		if err != nil {
			t.Errorf("failed to create namespace: %s", err)
		}

		if _, ok := scenario.namespaces[namespace]; !ok {
			t.Errorf("namespace is not in scenario")
		}
	})

	t.Run("create-client", func(t *testing.T) {
		err := scenario.CreateNodesInNamespace(namespace, "1.30.2", count)
		if err != nil {
			t.Errorf("failed to add client nodes: %s", err)
		}

		if clients := len(scenario.namespaces[namespace].Clients); clients != count {
			t.Errorf("wrong number of client clients: %d != %d", clients, count)
		}
	})

	t.Run("join-ninjapanda", func(t *testing.T) {
		key, err := scenario.CreatePreAuthKey(namespace, true, false)
		if err != nil {
			t.Errorf("failed to create preauthkey: %s", err)
		}

		ninjapanda, err := scenario.Ninjapanda()
		if err != nil {
			t.Errorf("failed to start ninjapanda: %s", err)
		}

		err = scenario.RunZTClientUp(
			namespace,
			ninjapanda.GetEndpoint(),
			key.GetKey(),
		)
		if err != nil {
			t.Errorf("failed to login: %s", err)
		}
	})

	t.Run("get-ips", func(t *testing.T) {
		ips, err := scenario.GetIPs(namespace)
		if err != nil {
			t.Errorf("failed to get client ips: %s", err)
		}

		if len(ips) != count*2 {
			t.Errorf(
				"got the wrong amount of client ips, %d != %d",
				len(ips),
				count*2,
			)
		}
	})

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}
