package integration

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"optm.com/ninja-panda/integration/hsic"
	"optm.com/ninja-panda/integration/tsic"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

func executeAndUnmarshal[T any](
	ninjapanda ControlServer,
	command []string,
	result T,
) error {
	str, err := ninjapanda.Execute(command)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(str), result)
	if err != nil {
		return err
	}

	return nil
}

func TestNamespaceCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		"namespace1": 0,
		"namespace2": 0,
	}

	err = scenario.CreateNinjapandaEnv(
		spec,
		[]tsic.Option{},
		hsic.WithTestName("clins"),
	)
	assert.NoError(t, err)

	ninjapanda, err := scenario.Ninjapanda()
	assert.NoError(t, err)

	var listNamespaces []v1.Namespace
	err = executeAndUnmarshal(ninjapanda,
		[]string{
			"ninjapanda",
			"namespaces",
			"list",
			"--output",
			"json",
		},
		&listNamespaces,
	)
	assert.NoError(t, err)

	result := []string{listNamespaces[0].Name, listNamespaces[1].Name}
	sort.Strings(result)

	assert.Equal(
		t,
		[]string{"namespace1", "namespace2"},
		result,
	)

	_, err = ninjapanda.Execute(
		[]string{
			"ninjapanda",
			"namespaces",
			"rename",
			"--output",
			"json",
			"namespace2",
			"newname",
		},
	)
	assert.NoError(t, err)

	var listAfterRenameNamespaces []v1.Namespace
	err = executeAndUnmarshal(ninjapanda,
		[]string{
			"ninjapanda",
			"namespaces",
			"list",
			"--output",
			"json",
		},
		&listAfterRenameNamespaces,
	)
	assert.NoError(t, err)

	result = []string{
		listAfterRenameNamespaces[0].Name,
		listAfterRenameNamespaces[1].Name,
	}
	sort.Strings(result)

	assert.Equal(
		t,
		[]string{"namespace1", "newname"},
		result,
	)

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestPreAuthKeyCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	namespace := "preauthkeyspace"
	count := 3

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		namespace: 0,
	}

	err = scenario.CreateNinjapandaEnv(
		spec,
		[]tsic.Option{},
		hsic.WithTestName("clipak"),
	)
	assert.NoError(t, err)

	ninjapanda, err := scenario.Ninjapanda()
	assert.NoError(t, err)

	keys := make([]*v1.PreAuthKey, count)
	assert.NoError(t, err)

	for index := 0; index < count; index++ {
		var preAuthKey v1.PreAuthKey
		err := executeAndUnmarshal(
			ninjapanda,
			[]string{
				"ninjapanda",
				"preauthkeys",
				"--namespace",
				namespace,
				"create",
				"--reusable",
				"--expiration",
				"24h",
				"--output",
				"json",
				"--tags",
				"tag:test1,tag:test2",
			},
			&preAuthKey,
		)
		assert.NoError(t, err)

		keys[index] = &preAuthKey
	}

	assert.Len(t, keys, 3)

	var listedPreAuthKeys []v1.PreAuthKey
	err = executeAndUnmarshal(
		ninjapanda,
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace,
			"list",
			"--output",
			"json",
		},
		&listedPreAuthKeys,
	)
	assert.NoError(t, err)

	// There is one key created by "scenario.CreateNinjapandaEnv"
	assert.Len(t, listedPreAuthKeys, 4)

	assert.Equal(
		t,
		[]string{keys[0].PreAuthKeyId, keys[1].PreAuthKeyId, keys[2].PreAuthKeyId},
		[]string{
			listedPreAuthKeys[1].PreAuthKeyId,
			listedPreAuthKeys[2].PreAuthKeyId,
			listedPreAuthKeys[3].PreAuthKeyId,
		},
	)

	assert.NotEmpty(t, listedPreAuthKeys[1].Key)
	assert.NotEmpty(t, listedPreAuthKeys[2].Key)
	assert.NotEmpty(t, listedPreAuthKeys[3].Key)

	assert.True(t, expirationToTime(listedPreAuthKeys[1].Expiration).After(time.Now()))
	assert.True(t, expirationToTime(listedPreAuthKeys[2].Expiration).After(time.Now()))
	assert.True(t, expirationToTime(listedPreAuthKeys[3].Expiration).After(time.Now()))

	assert.True(
		t,
		expirationToTime(
			listedPreAuthKeys[1].Expiration,
		).Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		expirationToTime(
			listedPreAuthKeys[2].Expiration,
		).Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		expirationToTime(
			listedPreAuthKeys[3].Expiration,
		).Before(time.Now().Add(time.Hour*26)),
	)

	for index := range listedPreAuthKeys {
		if index == 0 {
			continue
		}

		assert.Equal(
			t,
			listedPreAuthKeys[index].AclTags,
			[]string{"tag:test1", "tag:test2"},
		)
	}

	// Test key expiry
	_, err = ninjapanda.Execute(
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace,
			"expire",
			*listedPreAuthKeys[1].Key,
		},
	)
	assert.NoError(t, err)

	var listedPreAuthKeysAfterExpire []v1.PreAuthKey
	err = executeAndUnmarshal(
		ninjapanda,
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace,
			"list",
			"--output",
			"json",
		},
		&listedPreAuthKeysAfterExpire,
	)
	assert.NoError(t, err)

	assert.True(
		t,
		expirationToTime(listedPreAuthKeysAfterExpire[1].Expiration).Before(time.Now()),
	)
	assert.True(
		t,
		expirationToTime(listedPreAuthKeysAfterExpire[2].Expiration).After(time.Now()),
	)
	assert.True(
		t,
		expirationToTime(listedPreAuthKeysAfterExpire[3].Expiration).After(time.Now()),
	)

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestPreAuthKeyCommandWithoutExpiry(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	namespace := "pre-auth-key-without-exp-namespace"

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		namespace: 0,
	}

	err = scenario.CreateNinjapandaEnv(
		spec,
		[]tsic.Option{},
		hsic.WithTestName("clipaknaexp"),
	)
	assert.NoError(t, err)

	ninjapanda, err := scenario.Ninjapanda()
	assert.NoError(t, err)

	var preAuthKey v1.PreAuthKey
	err = executeAndUnmarshal(
		ninjapanda,
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace,
			"create",
			"--reusable",
			"--output",
			"json",
		},
		&preAuthKey,
	)
	assert.NoError(t, err)

	var listedPreAuthKeys []v1.PreAuthKey
	err = executeAndUnmarshal(
		ninjapanda,
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace,
			"list",
			"--output",
			"json",
		},
		&listedPreAuthKeys,
	)
	assert.NoError(t, err)

	// There is one key created by "scenario.CreateNinjapandaEnv"
	assert.Len(t, listedPreAuthKeys, 2)

	assert.True(t, expirationToTime(listedPreAuthKeys[1].Expiration).After(time.Now()))
	assert.True(
		t,
		expirationToTime(
			listedPreAuthKeys[1].Expiration,
		).Before(time.Now().Add(time.Minute*70)),
	)

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestPreAuthKeyCommandReusableEphemeral(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	namespace := "pre-auth-key-reus-ephm-namespace"

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		namespace: 0,
	}

	err = scenario.CreateNinjapandaEnv(
		spec,
		[]tsic.Option{},
		hsic.WithTestName("clipakresueeph"),
	)
	assert.NoError(t, err)

	ninjapanda, err := scenario.Ninjapanda()
	assert.NoError(t, err)

	var preAuthReusableKey v1.PreAuthKey
	err = executeAndUnmarshal(
		ninjapanda,
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace,
			"create",
			"--reusable=true",
			"--output",
			"json",
		},
		&preAuthReusableKey,
	)
	assert.NoError(t, err)

	var preAuthEphemeralKey v1.PreAuthKey
	err = executeAndUnmarshal(
		ninjapanda,
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace,
			"create",
			"--ephemeral=true",
			"--output",
			"json",
		},
		&preAuthEphemeralKey,
	)
	assert.NoError(t, err)

	assert.True(t, preAuthEphemeralKey.GetEphemeral())
	assert.Equal(t, 0, preAuthEphemeralKey.ReuseCount)

	var listedPreAuthKeys []v1.PreAuthKey
	err = executeAndUnmarshal(
		ninjapanda,
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace,
			"list",
			"--output",
			"json",
		},
		&listedPreAuthKeys,
	)
	assert.NoError(t, err)

	// There is one key created by "scenario.CreateNinjapandaEnv"
	assert.Len(t, listedPreAuthKeys, 3)

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestEnablingRoutes(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	namespace := "enable-routing"

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		namespace: 3,
	}

	err = scenario.CreateNinjapandaEnv(
		spec,
		[]tsic.Option{},
		hsic.WithTestName("clienableroute"),
	)
	assert.NoError(t, err)

	allClients, err := scenario.ListZTClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForClientSync()
	if err != nil {
		t.Errorf("failed wait for lients to be in sync: %s", err)
	}

	ninjapanda, err := scenario.Ninjapanda()
	assert.NoError(t, err)

	// advertise routes using the up command
	for i, client := range allClients {
		routeStr := fmt.Sprintf("10.0.%d.0/24", i)
		hostname, _ := client.FQDN()
		_, _, err = client.Execute([]string{
			"ninjapanda",
			"up",
			fmt.Sprintf("--advertise-routes=%s", routeStr),
			"-login-server", ninjapanda.GetEndpoint(),
			"--hostname", hostname,
		})
		assert.NoError(t, err)
	}

	err = scenario.WaitForClientSync()
	if err != nil {
		t.Errorf("failed wait for clients to be in sync: %s", err)
	}

	var routes []*v1.Route
	err = executeAndUnmarshal(
		ninjapanda,
		[]string{
			"ninjapanda",
			"routes",
			"list",
			"--output",
			"json",
		},
		&routes,
	)

	assert.NoError(t, err)
	assert.Len(t, routes, 3)

	for _, route := range routes {
		assert.Equal(t, route.Advertised, true)
		assert.Equal(t, route.Enabled, false)
		assert.Equal(t, route.IsPrimary, false)
	}

	for _, route := range routes {
		_, err = ninjapanda.Execute(
			[]string{
				"ninjapanda",
				"routes",
				"enable",
				"--route",
				route.RouteId,
			})
		assert.NoError(t, err)
	}

	var enablingRoutes []*v1.Route
	err = executeAndUnmarshal(
		ninjapanda,
		[]string{
			"ninjapanda",
			"routes",
			"list",
			"--output",
			"json",
		},
		&enablingRoutes,
	)
	assert.NoError(t, err)

	for _, route := range enablingRoutes {
		assert.Equal(t, route.Advertised, true)
		assert.Equal(t, route.Enabled, true)
		assert.Equal(t, route.IsPrimary, true)
	}

	routeIDToBeDisabled := enablingRoutes[0].RouteId

	_, err = ninjapanda.Execute(
		[]string{
			"ninjapanda",
			"routes",
			"disable",
			"--route",
			routeIDToBeDisabled,
		})
	assert.NoError(t, err)

	var disablingRoutes []*v1.Route
	err = executeAndUnmarshal(
		ninjapanda,
		[]string{
			"ninjapanda",
			"routes",
			"list",
			"--output",
			"json",
		},
		&disablingRoutes,
	)
	assert.NoError(t, err)

	for _, route := range disablingRoutes {
		assert.Equal(t, true, route.Advertised)

		if route.RouteId == routeIDToBeDisabled {
			assert.Equal(t, route.Enabled, false)
			assert.Equal(t, route.IsPrimary, false)
		} else {
			assert.Equal(t, route.Enabled, true)
			assert.Equal(t, route.IsPrimary, true)
		}
	}
}

func expirationToTime(exp *string) time.Time {
	layout := time.RFC3339Nano
	t, err := time.Parse(layout, *exp)
	if err != nil {
		return time.Time{}
	}
	return t
}
