// nolint
package ninjapanda

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

type IntegrationCLITestSuite struct {
	suite.Suite
	stats *suite.SuiteInformation

	pool       dockertest.Pool
	network    dockertest.Network
	ninjapanda dockertest.Resource
	database   dockertest.Resource
	env        []string
}

func TestIntegrationCLITestSuite(t *testing.T) {
	t.Skip("This fails on GitHub CI/CD, disabling for now")
	if testing.Short() {
		t.Skip("skipping integration tests due to short flag")
	}

	s := new(IntegrationCLITestSuite)

	suite.Run(t, s)
}

func (s *IntegrationCLITestSuite) SetupTest() {
	var err error

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

	ninjapandaBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile",
		ContextDir: "..",
	}

	currentPath, err := os.Getwd()
	if err != nil {
		s.FailNow(fmt.Sprintf("Could not determine current path: %s", err), "")
	}

	err = s.pool.RemoveContainerByName(postgresHostname)
	if err != nil {
		s.FailNow(
			fmt.Sprintf(
				"Could not remove existing database container postgres: %s",
				err,
			),
			"",
		)
	}

	ninjapandaOptions := &dockertest.RunOptions{
		Name: "ninjapanda-cli",
		Mounts: []string{
			fmt.Sprintf("%s/../integration_test/etc:/etc/ninjapanda", currentPath),
		},
		Cmd:          []string{"ninjapanda", "serve"},
		Networks:     []*dockertest.Network{&s.network},
		ExposedPorts: []string{"8080/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"8080/tcp": {{HostPort: "8080"}},
		},
	}

	database, err := CreatePostgresDatabase(&s.pool, &s.network)
	if err != nil {
		s.FailNow(
			fmt.Sprintf(
				"Could not start postgres database container: %s",
				err,
			),
			"",
		)
	} else {
		s.database = *database
	}
	err = s.pool.RemoveContainerByName(ninjapandaHostname)
	if err != nil {
		s.FailNow(
			fmt.Sprintf(
				"Could not remove existing container before building test: %s",
				err,
			),
			"",
		)
	}

	fmt.Println("Creating ninjapanda container for CLI tests")
	if pninjapanda, err := s.pool.BuildAndRunWithBuildOptions(ninjapandaBuildOptions, ninjapandaOptions, DockerRestartPolicy); err == nil {
		s.ninjapanda = *pninjapanda
	} else {
		s.FailNow(fmt.Sprintf("Could not start ninjapanda container: %s", err), "")
	}
	fmt.Println("Created ninjapanda container for CLI tests")

	fmt.Println("Waiting for ninjapanda to be ready for CLI tests")
	hostEndpoint := fmt.Sprintf("%s:%s",
		"localhost", // s.ninjapanda.GetIPInNetwork(&s.network),
		s.ninjapanda.GetPort("8080/tcp"))

	if err := s.pool.Retry(func() error {
		url := fmt.Sprintf("http://%s/health", hostEndpoint)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("ninjapanda for CLI test is not ready: %s\n", err)
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
	fmt.Println("ninjapanda container is ready for CLI tests")
}

func (s *IntegrationCLITestSuite) TearDownTest() {
	if err := s.pool.Purge(&s.ninjapanda); err != nil {
		log.Printf("Could not purge ninjapanda resource: %s\n", err)
	}
	if err := s.pool.Purge(&s.database); err != nil {
		log.Printf("Could not purge postgres database resource: %s\n", err)
	}
	if err := s.network.Close(); err != nil {
		log.Printf("Could not close network: %s\n", err)
	}
}

func (s *IntegrationCLITestSuite) HandleStats(
	suiteName string,
	stats *suite.SuiteInformation,
) {
	s.stats = stats
}

func (s *IntegrationCLITestSuite) createNamespace(name string) (*v1.Namespace, error) {
	result, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"namespaces",
			"create",
			name,
			"--output",
			"json",
		},
		[]string{},
	)
	if err != nil {
		return nil, err
	}

	var namespace v1.Namespace
	err = json.Unmarshal([]byte(result), &namespace)
	if err != nil {
		return nil, err
	}

	return &namespace, nil
}

func (s *IntegrationCLITestSuite) TestNamespaceCommand() {
	names := []string{"namespace1", "otherspace", "tasty"}
	namespaces := make([]*v1.Namespace, len(names))

	for index, namespaceName := range names {
		namespace, err := s.createNamespace(namespaceName)
		assert.Nil(s.T(), err)

		namespaces[index] = namespace
	}

	assert.Len(s.T(), namespaces, len(names))

	assert.Equal(s.T(), names[0], namespaces[0].Name)
	assert.Equal(s.T(), names[1], namespaces[1].Name)
	assert.Equal(s.T(), names[2], namespaces[2].Name)

	// Test list namespaces
	listResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"namespaces",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedNamespaces []v1.Namespace
	err = json.Unmarshal([]byte(listResult), &listedNamespaces)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), names[0], listedNamespaces[0].Name)
	assert.Equal(s.T(), names[1], listedNamespaces[1].Name)
	assert.Equal(s.T(), names[2], listedNamespaces[2].Name)

	// Test rename namespace
	renameResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"namespaces",
			"rename",
			"--output",
			"json",
			"tasty",
			"newname",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var renamedNamespace v1.Namespace
	err = json.Unmarshal([]byte(renameResult), &renamedNamespace)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), renamedNamespace.Name, "newname")

	// Test list after rename namespaces
	listAfterRenameResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"namespaces",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedAfterRenameNamespaces []v1.Namespace
	err = json.Unmarshal([]byte(listAfterRenameResult), &listedAfterRenameNamespaces)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), names[0], listedAfterRenameNamespaces[0].Name)
	assert.Equal(s.T(), names[1], listedAfterRenameNamespaces[1].Name)
	assert.Equal(s.T(), "newname", listedAfterRenameNamespaces[2].Name)
}

// Really creating PreAuthKeys with tags is busted.
// Cannot create Pre Auth Key: rpc error: code = Unknown desc = failed to ceate key tag in the database: ERROR: invalid input syntax for type bigint: "d5ea10f2-8a81-42c9-9df8-6eb16286dd6b" (SQLSTATE 22P02)
// TBD: Inserting tags into PreAuthKeys is under consideration.
func (s *IntegrationCLITestSuite) tbdTestPreAuthKeyCommand() {
	count := 5

	namespace, err := s.createNamespace("pre-auth-key-namespace")

	keys := make([]*v1.PreAuthKey, count)
	assert.Nil(s.T(), err)

	for i := 0; i < count; i++ {
		preAuthResult, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"preauthkeys",
				"--namespace",
				namespace.Name,
				"create",
				"--reuseCount",
				"0",
				"--expiration",
				"24h",
				"--output",
				"json",
				"--tags",
				"tag:test1,tag:test2",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		var preAuthKey v1.PreAuthKey
		err = json.Unmarshal([]byte(preAuthResult), &preAuthKey)
		assert.Nil(s.T(), err)

		keys[i] = &preAuthKey
	}

	assert.Len(s.T(), keys, 5)

	// Test list of keys
	listResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace.Name,
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedPreAuthKeys []v1.PreAuthKey
	err = json.Unmarshal([]byte(listResult), &listedPreAuthKeys)
	assert.Nil(s.T(), err)

	assert.True(
		s.T(),
		ExpirationToTime(listedPreAuthKeys[0].Expiration).After(time.Now().UTC()),
	)
	assert.True(
		s.T(),
		ExpirationToTime(listedPreAuthKeys[1].Expiration).After(time.Now().UTC()),
	)
	assert.True(
		s.T(),
		ExpirationToTime(listedPreAuthKeys[2].Expiration).After(time.Now().UTC()),
	)
	assert.True(
		s.T(),
		ExpirationToTime(listedPreAuthKeys[3].Expiration).After(time.Now().UTC()),
	)
	assert.True(
		s.T(),
		ExpirationToTime(listedPreAuthKeys[4].Expiration).After(time.Now().UTC()),
	)

	assert.True(
		s.T(),
		ExpirationToTime(
			listedPreAuthKeys[0].Expiration,
		).Before(time.Now().UTC().Add(time.Hour*26)),
	)
	assert.True(
		s.T(),
		ExpirationToTime(
			listedPreAuthKeys[1].Expiration,
		).Before(time.Now().UTC().Add(time.Hour*26)),
	)
	assert.True(
		s.T(),
		ExpirationToTime(
			listedPreAuthKeys[2].Expiration,
		).Before(time.Now().UTC().Add(time.Hour*26)),
	)
	assert.True(
		s.T(),
		ExpirationToTime(
			listedPreAuthKeys[3].Expiration,
		).Before(time.Now().UTC().Add(time.Hour*26)),
	)
	assert.True(
		s.T(),
		ExpirationToTime(
			listedPreAuthKeys[4].Expiration,
		).Before(time.Now().UTC().Add(time.Hour*26)),
	)

	// Test that tags are present
	for i := 0; i < count; i++ {
		assert.Equal(
			s.T(),
			listedPreAuthKeys[i].AclTags,
			[]string{"tag:test1", "tag:test2"},
		)
	}

	// Expire three keys
	for i := 0; i < 3; i++ {
		_, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"preauthkeys",
				"--namespace",
				namespace.Name,
				"expire",
				*listedPreAuthKeys[i].Key,
			},
			[]string{},
		)
		assert.Nil(s.T(), err)
	}

	// Test list pre auth keys after expire
	listAfterExpireResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace.Name,
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedAfterExpirePreAuthKeys []v1.PreAuthKey
	err = json.Unmarshal([]byte(listAfterExpireResult), &listedAfterExpirePreAuthKeys)
	assert.Nil(s.T(), err)

	assert.True(
		s.T(),
		ExpirationToTime(
			listedAfterExpirePreAuthKeys[0].Expiration,
		).Before(time.Now().UTC()),
	)
	assert.True(
		s.T(),
		ExpirationToTime(
			listedAfterExpirePreAuthKeys[1].Expiration,
		).Before(time.Now().UTC()),
	)
	assert.True(
		s.T(),
		ExpirationToTime(
			listedAfterExpirePreAuthKeys[2].Expiration,
		).Before(time.Now().UTC()),
	)
	assert.True(
		s.T(),
		ExpirationToTime(
			listedAfterExpirePreAuthKeys[3].Expiration,
		).After(time.Now().UTC()),
	)
	assert.True(
		s.T(),
		ExpirationToTime(
			listedAfterExpirePreAuthKeys[4].Expiration,
		).After(time.Now().UTC()),
	)
}

func (s *IntegrationCLITestSuite) TestPreAuthKeyCommandWithoutExpiry() {
	namespace, err := s.createNamespace("pre-auth-key-without-exp-namespace")
	assert.Nil(s.T(), err)

	preAuthResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace.Name,
			"create",
			"--reuseCount",
			"0",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var preAuthKey v1.PreAuthKey
	err = json.Unmarshal([]byte(preAuthResult), &preAuthKey)
	assert.Nil(s.T(), err)

	// Test list of keys
	listResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace.Name,
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedPreAuthKeys []v1.PreAuthKey
	err = json.Unmarshal([]byte(listResult), &listedPreAuthKeys)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listedPreAuthKeys, 1)

	preauthKeyExpiration := ExpirationToTime(listedPreAuthKeys[0].Expiration)
	assert.True(s.T(), preauthKeyExpiration.After(time.Now().UTC()))
	assert.True(
		s.T(),
		preauthKeyExpiration.Before(time.Now().UTC().Add(time.Minute*70)),
	)
}

// TBD: Feature needs to be re-evaluated.
func (s *IntegrationCLITestSuite) tbdTestPreAuthKeyCommandReusableEphemeral() {
	namespace, err := s.createNamespace("pre-auth-key-reus-ephm-namespace")
	assert.Nil(s.T(), err)

	preAuthReusableResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace.Name,
			"create",
			"--reuseCount",
			"0",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var preAuthReusableKey v1.PreAuthKey
	err = json.Unmarshal([]byte(preAuthReusableResult), &preAuthReusableKey)
	assert.Nil(s.T(), err)

	assert.True(s.T(), preAuthReusableKey.ReuseCount > 0)
	assert.False(s.T(), preAuthReusableKey.GetEphemeral())

	preAuthEphemeralResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace.Name,
			"create",
			"--ephemeral=true",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var preAuthEphemeralKey v1.PreAuthKey
	err = json.Unmarshal([]byte(preAuthEphemeralResult), &preAuthEphemeralKey)
	assert.Nil(s.T(), err)

	assert.True(s.T(), preAuthEphemeralKey.GetEphemeral())
	assert.False(s.T(), preAuthEphemeralKey.ReuseCount > 0)

	// TODO: Evaluate if we need a case to test for reusable and ephemeral
	// preAuthReusableAndEphemeralResult, err := ExecuteCommand(
	// 	&s.ninjapanda,
	// 	[]string{
	// 		"ninjapanda",
	// 		"preauthkeys",
	// 		"--namespace",
	// 		namespace.Name,
	// 		"create",
	// 		"--ephemeral",
	// 		"--reuseCount",
	//      "0",
	// 		"--output",
	// 		"json",
	// 	},
	// 	[]string{},
	// )
	// assert.NotNil(s.T(), err)

	// Test list of keys
	listResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"preauthkeys",
			"--namespace",
			namespace.Name,
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedPreAuthKeys []v1.PreAuthKey
	err = json.Unmarshal([]byte(listResult), &listedPreAuthKeys)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listedPreAuthKeys, 2)
}

// TBD: This test under review due to correlation IDs and Node ID's in cache.
func (s *IntegrationCLITestSuite) tbdTestNodeTagCommand() {
	namespace, err := s.createNamespace("machine-namespace")
	assert.Nil(s.T(), err)

	machineKeys := []string{
		"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"nodekey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range machineKeys {
		_, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--namespace",
				namespace.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"nodes",
				"--namespace",
				namespace.Name,
				"register",
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		var machine v1.Machine
		err = json.Unmarshal([]byte(machineResult), &machine)
		assert.Nil(s.T(), err)

		machines[index] = &machine
	}
	assert.Len(s.T(), machines, len(machineKeys))

	addTagResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"tag",
			"-i", "1",
			"-t", "tag:test",
			"--output", "json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var machine v1.Machine
	err = json.Unmarshal([]byte(addTagResult), &machine)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), []string{"tag:test"}, machine.ForcedTags)

	// try to set a wrong tag and retrieve the error
	wrongTagResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"tag",
			"-i", "2",
			"-t", "wrong-tag",
			"--output", "json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)
	type errOutput struct {
		Error string `json:"error"`
	}
	var errorOutput errOutput
	err = json.Unmarshal([]byte(wrongTagResult), &errorOutput)
	assert.Nil(s.T(), err)
	assert.Contains(s.T(), errorOutput.Error, "tag must start with the string 'tag:'")

	// Test list all nodes after added seconds
	listAllResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"list",
			"--output", "json",
		},
		[]string{},
	)
	resultMachines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(s.T(), err)
	json.Unmarshal([]byte(listAllResult), &resultMachines)
	found := false
	for _, machine := range resultMachines {
		if machine.ForcedTags != nil {
			for _, tag := range machine.ForcedTags {
				if tag == "tag:test" {
					found = true
				}
			}
		}
	}
	assert.Equal(
		s.T(),
		true,
		found,
		"should find a machine with the tag 'tag:test' in the list of machines",
	)
}

// TBD: This test under review due to correlation IDs and Node ID's in cache.
func (s *IntegrationCLITestSuite) tbdTestNodeCommand() {
	namespace, err := s.createNamespace("machine-namespace")
	assert.Nil(s.T(), err)

	secondNamespace, err := s.createNamespace("other-namespace")
	assert.Nil(s.T(), err)

	// Randomly generated machine keys
	machineKeys := []string{
		"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"nodekey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"nodekey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"nodekey:8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"nodekey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range machineKeys {
		_, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--namespace",
				namespace.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"nodes",
				"--namespace",
				namespace.Name,
				"register",
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		var machine v1.Machine
		err = json.Unmarshal([]byte(machineResult), &machine)
		assert.Nil(s.T(), err)

		machines[index] = &machine
	}

	assert.Len(s.T(), machines, len(machineKeys))

	// Test list all nodes after added seconds
	listAllResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAll []v1.Machine
	err = json.Unmarshal([]byte(listAllResult), &listAll)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listAll, 5)

	assert.Equal(s.T(), "machine-1", listAll[0].Name)
	assert.Equal(s.T(), "machine-2", listAll[1].Name)
	assert.Equal(s.T(), "machine-3", listAll[2].Name)
	assert.Equal(s.T(), "machine-4", listAll[3].Name)
	assert.Equal(s.T(), "machine-5", listAll[4].Name)

	otherNamespaceMachineKeys := []string{
		"nodekey:b5b444774186d4217adcec407563a1223929465ee2c68a4da13af0d0185b4f8e",
		"nodekey:dc721977ac7415aafa87f7d4574cbe07c6b171834a6d37375782bdc1fb6b3584",
	}
	otherNamespaceMachines := make([]*v1.Machine, len(otherNamespaceMachineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range otherNamespaceMachineKeys {
		_, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("otherNamespace-machine-%d", index+1),
				"--namespace",
				secondNamespace.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"nodes",
				"--namespace",
				secondNamespace.Name,
				"register",
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		var machine v1.Machine
		err = json.Unmarshal([]byte(machineResult), &machine)
		assert.Nil(s.T(), err)

		otherNamespaceMachines[index] = &machine
	}

	assert.Len(s.T(), otherNamespaceMachines, len(otherNamespaceMachineKeys))

	// Test list all nodes after added otherNamespace
	listAllWithotherNamespaceResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAllWithotherNamespace []v1.Machine
	err = json.Unmarshal(
		[]byte(listAllWithotherNamespaceResult),
		&listAllWithotherNamespace,
	)
	assert.Nil(s.T(), err)

	// All nodes, machines + otherNamespace
	assert.Len(s.T(), listAllWithotherNamespace, 7)

	assert.Equal(s.T(), "otherNamespace-machine-1", listAllWithotherNamespace[5].Name)
	assert.Equal(s.T(), "otherNamespace-machine-2", listAllWithotherNamespace[6].Name)

	// Test list all nodes after added otherNamespace
	listOnlyotherNamespaceMachineNamespaceResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"list",
			"--namespace",
			secondNamespace.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listOnlyotherNamespaceMachineNamespace []v1.Machine
	err = json.Unmarshal(
		[]byte(listOnlyotherNamespaceMachineNamespaceResult),
		&listOnlyotherNamespaceMachineNamespace,
	)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listOnlyotherNamespaceMachineNamespace, 2)

	assert.Equal(
		s.T(),
		"otherNamespace-machine-1",
		listOnlyotherNamespaceMachineNamespace[0].Name,
	)
	assert.Equal(
		s.T(),
		"otherNamespace-machine-2",
		listOnlyotherNamespaceMachineNamespace[1].Name,
	)

	// Delete a machines
	deleteResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"delete",
			"--identifier",
			// Delete the last added machine
			fmt.Sprintf("%s", listAll[4].MachineId),
			"--output",
			"json",
			"--force",
		},
		[]string{},
	)
	assert.NotEmpty(s.T(), deleteResult)
	assert.Nil(s.T(), err)

	// Test: list main namespace after machine is deleted
	listOnlyMachineNamespaceAfterDeleteResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"list",
			"--namespace",
			namespace.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listOnlyMachineNamespaceAfterDelete []v1.Machine
	err = json.Unmarshal(
		[]byte(listOnlyMachineNamespaceAfterDeleteResult),
		&listOnlyMachineNamespaceAfterDelete,
	)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listOnlyMachineNamespaceAfterDelete, 4)
}

func (s *IntegrationCLITestSuite) ignoreTestNodeExpireCommand() {
	namespace, err := s.createNamespace("machine-expire-namespace")
	assert.Nil(s.T(), err)

	// Randomly generated machine keys
	machineKeys := []string{
		"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"nodekey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"nodekey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"nodekey:8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"nodekey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range machineKeys {
		_, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--namespace",
				namespace.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"nodes",
				"--namespace",
				namespace.Name,
				"register",
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		var machine v1.Machine
		err = json.Unmarshal([]byte(machineResult), &machine)
		assert.Nil(s.T(), err)

		machines[index] = &machine
	}

	assert.Len(s.T(), machines, len(machineKeys))

	listAllResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAll []v1.Machine
	err = json.Unmarshal([]byte(listAllResult), &listAll)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listAll, 5)

	assert.True(s.T(), ExpirationToTime(listAll[0].Expiry).IsZero())
	assert.True(s.T(), ExpirationToTime(listAll[1].Expiry).IsZero())
	assert.True(s.T(), ExpirationToTime(listAll[2].Expiry).IsZero())
	assert.True(s.T(), ExpirationToTime(listAll[3].Expiry).IsZero())
	assert.True(s.T(), ExpirationToTime(listAll[4].Expiry).IsZero())

	for i := 0; i < 3; i++ {
		_, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"nodes",
				"expire",
				"--identifier",
				fmt.Sprintf("%s", listAll[i].MachineId),
			},
			[]string{},
		)
		assert.Nil(s.T(), err)
	}

	listAllAfterExpiryResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAllAfterExpiry []v1.Machine
	err = json.Unmarshal([]byte(listAllAfterExpiryResult), &listAllAfterExpiry)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listAllAfterExpiry, 5)

	assert.True(
		s.T(),
		ExpirationToTime(listAllAfterExpiry[0].Expiry).Before(time.Now().UTC()),
	)
	assert.True(
		s.T(),
		ExpirationToTime(listAllAfterExpiry[1].Expiry).Before(time.Now().UTC()),
	)
	assert.True(
		s.T(),
		ExpirationToTime(listAllAfterExpiry[2].Expiry).Before(time.Now().UTC()),
	)
	assert.True(s.T(), ExpirationToTime(listAllAfterExpiry[3].Expiry).IsZero())
	assert.True(s.T(), ExpirationToTime(listAllAfterExpiry[4].Expiry).IsZero())
}

// TBD: This test under review due to correlation IDs and Node ID's in cache.
func (s *IntegrationCLITestSuite) tbdTestNodeRenameCommand() {
	namespace, err := s.createNamespace("machine-rename-command")
	assert.Nil(s.T(), err)

	// Randomly generated machine keys
	machineKeys := []string{
		"nodekey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
		"nodekey:8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"nodekey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"nodekey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(s.T(), err)

	for index, machineKey := range machineKeys {
		_, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--namespace",
				namespace.Name,
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		machineResult, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"nodes",
				"--namespace",
				namespace.Name,
				"register",
				"--key",
				machineKey,
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		var machine v1.Machine
		err = json.Unmarshal([]byte(machineResult), &machine)
		assert.Nil(s.T(), err)

		machines[index] = &machine
	}

	assert.Len(s.T(), machines, len(machineKeys))

	listAllResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAll []v1.Machine
	err = json.Unmarshal([]byte(listAllResult), &listAll)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listAll, 5)

	assert.Contains(s.T(), listAll[0].GetName(), "machine-1")
	assert.Contains(s.T(), listAll[1].GetName(), "machine-2")
	assert.Contains(s.T(), listAll[2].GetName(), "machine-3")
	assert.Contains(s.T(), listAll[3].GetName(), "machine-4")
	assert.Contains(s.T(), listAll[4].GetName(), "machine-5")

	for i := 0; i < 3; i++ {
		renameOut, renameErr, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"nodes",
				"rename",
				"--identifier",
				fmt.Sprintf("%s", listAll[i].MachineId),
				fmt.Sprintf("newmachine-%d", i+1),
			},
			[]string{},
		)
		assert.NotNil(s.T(), renameOut)
		assert.NotNil(s.T(), renameErr)
		assert.Nil(s.T(), err)
	}

	listAllAfterRenameResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAllAfterRename []v1.Machine
	err = json.Unmarshal([]byte(listAllAfterRenameResult), &listAllAfterRename)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listAllAfterRename, 5)

	assert.Equal(s.T(), "newmachine-1", listAllAfterRename[0].GetGivenName())
	assert.Equal(s.T(), "newmachine-2", listAllAfterRename[1].GetGivenName())
	assert.Equal(s.T(), "newmachine-3", listAllAfterRename[2].GetGivenName())
	assert.Contains(s.T(), listAllAfterRename[3].GetGivenName(), "machine-4")
	assert.Contains(s.T(), listAllAfterRename[4].GetGivenName(), "machine-5")

	// Test failure for too long names
	result, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"rename",
			"--identifier",
			fmt.Sprintf("%s", listAll[4].MachineId),
			"testmbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbchine12345678901234567890",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)
	assert.Contains(s.T(), result, "not be over 63 chars")

	listAllAfterRenameAttemptResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listAllAfterRenameAttempt []v1.Machine
	err = json.Unmarshal(
		[]byte(listAllAfterRenameAttemptResult),
		&listAllAfterRenameAttempt,
	)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listAllAfterRenameAttempt, 5)

	assert.Equal(s.T(), "newmachine-1", listAllAfterRenameAttempt[0].GetGivenName())
	assert.Equal(s.T(), "newmachine-2", listAllAfterRenameAttempt[1].GetGivenName())
	assert.Equal(s.T(), "newmachine-3", listAllAfterRenameAttempt[2].GetGivenName())
	assert.Contains(s.T(), listAllAfterRenameAttempt[3].GetGivenName(), "machine-4")
	assert.Contains(s.T(), listAllAfterRenameAttempt[4].GetGivenName(), "machine-5")
}

func (s *IntegrationCLITestSuite) TestApiKeyCommand() {
	count := 5

	keys := make([]string, count)

	for i := 0; i < count; i++ {
		apiResult, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"apikeys",
				"create",
				"--expiration",
				"24h",
				"--output",
				"json",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)
		assert.NotEmpty(s.T(), apiResult)

		// var apiKey v1.ApiKey
		// err = json.Unmarshal([]byte(apiResult), &apiKey)
		// assert.Nil(s.T(), err)

		keys[i] = apiResult
	}

	assert.Len(s.T(), keys, 5)

	// Test list of keys
	listResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"apikeys",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedApiKeys []v1.ApiKey
	err = json.Unmarshal([]byte(listResult), &listedApiKeys)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), listedApiKeys, 5)

	assert.NotEmpty(s.T(), listedApiKeys[0].ApikeyId)
	assert.NotEmpty(s.T(), listedApiKeys[1].ApikeyId)
	assert.NotEmpty(s.T(), listedApiKeys[2].ApikeyId)
	assert.NotEmpty(s.T(), listedApiKeys[3].ApikeyId)
	assert.NotEmpty(s.T(), listedApiKeys[4].ApikeyId)

	assert.NotEmpty(s.T(), listedApiKeys[0].Prefix)
	assert.NotEmpty(s.T(), listedApiKeys[1].Prefix)
	assert.NotEmpty(s.T(), listedApiKeys[2].Prefix)
	assert.NotEmpty(s.T(), listedApiKeys[3].Prefix)
	assert.NotEmpty(s.T(), listedApiKeys[4].Prefix)

	for _, key := range listedApiKeys {
		expirationTime := ExpirationToTime(key.Expiration)
		assert.True(
			s.T(),
			expirationTime.After(time.Now().UTC()),
			"Expiration key not after now",
		)
		assert.True(
			s.T(),
			expirationTime.Before(
				time.Now().UTC().Add(time.Hour*26),
			),
			"Expiration is before 26 hours",
		)

	}

	expiredPrefixes := make(map[string]bool)

	// Expire three keys
	for i := 0; i < 3; i++ {
		_, _, err := ExecuteCommand(
			&s.ninjapanda,
			[]string{
				"ninjapanda",
				"apikeys",
				"expire",
				"--prefix",
				listedApiKeys[i].Prefix,
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		expiredPrefixes[listedApiKeys[i].Prefix] = true
	}

	// Test list pre auth keys after expire
	listAfterExpireResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"apikeys",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var listedAfterExpireApiKeys []v1.ApiKey
	err = json.Unmarshal([]byte(listAfterExpireResult), &listedAfterExpireApiKeys)
	assert.Nil(s.T(), err)

	for index := range listedAfterExpireApiKeys {
		if _, ok := expiredPrefixes[listedAfterExpireApiKeys[index].Prefix]; ok {
			// Expired
			assert.True(
				s.T(),
				ExpirationToTime(
					listedAfterExpireApiKeys[index].Expiration,
				).Before(time.Now().UTC()),
			)
		} else {
			// Not expired
			assert.False(
				s.T(),
				ExpirationToTime(listedAfterExpireApiKeys[index].Expiration).Before(time.Now().UTC()),
			)
		}
	}
}

// TBD: Based on current circumstances this test needs to be re-evaluated.
func (s *IntegrationCLITestSuite) tbdTestNodeMoveCommand() {
	oldNamespace, err := s.createNamespace("old-namespace")
	assert.Nil(s.T(), err)
	newNamespace, err := s.createNamespace("new-namespace")
	assert.Nil(s.T(), err)

	// Randomly generated machine key
	machineKey := "nodekey:688411b767663479632d44140f08a9fde87383adc7cdeb518f62ce28a17ef0aa"

	_, _, err = ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"debug",
			"create-node",
			"--name",
			"nomad-machine",
			"--namespace",
			oldNamespace.Name,
			"--key",
			machineKey,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	machineResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"--namespace",
			oldNamespace.Name,
			"register",
			"--key",
			machineKey,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var machine v1.Machine
	err = json.Unmarshal([]byte(machineResult), &machine)
	assert.Nil(s.T(), err)
	assert.NotEmpty(s.T(), machine.MachineId)
	assert.Equal(s.T(), "nomad-machine", machine.Name)
	assert.Equal(s.T(), machine.Namespace.Name, oldNamespace.Name)

	machineId := fmt.Sprintf("%s", machine.MachineId)

	moveToNewNSResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"move",
			"--identifier",
			machineId,
			"--namespace",
			newNamespace.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	err = json.Unmarshal([]byte(moveToNewNSResult), &machine)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), machine.Namespace.Name, newNamespace.Name)

	listAllNodesResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var allNodes []v1.Machine
	err = json.Unmarshal([]byte(listAllNodesResult), &allNodes)
	assert.Nil(s.T(), err)

	assert.Len(s.T(), allNodes, 1)

	assert.Equal(s.T(), allNodes[0].MachineId, machine.MachineId)
	assert.Equal(s.T(), allNodes[0].Namespace, machine.Namespace)
	assert.Equal(s.T(), allNodes[0].Namespace.Name, newNamespace.Name)

	moveToNonExistingNSResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"move",
			"--identifier",
			machineId,
			"--namespace",
			"non-existing-namespace",
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	assert.Contains(
		s.T(),
		string(moveToNonExistingNSResult),
		"Namespace not found",
	)
	assert.Equal(s.T(), machine.Namespace.Name, newNamespace.Name)

	moveToOldNSResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"move",
			"--identifier",
			machineId,
			"--namespace",
			oldNamespace.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	err = json.Unmarshal([]byte(moveToOldNSResult), &machine)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), machine.Namespace.Name, oldNamespace.Name)

	moveToSameNSResult, _, err := ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"move",
			"--identifier",
			machineId,
			"--namespace",
			oldNamespace.Name,
			"--output",
			"json",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	err = json.Unmarshal([]byte(moveToSameNSResult), &machine)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), machine.Namespace.Name, oldNamespace.Name)
}

func (s *IntegrationCLITestSuite) ignoreTestLoadConfigFromCommand() {
	// TODO: make sure defaultConfig is not same as altConfig
	defaultConfig, err := os.ReadFile("../integration_test/etc/config.dump.gold.yaml")
	assert.Nil(s.T(), err)
	altConfig, err := os.ReadFile("../integration_test/etc/alt-config.dump.gold.yaml")
	assert.Nil(s.T(), err)
	altEnvConfig, err := os.ReadFile(
		"../integration_test/etc/alt-env-config.dump.gold.yaml",
	)
	assert.Nil(s.T(), err)

	_, _, err = ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"dumpConfig",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	defaultDumpConfig, err := os.ReadFile("../integration_test/etc/config.dump.yaml")
	assert.Nil(s.T(), err)

	assert.YAMLEq(s.T(), string(defaultConfig), string(defaultDumpConfig))

	_, _, err = ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"-c",
			"/etc/ninjapanda/alt-config.yaml",
			"dumpConfig",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	altDumpConfig, err := os.ReadFile("../integration_test/etc/config.dump.yaml")
	assert.Nil(s.T(), err)

	assert.YAMLEq(s.T(), string(altConfig), string(altDumpConfig))

	_, _, err = ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"dumpConfig",
		},
		[]string{
			"NINJAPANDA_CONFIG=/etc/ninjapanda/alt-env-config.yaml",
		},
	)
	assert.Nil(s.T(), err)

	altEnvDumpConfig, err := os.ReadFile("../integration_test/etc/config.dump.yaml")
	assert.Nil(s.T(), err)

	assert.YAMLEq(s.T(), string(altEnvConfig), string(altEnvDumpConfig))

	_, _, err = ExecuteCommand(
		&s.ninjapanda,
		[]string{
			"ninjapanda",
			"-c",
			"/etc/ninjapanda/alt-config.yaml",
			"dumpConfig",
		},
		[]string{
			"NINJAPANDA_CONFIG=/etc/ninjapanda/alt-env-config.yaml",
		},
	)
	assert.Nil(s.T(), err)

	altDumpConfig, err = os.ReadFile("../integration_test/etc/config.dump.yaml")
	assert.Nil(s.T(), err)

	assert.YAMLEq(s.T(), string(altConfig), string(altDumpConfig))
}
