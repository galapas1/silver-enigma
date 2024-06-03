// nolint
package ninjapanda

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

const (
	ninjapandaNetwork      = "ninjapanda-test"
	ninjapandaHostname     = "ninjapanda"
	postgresHostname       = "postgres"
	DOCKER_EXECUTE_TIMEOUT = 10 * time.Second
)

var (
	errEnvVarEmpty = errors.New("getenv: environment variable empty")

	IpPrefix4 = netip.MustParsePrefix("100.64.0.0/10")
	IpPrefix6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")

	clientVersions = []string{
		"head",
	}
)

type TestNamespace struct {
	count   int
	clients map[string]dockertest.Resource
}

type ExecuteCommandConfig struct {
	timeout time.Duration
}

type ExecuteCommandOption func(*ExecuteCommandConfig) error

func ExecuteCommandTimeout(timeout time.Duration) ExecuteCommandOption {
	return ExecuteCommandOption(func(conf *ExecuteCommandConfig) error {
		conf.timeout = timeout
		return nil
	})
}

func CreatePostgresDatabase(
	pool *dockertest.Pool,
	network *dockertest.Network,
) (*dockertest.Resource, error) {
	pool.RemoveContainerByName(postgresHostname)

	postgresDatabaseOptions := &dockertest.RunOptions{
		Repository:   "postgres",
		Tag:          "14-alpine",
		Name:         postgresHostname,
		Hostname:     postgresHostname,
		Networks:     []*dockertest.Network{network},
		ExposedPorts: []string{"5432/tcp"},
		Env:          []string{"POSTGRES_PASSWORD=ninjapanda"},
	}

	postgresDb, err := pool.RunWithOptions(postgresDatabaseOptions, DockerRestartPolicy)
	if err != nil {
		return nil, err
	}
	dbString := "CREATE DATABASE ninjapanda;\nCREATE ROLE ninjaadmin WITH LOGIN PASSWORD 'n1nj@@dm1n';\nALTER ROLE ninjaadmin CREATEDB;"
	myReader := strings.NewReader(dbString)
	time.Sleep(2 * time.Second)
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	_, err = postgresDb.Exec([]string{"psql", "-U", "postgres"}, dockertest.ExecOptions{
		Env:    nil,
		StdIn:  myReader,
		StdOut: &stdout,
		StdErr: &stderr,
		TTY:    false,
	})
	// fmt.Printf("Code=%d, Error=%s\nStdout=%s\nStderr=%s\n", code, err, stdout.String(), stderr.String())
	// fmt.Println(postgresDb.Container.Name)
	return postgresDb, nil
}

func ExecuteCommand(
	resource *dockertest.Resource,
	cmd []string,
	env []string,
	options ...ExecuteCommandOption,
) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	execConfig := ExecuteCommandConfig{
		timeout: DOCKER_EXECUTE_TIMEOUT,
	}

	for _, opt := range options {
		if err := opt(&execConfig); err != nil {
			return "", "", fmt.Errorf("execute-command/options: %w", err)
		}
	}

	type result struct {
		exitCode int
		err      error
	}

	resultChan := make(chan result, 1)

	// Run your long running function in it's own goroutine and pass back it's
	// response into our channel.
	go func() {
		exitCode, err := resource.Exec(
			cmd,
			dockertest.ExecOptions{
				Env:    append(env, "NINJAPANDA_LOG_LEVEL=disabled"),
				StdOut: &stdout,
				StdErr: &stderr,
			},
		)
		resultChan <- result{exitCode, err}
	}()

	// Listen on our channel AND a timeout channel - which ever happens first.
	select {
	case res := <-resultChan:
		if res.err != nil {
			return stdout.String(), stderr.String(), res.err
		}

		if res.exitCode != 0 {
			fmt.Println("Command: ", cmd)
			fmt.Println("stdout: ", stdout.String())
			fmt.Println("stderr: ", stderr.String())

			return stdout.String(), stderr.String(), fmt.Errorf(
				"command failed with: %s",
				stderr.String(),
			)
		}

		return stdout.String(), stderr.String(), nil
	case <-time.After(execConfig.timeout):

		return stdout.String(), stderr.String(), fmt.Errorf(
			"command timed out after %s",
			execConfig.timeout,
		)
	}
}

func DockerRestartPolicy(config *docker.HostConfig) {
	// set AutoRemove to true so that stopped container goes away by itself on error *immediately*.
	// when set to false, containers remain until the end of the integration test.
	config.AutoRemove = false
	config.RestartPolicy = docker.RestartPolicy{
		Name: "no",
	}
}

func DockerAllowLocalIPv6(config *docker.HostConfig) {
	if config.Sysctls == nil {
		config.Sysctls = make(map[string]string, 1)
	}
	config.Sysctls["net.ipv6.conf.all.disable_ipv6"] = "0"
}

func DockerAllowNetworkAdministration(config *docker.HostConfig) {
	config.CapAdd = append(config.CapAdd, "NET_ADMIN")
	config.Mounts = append(config.Mounts, docker.HostMount{
		Type:   "bind",
		Source: "/dev/net/tun",
		Target: "/dev/net/tun",
	})
}

func getDockerBuildOptions(version string) *dockertest.BuildOptions {
	var buildOptions *dockertest.BuildOptions
	switch version {
	case "head":
		buildOptions = &dockertest.BuildOptions{
			Dockerfile: "Dockerfile.client-HEAD",
			ContextDir: "..",
			BuildArgs:  []docker.BuildArg{},
		}
	case "unstable":
		buildOptions = &dockertest.BuildOptions{
			Dockerfile: "Dockerfile.client",
			ContextDir: "..",
			BuildArgs: []docker.BuildArg{
				{
					Name:  "NINJAPANDA_VERSION",
					Value: "*",
				},
				{
					Name:  "NINJAPANDA_CHANNEL",
					Value: "unstable",
				},
			},
		}
	default:
		buildOptions = &dockertest.BuildOptions{
			Dockerfile: "Dockerfile.client",
			ContextDir: "..",
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
	return buildOptions
}

func getDNSNames(
	ninjapanda *dockertest.Resource,
) ([]string, error) {
	listAllResult, _, err := ExecuteCommand(
		ninjapanda,
		[]string{
			"ninjapanda",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	if err != nil {
		return nil, err
	}

	var listAll []v1.Machine
	err = json.Unmarshal([]byte(listAllResult), &listAll)
	if err != nil {
		return nil, err
	}

	hostnames := make([]string, len(listAll))

	for index := range listAll {
		hostnames[index] = listAll[index].GetGivenName()
	}

	return hostnames, nil
}

func GetEnvStr(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return v, errEnvVarEmpty
	}

	return v, nil
}

func GetEnvBool(key string) (bool, error) {
	s, err := GetEnvStr(key)
	if err != nil {
		return false, err
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		return false, err
	}

	return v, nil
}

func GetFirstOrCreateNetwork(
	pool *dockertest.Pool,
	name string,
) (dockertest.Network, error) {
	networks, err := pool.NetworksByName(name)
	if err != nil || len(networks) == 0 {
		if _, err = pool.CreateNetwork(name); err == nil {
			// Create does not give us an updated version of the resource, so we need to
			// get it again.
			networks, err = pool.NetworksByName(name)
			if err != nil || len(networks) == 0 {
				return dockertest.Network{}, err
			}
		}
	}

	if err != nil || len(networks) == 0 {
		fmt.Printf("Make sure docker is running!!!")
		return dockertest.Network{}, err
	}

	return networks[0], nil
}

func ExpirationToTime(exp *string) time.Time {
	layout := time.RFC3339Nano
	t, err := time.Parse(layout, *exp)
	if err != nil {
		return time.Time{}
	}
	return t
}
