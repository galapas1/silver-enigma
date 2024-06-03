package hsic

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/ory/dockertest/v3"

	"optm.com/ninja-panda/integration/dockertestutil"
	"optm.com/ninja-panda/integration/integrationutil"
	"optm.com/ninja-panda/src"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

const (
	hsicHashLength        = 6
	dockerContextPath     = "../."
	aclPolicyPath         = "/etc/ninjapanda/acl.json"
	tlsCertPath           = "/etc/ninjapanda/tls.cert"
	tlsKeyPath            = "/etc/ninjapanda/tls.key"
	ninjapandaDefaultPort = 8080
)

var errNinjapandaStatusCodeNotOk = errors.New("ninjapanda status code not ok")

type fileInContainer struct {
	path     string
	contents []byte
}

type NinjapandaInContainer struct {
	hostname string

	pool      *dockertest.Pool
	container *dockertest.Resource
	network   *dockertest.Network

	// optional config
	port             int
	aclPolicy        *ninjapanda.ACLPolicy
	env              map[string]string
	tlsCert          []byte
	tlsKey           []byte
	filesInContainer []fileInContainer
}

type Option = func(c *NinjapandaInContainer)

func WithACLPolicy(acl *ninjapanda.ACLPolicy) Option {
	return func(hsic *NinjapandaInContainer) {
		// TODO: Move somewhere appropriate
		hsic.env["NINJAPANDA_ACL_POLICY_PATH"] = aclPolicyPath

		hsic.aclPolicy = acl
	}
}

func WithTLS() Option {
	return func(hsic *NinjapandaInContainer) {
		cert, key, err := createCertificate()
		if err != nil {
			log.Fatalf("failed to create certificates for ninjapanda test: %s", err)
		}

		// TODO: Move somewhere appropriate
		hsic.env["NINJAPANDA_TLS_CERT_PATH"] = tlsCertPath
		hsic.env["NINJAPANDA_TLS_KEY_PATH"] = tlsKeyPath

		hsic.tlsCert = cert
		hsic.tlsKey = key
	}
}

func WithConfigEnv(configEnv map[string]string) Option {
	return func(hsic *NinjapandaInContainer) {
		for key, value := range configEnv {
			hsic.env[key] = value
		}
	}
}

func WithPort(port int) Option {
	return func(hsic *NinjapandaInContainer) {
		hsic.port = port
	}
}

func WithTestName(testName string) Option {
	return func(hsic *NinjapandaInContainer) {
		hash, _ := ninjapanda.GenerateRandomStringDNSSafe(hsicHashLength)

		hostname := fmt.Sprintf("np-%s-%s", testName, hash)
		hsic.hostname = hostname
	}
}

func WithHostnameAsServerURL() Option {
	return func(hsic *NinjapandaInContainer) {
		hsic.env["NINJAPANDA_SERVER_URL"] = fmt.Sprintf("http://%s",
			net.JoinHostPort(hsic.GetHostname(),
				fmt.Sprintf("%d", hsic.port)),
		)
	}
}

func WithFileInContainer(path string, contents []byte) Option {
	return func(hsic *NinjapandaInContainer) {
		hsic.filesInContainer = append(hsic.filesInContainer,
			fileInContainer{
				path:     path,
				contents: contents,
			})
	}
}

func New(
	pool *dockertest.Pool,
	network *dockertest.Network,
	opts ...Option,
) (*NinjapandaInContainer, error) {
	hash, err := ninjapanda.GenerateRandomStringDNSSafe(hsicHashLength)
	if err != nil {
		return nil, err
	}

	hostname := fmt.Sprintf("np-%s", hash)

	hsic := &NinjapandaInContainer{
		hostname: hostname,
		port:     ninjapandaDefaultPort,

		pool:    pool,
		network: network,

		env:              DefaultConfigEnv(),
		filesInContainer: []fileInContainer{},
	}

	for _, opt := range opts {
		opt(hsic)
	}

	log.Println("NAME: ", hsic.hostname)

	portProto := fmt.Sprintf("%d/tcp", hsic.port)

	ninjapandaBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile.debug",
		ContextDir: dockerContextPath,
	}

	env := []string{}
	for key, value := range hsic.env {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	log.Printf("ENV: \n%s", spew.Sdump(hsic.env))

	runOptions := &dockertest.RunOptions{
		Name:         hsic.hostname,
		ExposedPorts: []string{portProto},
		Networks:     []*dockertest.Network{network},
		// Cmd:          []string{"ninjapanda", "serve"},
		// TODO: Get rid of this hack, we currently need to give us some
		// to inject the ninjapanda configuration further down.
		Entrypoint: []string{"/bin/bash", "-c", "/bin/sleep 3 ; ninjapanda serve"},
		Env:        env,
	}

	// dockertest isnt very good at handling containers that has already
	// been created, this is an attempt to make sure this container isnt
	// present.
	err = pool.RemoveContainerByName(hsic.hostname)
	if err != nil {
		return nil, err
	}

	container, err := pool.BuildAndRunWithBuildOptions(
		ninjapandaBuildOptions,
		runOptions,
		dockertestutil.DockerRestartPolicy,
		dockertestutil.DockerAllowLocalIPv6,
		dockertestutil.DockerAllowNetworkAdministration,
	)
	if err != nil {
		return nil, fmt.Errorf("could not start ninjapanda container: %w", err)
	}
	log.Printf("Created %s container\n", hsic.hostname)

	hsic.container = container

	err = hsic.WriteFile("/etc/ninjapanda/config.yaml", []byte(MinimumConfigYAML()))
	if err != nil {
		return nil, fmt.Errorf(
			"failed to write ninjapanda config to container: %w",
			err,
		)
	}

	if hsic.aclPolicy != nil {
		data, err := json.Marshal(hsic.aclPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ACL Policy to JSON: %w", err)
		}

		err = hsic.WriteFile(aclPolicyPath, data)
		if err != nil {
			return nil, fmt.Errorf("failed to write ACL policy to container: %w", err)
		}
	}

	if hsic.hasTLS() {
		err = hsic.WriteFile(tlsCertPath, hsic.tlsCert)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to write TLS certificate to container: %w",
				err,
			)
		}

		err = hsic.WriteFile(tlsKeyPath, hsic.tlsKey)
		if err != nil {
			return nil, fmt.Errorf("failed to write TLS key to container: %w", err)
		}
	}

	for _, f := range hsic.filesInContainer {
		if err := hsic.WriteFile(f.path, f.contents); err != nil {
			return nil, fmt.Errorf("failed to write %q: %w", f.path, err)
		}
	}

	return hsic, nil
}

func (t *NinjapandaInContainer) hasTLS() bool {
	return len(t.tlsCert) != 0 && len(t.tlsKey) != 0
}

func (t *NinjapandaInContainer) Shutdown() error {
	return t.pool.Purge(t.container)
}

func (t *NinjapandaInContainer) Execute(
	command []string,
) (string, error) {
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

		return "", err
	}

	return stdout, nil
}

func (t *NinjapandaInContainer) GetIP() string {
	return t.container.GetIPInNetwork(t.network)
}

func (t *NinjapandaInContainer) GetPort() string {
	return fmt.Sprintf("%d", t.port)
}

func (t *NinjapandaInContainer) GetHealthEndpoint() string {
	return fmt.Sprintf("%s/health", t.GetEndpoint())
}

func (t *NinjapandaInContainer) GetEndpoint() string {
	hostEndpoint := fmt.Sprintf("%s:%d",
		t.GetIP(),
		t.port)

	if t.hasTLS() {
		return fmt.Sprintf("https://%s", hostEndpoint)
	}

	return fmt.Sprintf("http://%s", hostEndpoint)
}

func (t *NinjapandaInContainer) GetCert() []byte {
	return t.tlsCert
}

func (t *NinjapandaInContainer) GetHostname() string {
	return t.hostname
}

func (t *NinjapandaInContainer) WaitForReady() error {
	url := t.GetHealthEndpoint()

	log.Printf("waiting for ninjapanda to be ready at %s", url)

	client := &http.Client{}

	if t.hasTLS() {
		insecureTransport := http.DefaultTransport.(*http.Transport).Clone() //nolint
		insecureTransport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		} //nolint
		client = &http.Client{Transport: insecureTransport}
	}

	return t.pool.Retry(func() error {
		resp, err := client.Get(url) //nolint
		if err != nil {
			return fmt.Errorf("ninjapanda is not ready: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return errNinjapandaStatusCodeNotOk
		}

		return nil
	})
}

func (t *NinjapandaInContainer) CreateNamespace(
	namespace string,
) error {
	command := []string{"ninjapanda", "namespaces", "create", namespace}

	_, _, err := dockertestutil.ExecuteCommand(
		t.container,
		command,
		[]string{},
	)
	if err != nil {
		return err
	}

	return nil
}

func (t *NinjapandaInContainer) CreateAuthKey(
	namespace string,
	reusable bool,
	ephemeral bool,
) (*v1.PreAuthKey, error) {
	command := []string{
		"ninjapanda",
		"--namespace",
		namespace,
		"preauthkeys",
		"create",
		"--expiration",
		"24h",
		"--output",
		"json",
	}

	if reusable {
		command = append(command, "--reusable")
	}

	if ephemeral {
		command = append(command, "--ephemeral")
	}

	result, _, err := dockertestutil.ExecuteCommand(
		t.container,
		command,
		[]string{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute create auth key command: %w", err)
	}

	var preAuthKey v1.PreAuthKey
	err = json.Unmarshal([]byte(result), &preAuthKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth key: %w", err)
	}

	return &preAuthKey, nil
}

func (t *NinjapandaInContainer) ListMachinesInNamespace(
	namespace string,
) ([]*v1.Machine, error) {
	command := []string{
		"ninjapanda",
		"--namespace",
		namespace,
		"nodes",
		"list",
		"--output",
		"json",
	}

	result, _, err := dockertestutil.ExecuteCommand(
		t.container,
		command,
		[]string{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute list node command: %w", err)
	}

	var nodes []*v1.Machine
	err = json.Unmarshal([]byte(result), &nodes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal nodes: %w", err)
	}

	return nodes, nil
}

func (t *NinjapandaInContainer) WriteFile(path string, data []byte) error {
	return integrationutil.WriteFileToContainer(t.pool, t.container, path, data)
}

// nolint
func createCertificate() ([]byte, []byte, error) {
	// From:
	// https://shaneutt.com/blog/golang-ca-and-signed-cert-go/

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Ninjapanda testing INC"},
			Country:      []string{"NL"},
			Locality:     []string{"Leiden"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(30 * time.Minute),
		IsCA:      true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Ninjapanda testing INC"},
			Country:      []string{"NL"},
			Locality:     []string{"Leiden"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(30 * time.Minute),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		cert,
		ca,
		&certPrivKey.PublicKey,
		caPrivKey,
	)
	if err != nil {
		return nil, nil, err
	}

	certPEM := new(bytes.Buffer)

	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, nil, err
	}

	certPrivKeyPEM := new(bytes.Buffer)

	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return nil, nil, err
	}

	return certPEM.Bytes(), certPrivKeyPEM.Bytes(), nil
}
