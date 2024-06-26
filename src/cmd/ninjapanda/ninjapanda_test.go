package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"gopkg.in/check.v1"

	ninjapanda "optm.com/ninja-panda/src"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

var _ = check.Suite(&Suite{})

type Suite struct{}

func (s *Suite) SetUpSuite(c *check.C) {
}

func (s *Suite) TearDownSuite(c *check.C) {
}

func (*Suite) ignoreTestConfigFileLoading(c *check.C) {
	tmpDir, err := os.MkdirTemp("", "ninjapanda")
	if err != nil {
		c.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	path, err := os.Getwd()
	if err != nil {
		c.Fatal(err)
	}

	cfgFile := filepath.Join(tmpDir, "config.yaml")

	// Symlink the example config file
	err = os.Symlink(
		filepath.Clean(path+"/../../../config-example.yaml"),
		cfgFile,
	)
	if err != nil {
		c.Fatal(err)
	}

	// Load example config, it should load without validation errors
	err = ninjapanda.LoadConfig(cfgFile, true)
	c.Assert(err, check.IsNil)

	// Test that config file was interpreted correctly
	c.Assert(viper.GetString("server_url"), check.Equals, "http://127.0.0.1:8080")
	c.Assert(viper.GetString("listen_addr"), check.Equals, "127.0.0.1:443")
	c.Assert(viper.GetString("metrics_listen_addr"), check.Equals, "127.0.0.1:9090")
	c.Assert(viper.GetString("db_type"), check.Equals, "postgres")
	c.Assert(viper.GetString("tls_letsencrypt_hostname"), check.Equals, "")
	c.Assert(viper.GetString("tls_letsencrypt_listen"), check.Equals, ":https")
	c.Assert(viper.GetString("tls_letsencrypt_challenge_type"), check.Equals, "HTTP-01")
	c.Assert(viper.GetStringSlice("dns_config.nameservers")[0], check.Equals, "1.1.1.1")
	c.Assert(
		ninjapanda.GetFileMode("unix_socket_permission"),
		check.Equals,
		fs.FileMode(0o770),
	)
	c.Assert(viper.GetBool("ztmlog.enabled"), check.Equals, false)
}

func (*Suite) ignoreTestConfigLoading(c *check.C) {
	tmpDir, err := os.MkdirTemp("", "ninjapanda")
	if err != nil {
		c.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	path, err := os.Getwd()
	if err != nil {
		c.Fatal(err)
	}

	// Symlink the example config file
	err = os.Symlink(
		filepath.Clean(path+"/../../../config-example.yaml"),
		filepath.Join(tmpDir, "config.yaml"),
	)
	if err != nil {
		c.Fatal(err)
	}

	// Load example config, it should load without validation errors
	err = ninjapanda.LoadConfig(tmpDir, false)
	c.Assert(err, check.IsNil)

	// Test that config file was interpreted correctly
	c.Assert(viper.GetString("server_url"), check.Equals, "http://127.0.0.1:8080")
	c.Assert(viper.GetString("listen_addr"), check.Equals, "127.0.0.1:443")
	c.Assert(viper.GetString("metrics_listen_addr"), check.Equals, "127.0.0.1:9090")
	c.Assert(viper.GetString("db_type"), check.Equals, "postgres")
	c.Assert(viper.GetString("tls_letsencrypt_hostname"), check.Equals, "")
	c.Assert(viper.GetString("tls_letsencrypt_listen"), check.Equals, ":https")
	c.Assert(viper.GetString("tls_letsencrypt_challenge_type"), check.Equals, "HTTP-01")
	c.Assert(viper.GetStringSlice("dns_config.nameservers")[0], check.Equals, "1.1.1.1")
	c.Assert(
		ninjapanda.GetFileMode("unix_socket_permission"),
		check.Equals,
		fs.FileMode(0o770),
	)
	c.Assert(viper.GetBool("ztmlog.enabled"), check.Equals, false)
	c.Assert(viper.GetBool("randomize_client_port"), check.Equals, false)
}

func (*Suite) TestDNSConfigLoading(c *check.C) {
	tmpDir, err := os.MkdirTemp("", "ninjapanda")
	if err != nil {
		c.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	path, err := os.Getwd()
	if err != nil {
		c.Fatal(err)
	}

	// Symlink the example config file
	err = os.Symlink(
		filepath.Clean(path+"/../../../config-example.yaml"),
		filepath.Join(tmpDir, "config.yaml"),
	)
	if err != nil {
		c.Fatal(err)
	}

	// Load example config, it should load without validation errors
	err = ninjapanda.LoadConfig(tmpDir, false)
	c.Assert(err, check.IsNil)

	dnsConfig, baseDomain := ninjapanda.GetDNSConfig()

	c.Assert(dnsConfig.Nameservers[0].String(), check.Equals, "1.1.1.1")
	c.Assert(dnsConfig.Resolvers[0].Addr, check.Equals, "1.1.1.1")
	c.Assert(dnsConfig.Proxied, check.Equals, true)
	c.Assert(baseDomain, check.Equals, "ztmesh.net")
}

func writeConfig(c *check.C, tmpDir string, configYaml []byte) {
	// Populate a custom config file
	configFile := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configFile, configYaml, 0o600)
	if err != nil {
		c.Fatalf("Couldn't write file %s", configFile)
	}
}

func (*Suite) TestTLSConfigValidation(c *check.C) {
	tmpDir, err := os.MkdirTemp("", "ninjapanda")
	if err != nil {
		c.Fatal(err)
	}
	// defer os.RemoveAll(tmpDir)
	configYaml := []byte(`---
tls_letsencrypt_hostname: example.com
tls_letsencrypt_challenge_type: ""
tls_cert_path: abc.pem
noise:
  private_key_path: noise_private.key`)
	writeConfig(c, tmpDir, configYaml)

	// Check configuration validation errors (1)
	err = ninjapanda.LoadConfig(tmpDir, false)
	c.Assert(err, check.NotNil)
	// check.Matches can not handle multiline strings
	tmp := strings.ReplaceAll(err.Error(), "\n", "***")
	c.Assert(
		tmp,
		check.Matches,
		".*Fatal config error: set either tls_letsencrypt_hostname or tls_cert_path/tls_key_path, not both.*",
	)
	c.Assert(
		tmp,
		check.Matches,
		".*Fatal config error: the only supported values for tls_letsencrypt_challenge_type are.*",
	)
	c.Assert(
		tmp,
		check.Matches,
		".*Fatal config error: server_url must start with https:// or http://.*",
	)

	// Check configuration validation errors (2)
	configYaml = []byte(`---
noise:
  private_key_path: noise_private.key
server_url: http://127.0.0.1:8080
tls_letsencrypt_hostname: example.com
tls_letsencrypt_challenge_type: TLS-ALPN-01
`)
	writeConfig(c, tmpDir, configYaml)
	err = ninjapanda.LoadConfig(tmpDir, false)
	c.Assert(err, check.IsNil)
}
