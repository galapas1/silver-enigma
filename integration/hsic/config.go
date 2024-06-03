package hsic

func DefaultConfigYAML() string {
	yaml := `
log:
  level: trace
acl_policy_path: ""
db_type: sqlite3
db_path: /tmp/integration_test_db.sqlite3
ephemeral_node_inactivity_timeout: 30m
node_update_check_interval: 10s
ip_prefixes:
  - fd7a:115c:a1e0::/48
  - 100.64.0.0/10
dns_config:
  base_domain: ninjapanda.net
  magic_dns: true
  domains: []
  nameservers:
    - 127.0.0.11
    - 1.1.1.1
private_key_path: /tmp/private.key
noise:
  private_key_path: /tmp/noise_private.key
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 127.0.0.1:9090
server_url: http://ninjapanda:8080

relay.
  urls:
    - https://controlplane.client.com/relaymap/default
  auto_update_enabled: false
  update_frequency: 1m
`

	return yaml
}

func MinimumConfigYAML() string {
	return `
private_key_path: /tmp/private.key
noise:
  private_key_path: /tmp/noise_private.key
`
}

func DefaultConfigEnv() map[string]string {
	return map[string]string{
		"NINJAPANDA_LOG_LEVEL":                         "trace",
		"NINJAPANDA_ACL_POLICY_PATH":                   "",
		"NINJAPANDA_DB_TYPE":                           "sqlite3",
		"NINJAPANDA_DB_PATH":                           "/tmp/integration_test_db.sqlite3",
		"NINJAPANDA_EPHEMERAL_NODE_INACTIVITY_TIMEOUT": "30m",
		"NINJAPANDA_NODE_UPDATE_CHECK_INTERVAL":        "10s",
		"NINJAPANDA_IP_PREFIXES":                       "fd7a:115c:a1e0::/48 100.64.0.0/10",
		"NINJAPANDA_DNS_CONFIG_BASE_DOMAIN":            "ninjapanda.net",
		"NINJAPANDA_DNS_CONFIG_MAGIC_DNS":              "true",
		"NINJAPANDA_DNS_CONFIG_DOMAINS":                "",
		"NINJAPANDA_DNS_CONFIG_NAMESERVERS":            "127.0.0.11 1.1.1.1",
		"NINJAPANDA_PRIVATE_KEY_PATH":                  "/tmp/private.key",
		"NINJAPANDA_NOISE_PRIVATE_KEY_PATH":            "/tmp/noise_private.key",
		"NINJAPANDA_LISTEN_ADDR":                       "0.0.0.0:8080",
		"NINJAPANDA_METRICS_LISTEN_ADDR":               "127.0.0.1:9090",
		"NINJAPANDA_SERVER_URL":                        "http://ninjapanda:8080",
		"NINJAPANDA_RELAY_URLS":                        "https://controlplane.client.com/relaymap/default",
		"NINJAPANDA_RELAY_AUTO_UPDATE_ENABLED":         "false",
		"NINJAPANDA_RELAY_UPDATE_FREQUENCY":            "1m",
	}
}
