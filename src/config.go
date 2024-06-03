package ninjapanda

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"go4.org/netipx"

	"github.com/Optm-Main/ztmesh-core/types/dnstype"
	"github.com/Optm-Main/ztmesh-core/ztcfg"
	awsmsk "optm.com/ninja-panda/src/internal/awsmsk"
)

const (
	tlsALPN01ChallengeType = "TLS-ALPN-01"
	http01ChallengeType    = "HTTP-01"

	JSONLogFormat = "json"
	TextLogFormat = "text"

	dbPrivateKeyPath      = "/db/pvt_key"
	dbNoisePrivateKeyPath = "/db/pvt_noise_key"
)

var errOidcMutuallyExclusive = errors.New(
	"oidc_client_secret and oidc_client_secret_path are mutually exclusive",
)

// Config contains the initial Ninjapanda configuration.
type Config struct {
	ServerURL                      string `mapstructure:"NINJA_SERVER_URL"`
	Addr                           string
	MetricsAddr                    string
	GRPCAddr                       string
	GRPCAllowInsecure              bool
	EphemeralNodeInactivityTimeout time.Duration
	NodeUpdateCheckInterval        time.Duration
	GeocodingEnabled               bool
	NameCollisionEnabled           bool `mapstructure:"NAME_COLLISION_ENABLED"`
	IPPrefixes                     []netip.Prefix
	PrivateKeyPath                 string
	NoisePrivateKeyPath            string
	BaseDomain                     string
	Log                            LogConfig
	DisableUpdateCheck             bool

	Kafka KafkaConfig
	RELAY RELAYConfig

	IVRegion     string
	IVLedgerName string

	DBtype string `mapstructure:"NINJA_DB_TYPE"`
	DBpath string `mapstructure:"NINJA_DB_PATH"`
	DBhost string `mapstructure:"NINJA_DB_HOST"`
	DBport int    `mapstructure:"NINJA_DB_PORT"`
	DBname string `mapstructure:"NINJA_DB_NAME"`
	DBuser string `mapstructure:"NINJA_DB_USER"`
	DBpass string `mapstructure:"NINJA_DB_PASS"`
	DBssl  string `mapstructure:"NINJA_DB_SSL"`

	LicenseServer           string `mapstructure:"NINJA_LICENSE_SERVER"`
	MachineAuthorizationURL string `mapstructure:"NINJA_MACHINE_AUTH_URL"`

	OtelServiceName      string `mapstructure:"NINJA_OTEL_SERVICE_NAME"`
	OtelSdkDisabled      bool   `mapstructure:"NINJA_OTEL_SDK_DISABLED"`
	OtelExporterEndpoint string `mapstructure:"NINJA_OTEL_EXPORTER_OTLP_ENDPOINT"`

	RelayUrls string `mapstructure:NINJA_RELAY_FILE_URLS"`

	TLS TLSConfig

	ACMEURL   string
	ACMEEmail string

	DNSConfig *ztcfg.DNSConfig

	UnixSocket           string
	UnixSocketPermission fs.FileMode

	OIDC OIDCConfig

	ZtmLog              ZtmLogConfig
	RandomizeClientPort bool

	Cache CacheConfig

	CLI CLIConfig

	ACL ACLConfig

	KeySigning          KeySigningConfig
	ClientPollQueueSize int `mapstructure:"CLIENT_POLL_QUEUE_SIZE"`
}

type TLSConfig struct {
	CertPath string
	KeyPath  string

	LetsEncrypt LetsEncryptConfig
}

type LetsEncryptConfig struct {
	Listen        string
	Hostname      string
	CacheDir      string
	ChallengeType string
}

type OIDCConfig struct {
	OnlyStartIfOIDCIsAvailable bool
	Issuer                     string
	ClientID                   string
	ClientSecret               string
	Scope                      []string
	ExtraParams                map[string]string
	AllowedDomains             []string
	AllowedUsers               []string
	AllowedGroups              []string
	StripEmaildomain           bool
}

type RELAYConfig struct {
	ServerEnabled    bool
	ServerRegionID   int
	ServerRegionCode string
	ServerRegionName string
	STUNAddr         string
	URLs             []url.URL
	Paths            []string
	AutoUpdate       bool
	UpdateFrequency  time.Duration
}

type ZtmLogConfig struct {
	Enabled bool
}

type CLIConfig struct {
	Address  string
	APIKey   string
	Timeout  time.Duration
	Insecure bool
}

type ACLConfig struct {
	PolicyPath string
}

type LogConfig struct {
	Format string
	Level  zerolog.Level
}

type KeySigningConfig struct {
	KeyServerUrl string
}

type CacheConfig struct {
	CacheType       string
	Addr            string
	Password        string
	MaxRetries      int
	ConnMaxIdleTime time.Duration
	PoolSize        int
	MinIdleConns    int
}

func LoadConfig(path string, isFile bool) error {
	if isFile {
		viper.SetConfigFile(path)
	} else {
		viper.SetConfigName("config")
		if path == "" {
			viper.AddConfigPath("/etc/ninjapanda/")
			viper.AddConfigPath("$HOME/.ninjapanda")
			viper.AddConfigPath(".")
		} else {
			// For testing
			viper.AddConfigPath(path)
		}
	}

	viper.SetEnvPrefix("NINJA")

	viper.SetDefault("name_collision_enabled", true)
	viper.BindEnv("NAME_COLLISION_ENABLED")

	viper.SetDefault("client_poll_queue_size", 3)
	viper.BindEnv("CLIENT_POLL_QUEUE_SIZE") // test this!

	viper.BindEnv("SERVER_URL")
	viper.BindEnv("DB_TYPE")
	viper.BindEnv("DB_PATH")
	viper.BindEnv("DB_HOST")
	viper.BindEnv("DB_PORT")
	viper.BindEnv("DB_NAME")
	viper.BindEnv("DB_USER")
	viper.BindEnv("DB_PASS")
	viper.BindEnv("DB_SSL")

	viper.BindEnv("LICENSE_SERVER_URL")
	viper.BindEnv("MACHINE_AUTH_URL")

	viper.BindEnv("alternate_relay_file_urls", "NINJA_RELAY_FILE_URLS")

	viper.BindEnv("otel.service_name", "NINJA_OTEL_SERVICE_NAME")
	viper.BindEnv("otel.sdk_disabled", "NINJA_OTEL_SDK_DISABLED")
	viper.BindEnv("otel.exporter_endpoint", "NINJA_OTEL_EXPORTER_OTLP_ENDPOINT")

	viper.SetDefault("otel.service_name", "ninjapanda")

	viper.BindEnv("kafka.update_interval", "KAFKA_UPDATE_INTERVAL")
	viper.BindEnv("kafka.broker", "KAFKA_BOOTSTRAP_SERVER")
	viper.BindEnv("kafka.enable_tls", "KAFKA_USE_TLS")
	viper.BindEnv("kafka.auth", "KAFKA_AUTH")
	viper.BindEnv("kafka.region", "KAFKA_REGION")

	viper.BindEnv("iv.region", "IV_REGION")
	viper.BindEnv("iv.ledger_name", "IV_LEDGER_NAME")

	viper.SetDefault("cache.type", "memory")
	viper.BindEnv("cache.type", "CACHE_TYPE")
	viper.BindEnv("cache.address", "CACHE_ADDRESS")
	viper.BindEnv("cache.password", "CACHE_PASSWORD")
	viper.BindEnv("cache.max_retries", "CACHE_MAX_RETRIES")
	viper.BindEnv("cache.conn_max_idle_time", "CACHE_CONN_MAX_IDLE_TIME")
	viper.BindEnv("cache.pool_size", "CACHE_POOL_SIZE")
	viper.BindEnv("cache.min_idle_conns", "CACHE_MIN_IDLE_CONNS")

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	viper.SetDefault("tls_letsencrypt_cache_dir", "/var/www/.cache")
	viper.SetDefault("tls_letsencrypt_challenge_type", http01ChallengeType)

	viper.BindEnv("log.level", "LOG_LEVEL")
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", TextLogFormat)

	viper.SetDefault("dns_config", nil)
	viper.SetDefault("dns_config.override_local_dns", true)

	viper.SetDefault("relay.server.enabled", false)
	viper.SetDefault("relay.server.stun.enabled", true)

	viper.SetDefault("unix_socket", "/var/run/ninjapanda.sock")
	viper.SetDefault("unix_socket_permission", "0o770")

	viper.SetDefault("grpc_listen_addr", ":50443")
	viper.SetDefault("grpc_allow_insecure", false)

	viper.SetDefault("cli.timeout", "5s")
	viper.SetDefault("cli.insecure", false)

	viper.SetDefault("db_ssl", false)

	viper.SetDefault("oidc.scope", []string{oidc.ScopeOpenID, "profile", "email"})
	viper.SetDefault("oidc.strip_email_domain", true)
	viper.SetDefault("oidc.only_start_if_oidc_is_available", true)

	viper.SetDefault("ztmlog.enabled", false)
	viper.SetDefault("randomize_client_port", false)

	viper.SetDefault("ephemeral_node_inactivity_timeout", "120s")

	viper.SetDefault("node_update_check_interval", "10s")

	viper.SetDefault("geocoding_enabled", true)

	viper.SetDefault("kafka.update_interval", "60s")
	viper.SetDefault("kafka.enable_tls", false)
	viper.SetDefault("kafka.auth", "none")

	if IsCLIConfigured() {
		return nil
	}

	if err := viper.ReadInConfig(); err != nil {
		log.Warn().
			Caller().
			Err(err).
			Msg("Failed to read configuration from disk")

		return fmt.Errorf("fatal error reading config file: %w", err)
	}

	// Collect any validation errors and return them all at once
	var errorText string
	if (viper.GetString("tls_letsencrypt_hostname") != "") &&
		((viper.GetString("tls_cert_path") != "") || (viper.GetString("tls_key_path") != "")) {
		errorText += "Fatal config error: set either tls_letsencrypt_hostname or tls_cert_path/tls_key_path, not both\n"
	}

	if !viper.IsSet("noise") || viper.GetString("noise.private_key_path") == "" {
		errorText += "Fatal config error: ninjapanda now requires a new `noise.private_key_path` field in the config file for the client v2 protocol\n"
	}

	if (viper.GetString("tls_letsencrypt_hostname") != "") &&
		(viper.GetString("tls_letsencrypt_challenge_type") == tlsALPN01ChallengeType) &&
		(!strings.HasSuffix(viper.GetString("listen_addr"), ":443")) {
		// this is only a warning because there could be something sitting in front of ninjapanda that redirects the traffic (e.g. an iptables rule)
		log.Warn().
			Caller().
			Str("listen_addr", viper.GetString("listen_addr")).
			Msg("Warning: when using tls_letsencrypt_hostname with TLS-ALPN-01 as challenge type, ninjapanda must be reachable on port 443, i.e. listen_addr should probably end in :443")
	}

	if (viper.GetString("tls_letsencrypt_challenge_type") != http01ChallengeType) &&
		(viper.GetString("tls_letsencrypt_challenge_type") != tlsALPN01ChallengeType) {
		errorText += "Fatal config error: the only supported values for tls_letsencrypt_challenge_type are HTTP-01 and TLS-ALPN-01\n"
	}

	if !strings.HasPrefix(viper.GetString("server_url"), "http://") &&
		!strings.HasPrefix(viper.GetString("server_url"), "https://") {
		errorText += "Fatal config error: server_url must start with https:// or http://\n"
	}

	// Minimum inactivity time out is keepalive timeout (60s) plus a few seconds
	// to avoid races
	minInactivityTimeout, _ := time.ParseDuration("65s")
	if viper.GetDuration("ephemeral_node_inactivity_timeout") <= minInactivityTimeout {
		errorText += fmt.Sprintf(
			"Fatal config error: ephemeral_node_inactivity_timeout (%s) is set too low, must be more than %s",
			viper.GetString("ephemeral_node_inactivity_timeout"),
			minInactivityTimeout,
		)
	}

	maxNodeUpdateCheckInterval, _ := time.ParseDuration("60s")
	if viper.GetDuration("node_update_check_interval") > maxNodeUpdateCheckInterval {
		errorText += fmt.Sprintf(
			"Fatal config error: node_update_check_interval (%s) is set too high, must be less than %s",
			viper.GetString("node_update_check_interval"),
			maxNodeUpdateCheckInterval,
		)
	}

	if errorText != "" {
		//nolint
		return errors.New(strings.TrimSuffix(errorText, "\n"))
	}

	return nil
}

func GetTLSConfig() TLSConfig {
	return TLSConfig{
		LetsEncrypt: LetsEncryptConfig{
			Hostname: viper.GetString("tls_letsencrypt_hostname"),
			Listen:   viper.GetString("tls_letsencrypt_listen"),
			CacheDir: AbsolutePathFromConfigPath(
				viper.GetString("tls_letsencrypt_cache_dir"),
			),
			ChallengeType: viper.GetString("tls_letsencrypt_challenge_type"),
		},
		CertPath: AbsolutePathFromConfigPath(
			viper.GetString("tls_cert_path"),
		),
		KeyPath: AbsolutePathFromConfigPath(
			viper.GetString("tls_key_path"),
		),
	}
}

func GetRELAYConfig() RELAYConfig {
	serverEnabled := viper.GetBool("relay.server.enabled")
	serverRegionID := viper.GetInt("relay.server.region_id")
	serverRegionCode := viper.GetString("relay.server.region_code")
	serverRegionName := viper.GetString("relay.server.region_name")
	stunAddr := viper.GetString("relay.server.stun_listen_addr")

	if serverEnabled && stunAddr == "" {
		log.Fatal().
			Caller().
			Msg("relay.server.stun_listen_addr must be set if relay.server.enabled is true")
	}

	var urlStrs []string
	if envRelayUrls := viper.GetString("alternate_relay_file_urls"); envRelayUrls != "" {
		urlStrs = strings.Split(envRelayUrls, ",")
	} else {
		urlStrs = viper.GetStringSlice("relay.urls")
	}

	urls := make([]url.URL, len(urlStrs))
	for index, urlStr := range urlStrs {
		urlAddr, err := url.Parse(urlStr)
		if err != nil {
			log.Error().
				Caller().
				Str(logtags.GetTag(logtags.url, ""), urlStr).
				Err(err).
				Msg("Failed to parse url, ignoring...")
		}

		urls[index] = *urlAddr
	}

	paths := viper.GetStringSlice("relay.paths")

	autoUpdate := viper.GetBool("relay.auto_update_enabled")
	updateFrequency := viper.GetDuration("relay.update_frequency")

	return RELAYConfig{
		ServerEnabled:    serverEnabled,
		ServerRegionID:   serverRegionID,
		ServerRegionCode: serverRegionCode,
		ServerRegionName: serverRegionName,
		STUNAddr:         stunAddr,
		URLs:             urls,
		Paths:            paths,
		AutoUpdate:       autoUpdate,
		UpdateFrequency:  updateFrequency,
	}
}

func GetZtmLogConfig() ZtmLogConfig {
	enabled := viper.GetBool("ztmlog.enabled")

	return ZtmLogConfig{
		Enabled: enabled,
	}
}

func GetACLConfig() ACLConfig {
	policyPath := viper.GetString("acl_policy_path")

	return ACLConfig{
		PolicyPath: policyPath,
	}
}

func GetKeySigningConfig() KeySigningConfig {
	keyServerUrl := viper.GetString("key_signing.key_server_url")

	return KeySigningConfig{
		KeyServerUrl: keyServerUrl,
	}
}

func GetLogConfig() LogConfig {
	logLevelStr := viper.GetString("log.level")
	logLevel, err := zerolog.ParseLevel(logLevelStr)
	if err != nil {
		logLevel = zerolog.DebugLevel
	}

	logFormatOpt := viper.GetString("log.format")
	var logFormat string
	switch logFormatOpt {
	case "json":
		logFormat = JSONLogFormat
	case "text":
		logFormat = TextLogFormat
	case "":
		logFormat = TextLogFormat
	default:
		log.Error().
			Caller().
			Msgf("Could not parse log format: %s. Valid choices are 'json' or 'text'", logFormatOpt)
	}

	return LogConfig{
		Format: logFormat,
		Level:  logLevel,
	}
}

func GetDNSConfig() (*ztcfg.DNSConfig, string) {
	if viper.IsSet("dns_config") {
		dnsConfig := &ztcfg.DNSConfig{}

		overrideLocalDNS := viper.GetBool("dns_config.override_local_dns")

		if viper.IsSet("dns_config.nameservers") {
			nameserversStr := viper.GetStringSlice("dns_config.nameservers")

			nameservers := []netip.Addr{}
			resolvers := []*dnstype.Resolver{}

			for _, nameserverStr := range nameserversStr {
				// Search for explicit DNS-over-HTTPS resolvers
				if strings.HasPrefix(nameserverStr, "https://") {
					resolvers = append(resolvers, &dnstype.Resolver{
						Addr: nameserverStr,
					})

					// This nameserver can not be parsed as an IP address
					continue
				}

				// Parse nameserver as a regular IP
				nameserver, err := netip.ParseAddr(nameserverStr)
				if err != nil {
					log.Error().
						Caller().
						Err(err).
						Msgf("Could not parse nameserver IP: %s", nameserverStr)
				}

				nameservers = append(nameservers, nameserver)
				resolvers = append(resolvers, &dnstype.Resolver{
					Addr: nameserver.String(),
				})
			}

			dnsConfig.Nameservers = nameservers

			if overrideLocalDNS {
				dnsConfig.Resolvers = resolvers
			} else {
				dnsConfig.FallbackResolvers = resolvers
			}
		}

		if viper.IsSet("dns_config.restricted_nameservers") {
			if len(dnsConfig.Resolvers) > 0 {
				dnsConfig.Routes = make(map[string][]*dnstype.Resolver)
				restrictedDNS := viper.GetStringMapStringSlice(
					"dns_config.restricted_nameservers",
				)
				for domain, restrictedNameservers := range restrictedDNS {
					restrictedResolvers := make(
						[]*dnstype.Resolver,
						len(restrictedNameservers),
					)
					for index, nameserverStr := range restrictedNameservers {
						nameserver, err := netip.ParseAddr(nameserverStr)
						if err != nil {
							log.Error().
								Caller().
								Err(err).
								Msgf("Could not parse restricted nameserver IP: %s", nameserverStr)
						}
						restrictedResolvers[index] = &dnstype.Resolver{
							Addr: nameserver.String(),
						}
					}
					dnsConfig.Routes[domain] = restrictedResolvers
				}
			} else {
				log.Warn().
					Caller().
					Msg("Warning: dns_config.restricted_nameservers is set, but no nameservers are configured. Ignoring restricted_nameservers.")
			}
		}

		if viper.IsSet("dns_config.domains") {
			domains := viper.GetStringSlice("dns_config.domains")
			if len(dnsConfig.Resolvers) > 0 {
				dnsConfig.Domains = domains
			} else if domains != nil {
				log.Warn().
					Caller().
					Msg("Warning: dns_config.domains is set, but no nameservers are configured. Ignoring domains.")
			}
		}

		if viper.IsSet("dns_config.extra_records") {
			var extraRecords []ztcfg.DNSRecord

			err := viper.UnmarshalKey("dns_config.extra_records", &extraRecords)
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msgf("Could not parse dns_config.extra_records")
			}

			dnsConfig.ExtraRecords = extraRecords
		}

		if viper.IsSet("dns_config.magic_dns") {
			dnsConfig.Proxied = viper.GetBool("dns_config.magic_dns")
		}

		var baseDomain string
		if viper.IsSet("dns_config.base_domain") {
			baseDomain = viper.GetString("dns_config.base_domain")
		} else {
			baseDomain = "ztmesh.net" // does not really matter when MagicDNS is not enabled
		}

		return dnsConfig, baseDomain
	}

	return nil, ""
}

func GetNinjapandaConfig() (*Config, error) {
	if IsCLIConfigured() {
		return &Config{
			CLI: CLIConfig{
				Address:  viper.GetString("cli.address"),
				APIKey:   viper.GetString("cli.api_key"),
				Timeout:  viper.GetDuration("cli.timeout"),
				Insecure: viper.GetBool("cli.insecure"),
			},
		}, nil
	}

	dnsConfig, baseDomain := GetDNSConfig()
	relayConfig := GetRELAYConfig()
	logConfig := GetZtmLogConfig()
	randomizeClientPort := viper.GetBool("randomize_client_port")

	configuredPrefixes := viper.GetStringSlice("ip_prefixes")
	parsedPrefixes := make([]netip.Prefix, 0, len(configuredPrefixes)+1)

	for i, prefixInConfig := range configuredPrefixes {
		prefix, err := netip.ParsePrefix(prefixInConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ip_prefixes[%d]: %w", i, err)
		}
		parsedPrefixes = append(parsedPrefixes, prefix)
	}

	prefixes := make([]netip.Prefix, 0, len(parsedPrefixes))
	{
		// dedup
		normalizedPrefixes := make(map[string]int, len(parsedPrefixes))
		for i, p := range parsedPrefixes {
			normalized, _ := netipx.RangeOfPrefix(p).Prefix()
			normalizedPrefixes[normalized.String()] = i
		}

		// convert back to list
		for _, i := range normalizedPrefixes {
			prefixes = append(prefixes, parsedPrefixes[i])
		}
	}

	if len(prefixes) < 1 {
		prefixes = append(prefixes, netip.MustParsePrefix("100.64.0.0/10"))
		log.Warn().
			Caller().
			Msgf("'ip_prefixes' not configured, falling back to default: %v", prefixes)
	}

	oidcClientSecret := viper.GetString("oidc.client_secret")
	oidcClientSecretPath := viper.GetString("oidc.client_secret_path")
	if oidcClientSecretPath != "" && oidcClientSecret != "" {
		return nil, errOidcMutuallyExclusive
	}
	if oidcClientSecretPath != "" {
		secretBytes, err := os.ReadFile(os.ExpandEnv(oidcClientSecretPath))
		if err != nil {
			return nil, err
		}
		oidcClientSecret = string(secretBytes)
	}

	kafkaConfig := KafkaConfig{
		UpdateInterval:  viper.GetDuration("kafka.update_interval"),
		BrokerAddress:   viper.GetString("kafka.broker"),
		ProtocolVersion: "2.0.0",
		EnableTLS:       viper.GetBool("kafka.enable_tls"),
		Compression:     "none",
	}

	if strings.EqualFold(viper.GetString("kafka.auth"), "AWS_IAM") {
		kafkaConfig.Authentication = &awsmsk.Authentication{
			SASL: &awsmsk.SASLConfig{
				Mechanism: "AWS_MSK_IAM",
				AWSMSK: awsmsk.AWSMSKConfig{
					Region:     viper.GetString("kafka.region"),
					BrokerAddr: viper.GetString("kafka.broker"),
				},
			},
		}
	}

	cacheConfig := CacheConfig{
		CacheType:       viper.GetString("cache.type"),
		Addr:            viper.GetString("cache.address"),
		Password:        viper.GetString("cache.password"),
		MaxRetries:      viper.GetInt("cache.max_retries"),
		ConnMaxIdleTime: viper.GetDuration("cache.conn_max_idle_time"),
		PoolSize:        viper.GetInt("cache.pool_size"),
		MinIdleConns:    viper.GetInt("cache.min_idle_conns"),
	}

	return &Config{
		ServerURL:          viper.GetString("server_url"),
		Addr:               viper.GetString("listen_addr"),
		MetricsAddr:        viper.GetString("metrics_listen_addr"),
		GRPCAddr:           viper.GetString("grpc_listen_addr"),
		GRPCAllowInsecure:  viper.GetBool("grpc_allow_insecure"),
		DisableUpdateCheck: viper.GetBool("disable_check_updates"),

		IPPrefixes: prefixes,
		PrivateKeyPath: AbsolutePathFromConfigPath(
			viper.GetString("private_key_path"),
		),
		NoisePrivateKeyPath: AbsolutePathFromConfigPath(
			viper.GetString("noise.private_key_path"),
		),
		BaseDomain: baseDomain,

		RELAY: relayConfig,
		Kafka: kafkaConfig,

		IVRegion:     viper.GetString("iv.region"),
		IVLedgerName: viper.GetString("iv.ledger_name"),

		EphemeralNodeInactivityTimeout: viper.GetDuration(
			"ephemeral_node_inactivity_timeout",
		),

		NodeUpdateCheckInterval: viper.GetDuration(
			"node_update_check_interval",
		),

		GeocodingEnabled:     viper.GetBool("geocoding_enabled"),
		NameCollisionEnabled: viper.GetBool("name_collision_enabled"),

		DBtype: viper.GetString("db_type"),
		DBpath: AbsolutePathFromConfigPath(viper.GetString("db_path")),
		DBhost: viper.GetString("db_host"),
		DBport: viper.GetInt("db_port"),
		DBname: viper.GetString("db_name"),
		DBuser: viper.GetString("db_user"),
		DBpass: viper.GetString("db_pass"),
		DBssl:  viper.GetString("db_ssl"),

		LicenseServer:           viper.GetString("license_server"),
		MachineAuthorizationURL: viper.GetString("machine_auth_url"),

		OtelServiceName:      viper.GetString("otel.service_name"),
		OtelSdkDisabled:      viper.GetBool("otel.sdk_disabled"),
		OtelExporterEndpoint: viper.GetString("otel.exporter_endpoint"),

		TLS:   GetTLSConfig(),
		Cache: cacheConfig,

		DNSConfig: dnsConfig,

		ACMEEmail: viper.GetString("acme_email"),
		ACMEURL:   viper.GetString("acme_url"),

		UnixSocket:           viper.GetString("unix_socket"),
		UnixSocketPermission: GetFileMode("unix_socket_permission"),

		KeySigning:          GetKeySigningConfig(),
		ClientPollQueueSize: viper.GetInt("client_poll_queue_size"),

		OIDC: OIDCConfig{
			OnlyStartIfOIDCIsAvailable: viper.GetBool(
				"oidc.only_start_if_oidc_is_available",
			),
			Issuer:           viper.GetString("oidc.issuer"),
			ClientID:         viper.GetString("oidc.client_id"),
			ClientSecret:     oidcClientSecret,
			Scope:            viper.GetStringSlice("oidc.scope"),
			ExtraParams:      viper.GetStringMapString("oidc.extra_params"),
			AllowedDomains:   viper.GetStringSlice("oidc.allowed_domains"),
			AllowedUsers:     viper.GetStringSlice("oidc.allowed_users"),
			AllowedGroups:    viper.GetStringSlice("oidc.allowed_groups"),
			StripEmaildomain: viper.GetBool("oidc.strip_email_domain"),
		},

		ZtmLog:              logConfig,
		RandomizeClientPort: randomizeClientPort,

		ACL: GetACLConfig(),

		CLI: CLIConfig{
			Address:  viper.GetString("cli.address"),
			APIKey:   viper.GetString("cli.api_key"),
			Timeout:  viper.GetDuration("cli.timeout"),
			Insecure: viper.GetBool("cli.insecure"),
		},

		Log: GetLogConfig(),
	}, nil
}

func IsCLIConfigured() bool {
	return viper.GetString("cli.address") != "" && viper.GetString("cli.api_key") != ""
}
