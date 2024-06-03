package ninjapanda

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/awslabs/amazon-qldb-driver-go/v3/qldbdriver"
	"github.com/redis/go-redis/v9"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"

	grpcMiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rs/zerolog/log"

	"go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"go.opentelemetry.io/otel"

	"go.opentelemetry.io/otel/attribute"
	ocodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"

	stdout "go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"

	"go.opentelemetry.io/otel/propagation"

	"go.opentelemetry.io/otel/sdk/resource"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"gorm.io/gorm"

	"github.com/Optm-Main/ztmesh-core/types/dnstype"
	"github.com/Optm-Main/ztmesh-core/types/key"
	"github.com/Optm-Main/ztmesh-core/ztcfg"

	"optm.com/ninja-panda/gen/go/license/v1"
	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

const (
	errSTUNAddressNotSet                   = Error("STUN address not set")
	errUnsupportedDatabase                 = Error("unsupported DB")
	errUnsupportedLetsEncryptChallengeType = Error(
		"unknown value for Lets Encrypt challenge type",
	)
)

const (
	AuthPrefix          = "Bearer "
	Postgres            = "postgres"
	Sqlite              = "sqlite3"
	updateInterval      = 5000
	HTTPReadTimeout     = 30 * time.Second
	HTTPShutdownTimeout = 3 * time.Second
	privateKeyFileMode  = 0o600

	registerCacheExpiration = time.Minute * 15
	registerCacheCleanup    = time.Minute * 20

	DisabledClientAuth = "disabled"
	RelaxedClientAuth  = "relaxed"
	EnforcedClientAuth = "enforced"

	MachinesPerUser = "machines-per-user"
	MachinesPerOrg  = "machines-per-org"
)

var (
	FilterDenyAll = []ztcfg.FilterRule{}
	logtags       = NewLogTags()

	EmptySessionKey = SessionPublicKeyEnsurePrefix(key.SessionPublic{}.String())

	tracer trace.Tracer
)

// Ninjapanda represents the base app of the service.
type Ninjapanda struct {
	cfg             *Config
	db              *gorm.DB
	dbString        string
	dbType          string
	dbDebug         bool
	privateKey      *key.MachinePrivate
	noisePrivateKey *key.MachinePrivate

	RELAYMap    *ztcfg.RELAYMap
	RELAYServer *RELAYServer

	aclPolicy *ACLPolicy
	aclRules  []ztcfg.FilterRule
	sshPolicy *ztcfg.SSHPolicy

	oidcProvider *oidc.Provider
	oauth2Config *oauth2.Config

	registrationCache *CacheClient

	ipAllocationMutex sync.Mutex

	shutdownChan       chan struct{}
	pollNetMapStreamWG sync.WaitGroup

	kafkaClient     *KafkaClient
	redisClient     *redis.Client
	redisSubscriber *redis.PubSub
	driver          *qldbdriver.QLDBDriver

	grpcLicenseServiceClient license.LicenseServiceClient
	notifier                 *Notifier
}

func NewNinjapanda(cfg *Config) (*Ninjapanda, error) {
	var dbString string
	switch cfg.DBtype {
	case Postgres:
		dbString = fmt.Sprintf(
			"host=%s dbname=%s user=%s",
			cfg.DBhost,
			cfg.DBname,
			cfg.DBuser,
		)

		if sslEnabled, err := strconv.ParseBool(cfg.DBssl); err == nil {
			if !sslEnabled {
				dbString += " sslmode=disable"
			}
		} else {
			dbString += fmt.Sprintf(" sslmode=%s", cfg.DBssl)
		}

		if cfg.DBport != 0 {
			dbString += fmt.Sprintf(" port=%d", cfg.DBport)
		}

		if cfg.DBpass != "" {
			dbString += fmt.Sprintf(" password=%s", cfg.DBpass)
		}
	case Sqlite:
		dbString = cfg.DBpath
	default:
		return nil, errUnsupportedDatabase
	}

	ctx := context.Background()
	registrationCache, err := NewCacheClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	app := Ninjapanda{
		cfg:                cfg,
		dbType:             cfg.DBtype,
		dbString:           dbString,
		aclRules:           FilterDenyAll,
		registrationCache:  registrationCache,
		redisClient:        registrationCache.singleClient,
		pollNetMapStreamWG: sync.WaitGroup{},
	}

	app.notifier = NewNotifier(&app)

	err = app.initDB()
	if err != nil {
		return nil, err
	}

	app.initHA()

	app.privateKey, err = app.readOrCreatePrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read or create private key: %w", err)
	}

	// TS2021 requires to have a different key from the legacy protocol.
	app.noisePrivateKey, err = app.readOrCreatePrivateKey(cfg.NoisePrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to read or create Noise protocol private key: %w",
			err,
		)
	}

	if app.privateKey.Equal(*app.noisePrivateKey) {
		return nil, fmt.Errorf(
			"private key and noise private key are the same: %w",
			err,
		)
	}

	if cfg.OIDC.Issuer != "" {
		err = app.initOIDC()
		if err != nil {
			if cfg.OIDC.OnlyStartIfOIDCIsAvailable {
				return nil, err
			} else {
				log.Warn().Caller().Err(err).Msg("failed to set up OIDC provider, falling back to CLI based authentication")
			}
		}
	}

	if app.cfg.DNSConfig != nil && app.cfg.DNSConfig.Proxied { // if MagicDNS
		magicDNSDomains := generateMagicDNSRootDomains(app.cfg.IPPrefixes)
		// we might have routes already from Split DNS
		if app.cfg.DNSConfig.Routes == nil {
			app.cfg.DNSConfig.Routes = make(map[string][]*dnstype.Resolver)
		}
		for _, d := range magicDNSDomains {
			app.cfg.DNSConfig.Routes[d.WithoutTrailingDot()] = nil
		}
	}

	if cfg.RELAY.ServerEnabled {
		embeddedRELAYServer, err := app.NewRELAYServer()
		if err != nil {
			return nil, err
		}
		app.RELAYServer = embeddedRELAYServer
	}

	initMetrics()

	return &app, nil
}

// In the case of HA NinjaPanda we need to be able to subscribe to what we are calling HA Events.
// Namely if one Ninja Panda instance has done a change to the system that other NP's should re-adjust
// their state, this will be the preferred method of notification for the originating NP to inform the
// other NPs.  Note that so far the Originating NP will also receive the event and do its updates twice
// but this is a fair price to pay.  TODO: Perhaps how to research a way to distinguish the originator
// from the recipients but this is not terribly performance expensive.
func (np *Ninjapanda) launchSubscriber() {
	np.SubscribeToHAEvents()
}

func (np *Ninjapanda) redirect(w http.ResponseWriter, req *http.Request) {
	target := np.cfg.ServerURL + req.URL.RequestURI()
	http.Redirect(w, req, target, http.StatusFound)
}

func (np *Ninjapanda) expireEphemeral(milliSeconds int64) {
	ticker := time.NewTicker(time.Duration(milliSeconds) * time.Millisecond)

	var update StateUpdate
	var changed bool

	for range ticker.C {
		update, changed = np.expireEphemeralWorker()

		if changed && update.Valid() {
			ctx := NotifyCtx(context.Background(), "expire-ephemeral", "na")
			np.notifier.NotifyAll(ctx, update)
		}
	}
}

func (np *Ninjapanda) expireExpiredMachines(milliSeconds int64) {
	ticker := time.NewTicker(time.Duration(milliSeconds) * time.Millisecond)

	lastCheckStr, _ := np.getValue("lastExpiryCheck")
	lastCheck := time.Unix(0, 0)

	if len(lastCheckStr) > 0 {
		_lastCheck, err := time.Parse(time.RFC3339, lastCheckStr)
		if err == nil {
			lastCheck = _lastCheck
		}
	}

	var update StateUpdate
	var changed bool

	for range ticker.C {
		lastCheck, update, changed = np.expireExpiredMachinesWorker(lastCheck)
		np.setValue("lastExpiryCheck", lastCheck.Format(time.RFC3339))

		if changed && update.Valid() {
			log.Trace().
				Caller().
				Str(logtags.GetTag(logtags.stateUpdate, "ChangedMachines"), update.ChangedMachines.String()).
				Msgf("expiring nodes")
			ctx := NotifyCtx(context.Background(), "expire-expired", "na")
			np.notifier.NotifyAll(ctx, update)
		}
	}
}

func (np *Ninjapanda) failoverSubnetRoutes(milliSeconds int64) {
	ticker := time.NewTicker(time.Duration(milliSeconds) * time.Millisecond)
	for range ticker.C {
		err := np.handlePrimarySubnetFailover()
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("failed to handle primary subnet failover")
		}
	}
}

func (np *Ninjapanda) expireEphemeralWorker() (StateUpdate, bool) {
	namespaces, err := np.ListNamespaces()
	if err != nil {
		log.Error().Caller().Err(err).Msg("Error listing namespaces")

		return StateUpdate{}, false
	}

	nowInUtc := time.Now().UTC()
	expired := make([]ztcfg.NodeID, 0)

	for _, namespace := range namespaces {
		machines, err := np.ListMachinesInNamespace(namespace.Name)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Str(logtags.GetTag(logtags.namespace, "Name"), namespace.Name).
				Msg("Error listing machines in namespace")

			return StateUpdate{}, false
		}

		for _, machine := range machines {
			if machine.LastSeen != nil {
				if machine.LastSeen.Before(nowInUtc.Add(-keepAliveInterval)) {
					// machines offline don't send updates, but need to at least once
					// REVIEW refine this (e.g., check if LastSeen before LastStateChagne)
					timeSinceLastSeen := nowInUtc.Sub(*machine.LastSeen)
					if timeSinceLastSeen < 5*time.Minute {
						np.SendMachineUpdate(&machine)
					}
				}

				if machine.isEphemeral() &&
					nowInUtc.
						After(
							machine.LastSeen.Add(np.cfg.EphemeralNodeInactivityTimeout),
						) {

					expired = append(expired, ztcfg.NodeID(machine.ID))

					log.Info().
						Caller().
						Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
						Msg("Ephemeral client removed from database")

					err = np.DeleteMachine(&machine)
					if err != nil {
						log.Error().
							Caller().
							Err(err).
							Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
							Msg("🤮 Cannot delete ephemeral machine from the database")
					}
				}
			}
		}
	}

	if len(expired) > 0 {
		return StateUpdate{
			Type:    StatePeerRemoved,
			Removed: expired,
		}, true
	}

	return StateUpdate{}, false
}

func (np *Ninjapanda) expireExpiredMachinesWorker(
	lastCheck time.Time,
) (time.Time, StateUpdate, bool) {
	started := time.Now().UTC()

	expired := make([]*ztcfg.PeerChange, 0)

	namespaces, err := np.ListNamespaces()
	if err != nil {
		log.Error().Caller().Err(err).Msg("Error listing namespaces")

		return lastCheck, StateUpdate{}, false
	}

	for _, namespace := range namespaces {
		machines, err := np.ListMachinesInNamespace(namespace.Name)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Str(logtags.GetTag(logtags.namespace, "Name"), namespace.Name).
				Msg("Error listing machines in namespace")

			return lastCheck, StateUpdate{}, false
		}

		for index, machine := range machines {
			if machine.isExpired() &&
				machine.Expiry.After(lastCheck) {
				log.Trace().
					Caller().
					Time("expiry", *machine.Expiry).
					Time("lastCheck", lastCheck).
					Bool("after", machine.Expiry.After(lastCheck)).
					Send()

				expired = append(expired, &ztcfg.PeerChange{
					NodeID:    ztcfg.NodeID(machine.ID),
					KeyExpiry: machine.Expiry,
				})

				err := np.ExpireMachine(&machines[index])
				if err != nil {
					log.Error().
						Caller().
						Err(err).
						Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
						Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
						Msg("🤮 Cannot expire machine")
				} else {
					log.Info().
						Caller().
						Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
						Str(logtags.GetTag(logtags.machine, "GivenName"), machine.GivenName).
						Msg("Machine successfully expired")
				}
			}
		}
	}

	if len(expired) > 0 {
		return started, StateUpdate{
			Type:          StatePeerChangedPatch,
			ChangePatches: expired,
		}, true
	}

	return started, StateUpdate{}, false
}

func (np *Ninjapanda) grpcAuthenticationInterceptor(ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Check if the request is coming from the on-server client.
	// This is not secure, but it is to maintain maintainability
	// with the "legacy" database-based client
	// It is also needed for grpc-gateway to be able to connect to
	// the server
	client, _ := peer.FromContext(ctx)

	log.Info().Caller().Msg(" ***** grpcAuthenticationInterceptor")
	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.peer, "Addr"), client.Addr.String()).
		Msg("Client is trying to authenticate")

	span := trace.SpanFromContext(ctx)

	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		span.SetStatus(ocodes.Error, "Retrieving metadata is failed")
		log.Error().
			Caller().
			Str(logtags.GetTag(logtags.peer, "Addr"), client.Addr.String()).
			Msg("Retrieving metadata is failed")

		return ctx, status.Errorf(
			codes.InvalidArgument,
			"Retrieving metadata is failed",
		)
	}

	authHeader, ok := meta["authorization"]
	if !ok {
		span.SetStatus(ocodes.Error, "Authorization token is not supplied")
		log.Error().
			Caller().
			Str(logtags.GetTag(logtags.peer, "Addr"), client.Addr.String()).
			Msg("Authorization token is not supplied")

		return ctx, status.Errorf(
			codes.Unauthenticated,
			"Authorization token is not supplied",
		)
	}

	token := authHeader[0]

	if !strings.HasPrefix(token, AuthPrefix) {
		span.SetStatus(
			ocodes.Error,
			`missing "Bearer " prefix in "Authorization" header`,
		)
		log.Error().
			Caller().
			Str(logtags.GetTag(logtags.peer, "Addr"), client.Addr.String()).
			Msg(`missing "Bearer " prefix in "Authorization" header`)

		return ctx, status.Error(
			codes.Unauthenticated,
			`missing "Bearer " prefix in "Authorization" header`,
		)
	}

	valid, err := np.ValidateAPIKey(strings.TrimPrefix(token, AuthPrefix))
	if err != nil {
		span.SetStatus(ocodes.Error, "failed to validate token")
		span.RecordError(err)
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.peer, "Addr"), client.Addr.String()).
			Msg("failed to validate token")

		return ctx, status.Error(codes.Internal, "failed to validate token")
	}

	if !valid {
		span.SetStatus(ocodes.Error, "not authorized: invalid token")
		log.Info().
			Caller().
			Str(logtags.GetTag(logtags.peer, "Addr"), client.Addr.String()).
			Msg("invalid token")

		return ctx, status.Error(codes.Unauthenticated, "invalid token")
	}

	ctx = trace.ContextWithSpan(ctx, span)
	return handler(ctx, req)
}

func (np *Ninjapanda) httpAuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(writer http.ResponseWriter, req *http.Request) {
			startTime := time.Now()

			ctx := req.Context()

			span := trace.SpanFromContext(ctx)

			// TODO: introduce a true whitelist for endpoints (jrb)
			if req.URL.Path != "/api/v1/relays" {
				log.Trace().
					Caller().
					Str(logtags.GetTag(logtags.httpRequest, "RemoteAddr"), req.RemoteAddr).
					Str(logtags.GetTag(logtags.url, "Path"), req.URL.Path).
					Str(logtags.GetTag(logtags.httpRequest, "Method"), req.Method).
					Msg("HTTP authentication invoked")

				authHeader := req.Header.Get("authorization")

				if !strings.HasPrefix(authHeader, AuthPrefix) {
					span.SetStatus(
						ocodes.Error,
						`missing "Bearer " prefix in "Authorization" header`,
					)
					log.Error().
						Caller().
						Str(logtags.GetTag(logtags.httpRequest, "RemoteAddr"), req.RemoteAddr).
						Msg(`missing "Bearer " prefix in "Authorization" header`)

					writer.WriteHeader(http.StatusUnauthorized)
					_, err := writer.Write([]byte("Unauthorized"))
					if err != nil {
						span.SetStatus(ocodes.Error, "failed to write response")
						span.RecordError(err)
						log.Error().
							Caller().
							Err(err).
							Msg("failed to write response")
					}

					return
				}

				span.AddEvent("ValidateAPIKey")
				valid, err := np.ValidateAPIKey(
					strings.TrimPrefix(authHeader, AuthPrefix),
				)
				if err != nil {
					span.SetStatus(ocodes.Error, "failed to validate token")
					span.RecordError(err)
					log.Error().
						Caller().
						Err(err).
						Str(logtags.GetTag(logtags.httpRequest, "RemoteAddr"), req.RemoteAddr).
						Msg("failed to validate token")

					writer.WriteHeader(http.StatusInternalServerError)
					_, err := writer.Write([]byte("Unauthorized"))
					if err != nil {
						span.SetStatus(ocodes.Error, "failed to write response")
						span.RecordError(err)
						log.Error().
							Caller().
							Err(err).
							Msg("failed to write response")
					}

					return
				}

				if !valid {
					span.SetStatus(ocodes.Error, "unauthenticated: invalid token")
					log.Info().
						Caller().
						Str(logtags.GetTag(logtags.httpRequest, "RemoteAddr"), req.RemoteAddr).
						Msg("invalid token")

					writer.WriteHeader(http.StatusUnauthorized)
					_, err := writer.Write([]byte("Unauthorized"))
					if err != nil {
						span.SetStatus(ocodes.Error, "failed to write response")
						log.Error().
							Caller().
							Err(err).
							Msg("failed to write response")
					}

					return
				}
			}

			ctx = trace.ContextWithSpan(ctx, span)

			responseWriter := NewResponseWriter(writer)
			next.ServeHTTP(responseWriter, req.WithContext(ctx))

			statusCode := responseWriter.Status()
			duration := time.Since(startTime).Seconds()
			requestDuration.With(
				prometheus.Labels{
					"method":      req.Method,
					"route":       req.URL.Path,
					"status_code": strconv.Itoa(statusCode),
				},
			).Observe(duration)

			span.SetAttributes(attribute.Float64("duration", duration))
		})
}

// ensureUnixSocketIsAbsent will check if the given path for ninjapandas unix socket is clear
// and will remove it if it is not.
func (np *Ninjapanda) ensureUnixSocketIsAbsent() error {
	// File does not exist, all fine
	if _, err := os.Stat(np.cfg.UnixSocket); errors.Is(err, os.ErrNotExist) {
		return nil
	}

	return os.Remove(np.cfg.UnixSocket)
}

func (np *Ninjapanda) createRouter(grpcMux *runtime.ServeMux) *mux.Router {
	router := mux.NewRouter()
	// router.Use(otelmux.Middleware("ninja-panda"))

	router.HandleFunc(ts2021UpgradePath, np.NoiseUpgradeHandler).
		Methods(http.MethodPost)
	router.HandleFunc(ztm2023UpgradePath, np.NoiseUpgradeHandler).
		Methods(http.MethodPost)

	router.HandleFunc("/version", np.VersionHandler).Methods(http.MethodGet)
	router.HandleFunc("/health", np.HealthHandler).Methods(http.MethodGet)
	router.HandleFunc("/key", np.KeyHandler).Methods(http.MethodGet)
	router.HandleFunc("/register/{nkey}", np.RegisterWebAPI).Methods(http.MethodGet)
	np.addLegacyHandlers(router)

	router.HandleFunc("/oidc/register/{nkey}", np.RegisterOIDC).Methods(http.MethodGet)
	router.HandleFunc("/oidc/callback", np.OIDCCallback).Methods(http.MethodGet)
	router.HandleFunc("/apple", np.AppleConfigMessage).Methods(http.MethodGet)
	router.HandleFunc("/apple/{platform}", np.ApplePlatformConfig).
		Methods(http.MethodGet)
	router.HandleFunc("/windows", np.WindowsConfigMessage).Methods(http.MethodGet)
	router.HandleFunc("/windows/ztmesh.reg", np.WindowsRegConfig).
		Methods(http.MethodGet)
	router.HandleFunc("/swagger", SwaggerUI).Methods(http.MethodGet)
	router.HandleFunc("/swagger/v1/openapiv2.json", SwaggerAPIv1).
		Methods(http.MethodGet)

	if np.cfg.RELAY.ServerEnabled {
		router.HandleFunc("/relay", np.RELAYHandler)
		router.HandleFunc("/relay/probe", np.RELAYProbeHandler)
		router.HandleFunc("/bootstrap-dns", np.RELAYBootstrapDNSHandler)
	}

	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.Use(otelmux.Middleware("ninja-panda"))
	apiRouter.Use(np.httpAuthenticationMiddleware)

	handler := http.Handler(grpcMux)
	handler = otelhttp.NewHandler(handler, "", otelhttp.WithSpanNameFormatter(spanName))

	apiRouter.PathPrefix("/v1/").HandlerFunc(handler.ServeHTTP)

	router.PathPrefix("/").HandlerFunc(np.stdoutHandler)

	return router
}

func spanName(operation string, req *http.Request) string {
	return req.Method + " " + req.URL.String()
}

func getExportMethod(otelExporterEndpoint string) string {
	endpoint := strings.ToLower(otelExporterEndpoint)

	if strings.Contains(endpoint, "stdout") {
		return "stdout"
	}

	if strings.Contains(endpoint, "http") {
		return "http"
	}

	parts := strings.Split(endpoint, ":")
	if len(parts) == 2 {
		if _, err := strconv.Atoi(parts[1]); err == nil {
			return "grpc"
		}
	}

	return "undefined"
}

func (np *Ninjapanda) initTracerProvider(ctx context.Context) func() {
	var bsp sdktrace.SpanProcessor

	otelExporterMethod := getExportMethod(np.cfg.OtelExporterEndpoint)
	log.Debug().
		Caller().
		Msgf("selecting %s as the otel export method", otelExporterMethod)

	switch otelExporterMethod {
	case "stdout":
		exporter, _ := stdout.New(stdout.WithPrettyPrint())
		bsp = sdktrace.NewSimpleSpanProcessor(exporter)
	case "grpc":
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		conn, err := grpc.DialContext(ctx, np.cfg.OtelExporterEndpoint,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		if err != nil {
			log.Fatal().
				Caller().
				Err(err).
				Msg("failed to create gRPC connection to collector")
		}
		exporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
		if err != nil {
			log.Fatal().Caller().Err(err).Msg("failed to init otel otlp grpcp exporter")
		}
		bsp = sdktrace.NewSimpleSpanProcessor(exporter)
	case "http":
		endpointUrl, err := url.Parse(np.cfg.OtelExporterEndpoint)
		if err != nil {
			log.Fatal().Caller().Err(err).Msg("failed to parse otel http endpoint")
		}

		exporter, err := otlptrace.New(
			ctx,
			otlptracehttp.NewClient(
				otlptracehttp.WithInsecure(),
				otlptracehttp.WithEndpoint(endpointUrl.Host),
			),
		)
		if err != nil {
			log.Fatal().Caller().Err(err).Msg("failed to init otel otlp http exporter")
		}
		bsp = sdktrace.NewSimpleSpanProcessor(exporter)
	default:
		log.Fatal().
			Caller().
			Msgf("unknown otel otlp export method, %s", np.cfg.OtelExporterEndpoint)
	}

	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(
				np.cfg.OtelServiceName,
			),
		),
	)
	if err != nil {
		log.Fatal().Caller().Err(err).Msg("failed to init otel tracer provider")
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(r),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(bsp),
	)

	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)

	otel.SetTracerProvider(tracerProvider)
	otel.SetTextMapPropagator(propagator)

	tracer = tracerProvider.Tracer("ninjapanda")

	return func() {
		if err := tracerProvider.Shutdown(ctx); err != nil {
			log.Error().Caller().Err(err).Msg("Error shutting down tracer provider")
		}
	}
}

// Serve launches a GIN server with the Ninjapanda API.
func (np *Ninjapanda) Serve() error {
	ctx := context.Background()

	var tracerShutdown func() = nil
	if !np.cfg.OtelSdkDisabled && len(np.cfg.OtelExporterEndpoint) > 0 {
		log.Info().Caller().Msgf("starting otel tracing")

		tracerShutdown = np.initTracerProvider(ctx)

	} else {
		log.Warn().Caller().Msgf("not starting otel tracing (disabled or missing endpoint)")
	}

	var err error

	// Fetch an initial RELAY Map before we start serving
	np.RELAYMap = GetRELAYMap(np.cfg.RELAY)

	if np.cfg.RELAY.ServerEnabled {
		// When embedded RELAY is enabled we always need a STUN server
		if np.cfg.RELAY.STUNAddr == "" {
			return errSTUNAddressNotSet
		}

		np.RELAYMap.Regions[np.RELAYServer.region.RegionID] = &np.RELAYServer.region
		go np.ServeSTUN()
	}

	if np.cfg.RELAY.AutoUpdate {
		relayMapCancelChannel := make(chan struct{})
		defer func() { relayMapCancelChannel <- struct{}{} }()
		go np.scheduledRELAYMapUpdateWorker(relayMapCancelChannel)
	}

	np.kafkaClient, err = NewKafkaClient(np.cfg.Kafka)
	if err != nil {
		log.Error().Caller().Err(err).Msg("Could not configure Kafka producer!")
	}
	if np.kafkaClient.Producer == nil {
		log.Warn().Caller().Msg("Not using Kafka to emit messages")
	}

	np.driver, err = np.initIV()
	if err != nil {
		log.Warn().Caller().Err(err).Msg("failed to create iv driver")
		np.driver = nil
	}

	go np.expireEphemeral(updateInterval)
	go np.expireExpiredMachines(updateInterval)

	go np.failoverSubnetRoutes(updateInterval)

	// Prepare group for running listeners
	errorGroup := new(errgroup.Group)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	//
	// Set up LOCAL listeners
	//

	err = np.ensureUnixSocketIsAbsent()
	if err != nil {
		return fmt.Errorf("unable to remove old socket file: %w", err)
	}

	socketListener, err := net.Listen("unix", np.cfg.UnixSocket)
	if err != nil {
		return fmt.Errorf("failed to set up gRPC socket: %w", err)
	}

	// Change socket permissions
	if err := os.Chmod(np.cfg.UnixSocket, np.cfg.UnixSocketPermission); err != nil {
		return fmt.Errorf("failed change permission of gRPC socket: %w", err)
	}

	grpcGatewayMux := runtime.NewServeMux(
		runtime.WithIncomingHeaderMatcher(
			func(key string) (string, bool) {
				switch key {
				case "X-Amzn-Trace-Id":
					return key, true
				default:
					return runtime.DefaultHeaderMatcher(key)
				}
			}),
	)

	// Make the grpc-gateway connect to grpc over socket
	grpcGatewayConn, err := grpc.Dial(
		np.cfg.UnixSocket,
		[]grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(GrpcSocketDialer),
			grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
		}...,
	)
	if err != nil {
		return err
	}

	// Connect to the gRPC server over localhost to skip
	// the authentication.
	err = v1.RegisterNinjapandaServiceHandler(ctx, grpcGatewayMux, grpcGatewayConn)
	if err != nil {
		return err
	}

	// Start the local gRPC server without TLS and without authentication
	grpcSocket := grpc.NewServer(
		grpc.UnaryInterceptor(otelgrpc.UnaryServerInterceptor()),
		grpc.StreamInterceptor(otelgrpc.StreamServerInterceptor()),
	)

	v1.RegisterNinjapandaServiceServer(grpcSocket, newNinjapandaV1APIServer(np))
	reflection.Register(grpcSocket)

	errorGroup.Go(func() error { return grpcSocket.Serve(socketListener) })

	//
	// Set up REMOTE listeners
	//

	tlsConfig, err := np.getTLSSettings()
	if err != nil {
		log.Error().Caller().Err(err).Msg("failed to set up TLS configuration")

		return err
	}

	//
	// gRPC setup
	//

	var grpcServer *grpc.Server
	var grpcListener net.Listener
	if tlsConfig != nil || np.cfg.GRPCAllowInsecure {
		log.Info().Caller().Msgf("Enabling remote gRPC at %s", np.cfg.GRPCAddr)

		grpcOptions := []grpc.ServerOption{
			grpc.UnaryInterceptor(
				grpcMiddleware.ChainUnaryServer(
					np.grpcAuthenticationInterceptor,
					NewUnaryServerInterceptor(),
				),
			),
		}

		if tlsConfig != nil {
			grpcOptions = append(grpcOptions,
				grpc.Creds(credentials.NewTLS(tlsConfig)),
			)
		} else {
			log.Warn().Caller().Msg("gRPC is running without security")
		}

		grpcServer = grpc.NewServer(grpcOptions...)

		v1.RegisterNinjapandaServiceServer(grpcServer, newNinjapandaV1APIServer(np))
		reflection.Register(grpcServer)

		grpcListener, err = net.Listen("tcp", np.cfg.GRPCAddr)
		if err != nil {
			return fmt.Errorf("failed to bind to TCP address: %w", err)
		}

		errorGroup.Go(func() error { return grpcServer.Serve(grpcListener) })

		log.Info().
			Caller().
			Msgf("listening and serving gRPC on: %s", np.cfg.GRPCAddr)
	}

	np.grpcLicenseServiceClient = nil
	licenseServerAddr := np.cfg.LicenseServer
	if len(licenseServerAddr) == 0 {
		log.Warn().
			Caller().
			Msg("license server addr undefined, license check disabled")
	} else {
		conn, err := grpc.Dial(
			licenseServerAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			return fmt.Errorf("Error accessing %s: %v", licenseServerAddr, err)
		}

		np.grpcLicenseServiceClient = license.NewLicenseServiceClient(conn)
	}

	//
	// HTTP setup
	//
	router := np.createRouter(grpcGatewayMux)

	httpServer := &http.Server{
		Addr:         np.cfg.Addr,
		Handler:      router,
		ReadTimeout:  HTTPReadTimeout,
		WriteTimeout: 0,
	}

	var httpListener net.Listener
	if tlsConfig != nil {
		httpServer.TLSConfig = tlsConfig
		httpListener, err = tls.Listen("tcp", np.cfg.Addr, tlsConfig)
	} else {
		httpListener, err = net.Listen("tcp", np.cfg.Addr)
	}
	if err != nil {
		return fmt.Errorf("failed to bind to TCP address: %w", err)
	}

	errorGroup.Go(func() error { return httpServer.Serve(httpListener) })

	log.Info().
		Caller().
		Msgf("listening and serving HTTP on: %s", np.cfg.Addr)

	promMux := http.NewServeMux()
	promMux.Handle("/metrics", promhttp.Handler())

	promHTTPServer := &http.Server{
		Addr:         np.cfg.MetricsAddr,
		Handler:      promMux,
		ReadTimeout:  HTTPReadTimeout,
		WriteTimeout: 0,
	}

	var promHTTPListener net.Listener
	promHTTPListener, err = net.Listen("tcp", np.cfg.MetricsAddr)

	if err != nil {
		return fmt.Errorf("failed to bind to TCP address: %w", err)
	}

	errorGroup.Go(func() error { return promHTTPServer.Serve(promHTTPListener) })

	log.Info().
		Caller().
		Msgf("listening and serving metrics on: %s", np.cfg.MetricsAddr)

	log.Info().Caller().Msg("Loading ACL policies from DB")
	np.LoadACLPolicyFromDB()

	// Handle common process-killing signals so we can gracefully shut down:
	np.shutdownChan = make(chan struct{})
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGHUP)
	sigFunc := func(c chan os.Signal) {
		// Wait for a SIGINT or SIGKILL:
		for {
			sig := <-c
			switch sig {
			case syscall.SIGHUP:
				log.Info().
					Caller().
					Str("signal", sig.String()).
					Msg("Received SIGHUP, reloading ACL and Config")

				// TODO: Reload config on SIGHUP

				if np.cfg.ACL.PolicyPath != "" {
					aclPath := AbsolutePathFromConfigPath(np.cfg.ACL.PolicyPath)
					err := np.LoadACLPolicy(aclPath)
					if err != nil {
						log.Error().
							Caller().
							Err(err).
							Msg("failed to reload ACL policy")
					} else {
						log.Info().
							Caller().
							Str("path", aclPath).
							Msg("ACL policy successfully reloaded from file, notifying nodes of change")
					}
				}

				err := np.LoadACLPolicyFromDB()
				if err != nil {
					log.Error().
						Caller().
						Err(err).
						Msg("failed to reload ACL policy from DB")
				} else {
					log.Info().
						Caller().
						Msg("ACL policy successfully reloaded from DB, notifying nodes of change")
				}

				ctx := NotifyCtx(context.Background(), "acl-sighup", "na")
				np.notifier.NotifyAll(ctx,
					StateUpdate{
						Type: StateFullUpdate,
					})

			default:
				log.Info().
					Caller().
					Str("signal", sig.String()).
					Msg("Received signal to stop, shutting down gracefully")

				close(np.shutdownChan)
				np.pollNetMapStreamWG.Wait()

				if tracerShutdown != nil {
					tracerShutdown()
				}

				// Gracefully shut down servers
				ctx, cancel := context.WithTimeout(
					context.Background(),
					HTTPShutdownTimeout,
				)
				if err := promHTTPServer.Shutdown(ctx); err != nil {
					log.Error().
						Caller().
						Err(err).
						Msg("failed to shutdown prometheus http")
				}
				if err := httpServer.Shutdown(ctx); err != nil {
					log.Error().Caller().Err(err).Msg("failed to shutdown http")
				}
				grpcSocket.GracefulStop()

				if grpcServer != nil {
					grpcServer.GracefulStop()
					grpcListener.Close()
				}

				// Close network listeners
				promHTTPListener.Close()
				httpListener.Close()
				grpcGatewayConn.Close()

				// Stop listening (and unlink the socket if unix type):
				socketListener.Close()

				// Close db connections
				db, err := np.db.DB()
				if err != nil {
					log.Error().Caller().Err(err).Msg("failed to get db handle")
				}
				err = db.Close()
				if err != nil {
					log.Error().Caller().Err(err).Msg("failed to close db")
				}

				if np.driver != nil {
					np.driver.Shutdown(ctx)
				}

				log.Info().
					Caller().
					Msg("Ninjapanda stopped")

				// ...and... we're done
				cancel()
				os.Exit(0)
			}
		}
	}
	errorGroup.Go(func() error {
		sigFunc(sigc)

		return nil
	})

	return errorGroup.Wait()
}

func (np *Ninjapanda) getTLSSettings() (*tls.Config, error) {
	var err error
	if np.cfg.TLS.LetsEncrypt.Hostname != "" {
		if !strings.HasPrefix(np.cfg.ServerURL, "https://") {
			log.Warn().
				Caller().
				Msg("Listening with TLS but ServerURL does not start with https://")
		}

		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(np.cfg.TLS.LetsEncrypt.Hostname),
			Cache:      autocert.DirCache(np.cfg.TLS.LetsEncrypt.CacheDir),
			Client: &acme.Client{
				DirectoryURL: np.cfg.ACMEURL,
			},
			Email: np.cfg.ACMEEmail,
		}

		switch np.cfg.TLS.LetsEncrypt.ChallengeType {
		case tlsALPN01ChallengeType:
			// Configuration via autocert with TLS-ALPN-01 (https://tools.ietf.org/html/rfc8737)
			// The RFC requires that the validation is done on port 443; in other words, ninjapanda
			// must be reachable on port 443.
			return certManager.TLSConfig(), nil

		case http01ChallengeType:
			// Configuration via autocert with HTTP-01. This requires listening on
			// port 80 for the certificate validation in addition to the ninjapanda
			// service, which can be configured to run on any other port.

			server := &http.Server{
				Addr:        np.cfg.TLS.LetsEncrypt.Listen,
				Handler:     certManager.HTTPHandler(http.HandlerFunc(np.redirect)),
				ReadTimeout: HTTPReadTimeout,
			}

			go func() {
				err := server.ListenAndServe()
				log.Fatal().
					Caller().
					Err(err).
					Msg("failed to set up a HTTP server")
			}()

			return certManager.TLSConfig(), nil

		default:
			return nil, errUnsupportedLetsEncryptChallengeType
		}
	} else if np.cfg.TLS.CertPath == "" {
		if !strings.HasPrefix(np.cfg.ServerURL, "http://") {
			log.Warn().Caller().Msg("Listening without TLS but ServerURL does not start with http://")
		}

		return nil, err
	} else {
		if !strings.HasPrefix(np.cfg.ServerURL, "https://") {
			log.Warn().Caller().Msg("Listening with TLS but ServerURL does not start with https://")
		}

		tlsConfig := &tls.Config{
			NextProtos:   []string{"http/1.1"},
			Certificates: make([]tls.Certificate, 1),
			MinVersion:   tls.VersionTLS12,
		}

		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(np.cfg.TLS.CertPath, np.cfg.TLS.KeyPath)

		return tlsConfig, err
	}
}

func (np *Ninjapanda) stdoutHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	body, _ := io.ReadAll(req.Body)

	log.Trace().
		Caller().
		Interface(logtags.GetTag(logtags.httpRequest, "Header"), req.Header).
		Interface(logtags.GetTag(logtags.httpRequest, "Proto"), req.Proto).
		Interface(logtags.GetTag(logtags.httpRequest, "URL"), req.URL).
		Str("body", string(body)).
		Msg("Request did not match")
}

func (np *Ninjapanda) readOrCreatePrivateKeyFromFile(
	path string,
) (*key.MachinePrivate, error) {
	privateKey, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		log.Info().
			Caller().
			Str("path", path).
			Msg("No private key file at path, creating...")

		machineKey := key.NewMachine()

		machineKeyStr, err := machineKey.MarshalText()
		if err != nil {
			return nil, fmt.Errorf(
				"failed to convert private key to string for saving: %w",
				err,
			)
		}
		err = os.WriteFile(path, machineKeyStr, privateKeyFileMode)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to save private key to disk: %w",
				err,
			)
		}

		return &machineKey, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	trimmedPrivateKey := strings.TrimSpace(string(privateKey))
	privateKeyEnsurePrefix := PrivateKeyEnsurePrefix(trimmedPrivateKey)

	var machineKey key.MachinePrivate
	if err = machineKey.UnmarshalText([]byte(privateKeyEnsurePrefix)); err != nil {
		log.Info().
			Caller().
			Str("path", path).
			Msg("This might be due to a legacy (ninjapanda pre-0.12) private key. " +
				"If the key is in WireGuard format, delete the key and restart ninjapanda. " +
				"A new key will automatically be generated. All clients will have to be restarted")

		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &machineKey, nil
}

func (np *Ninjapanda) readOrCreatePrivateKeyFromDB(
	kvKey string,
) (*key.MachinePrivate, error) {
	privateKey, err := np.getValue(kvKey)
	if err != nil {
		log.Info().
			Caller().
			Str(logtags.GetTag(logtags.kv, "Key"), kvKey).
			Msg("No private key found, creating...")

		machineKey := key.NewMachine()

		machineKeyStr, err := machineKey.MarshalText()
		if err != nil {
			return nil, fmt.Errorf(
				"failed to convert private key %s to string for saving: %w",
				kvKey, err,
			)
		}
		np.setValue(kvKey, string(machineKeyStr))
		if err != nil {
			return nil, fmt.Errorf(
				"failed to save private key to key %s: %w",
				kvKey, err,
			)
		}

		return &machineKey, nil
	}

	trimmedPrivateKey := strings.TrimSpace(string(privateKey))
	privateKeyEnsurePrefix := PrivateKeyEnsurePrefix(trimmedPrivateKey)

	var machineKey key.MachinePrivate
	if err = machineKey.UnmarshalText([]byte(privateKeyEnsurePrefix)); err != nil {
		return nil, fmt.Errorf("failed to parse private key %s: %w", kvKey, err)
	}

	return &machineKey, nil
}

func (np *Ninjapanda) readOrCreatePrivateKey(path string) (*key.MachinePrivate, error) {
	dbPaths := []string{dbPrivateKeyPath, dbNoisePrivateKeyPath}

	if contains(dbPaths, path) {
		return np.readOrCreatePrivateKeyFromDB(path)
	}

	return np.readOrCreatePrivateKeyFromFile(path)
}
