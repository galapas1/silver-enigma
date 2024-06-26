package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	"github.com/rs/zerolog/log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"gopkg.in/yaml.v2"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
	ninjapanda "optm.com/ninja-panda/src"
)

const (
	NinjapandaDateTimeFormat = "2006-01-02 15:04:05"
	SocketWritePermissions   = 0o666
)

func getNinjapandaApp() (*ninjapanda.Ninjapanda, error) {
	cfg, err := ninjapanda.GetNinjapandaConfig()
	if err != nil {
		return nil, fmt.Errorf(
			"failed to load configuration while creating ninjapanda instance: %w",
			err,
		)
	}

	app, err := ninjapanda.NewNinjapanda(cfg)
	if err != nil {
		return nil, err
	}

	// We are doing this here, as in the future could be cool to have it also hot-reload

	if cfg.ACL.PolicyPath != "" {
		aclPath := ninjapanda.AbsolutePathFromConfigPath(cfg.ACL.PolicyPath)
		err = app.LoadACLPolicy(aclPath)
		if err != nil {
			log.Fatal().
				Caller().
				Str("path", aclPath).
				Err(err).
				Msg("Could not load the ACL policy")
		}
	}

	return app, nil
}

func getNinjapandaCLIClient() (context.Context, v1.NinjapandaServiceClient, *grpc.ClientConn, context.CancelFunc) {
	cfg, err := ninjapanda.GetNinjapandaConfig()
	if err != nil {
		log.Fatal().
			Caller().
			Err(err).
			Msgf("Failed to load configuration")
		os.Exit(-1) // we get here if logging is suppressed (i.e., json output)
	}

	log.Debug().
		Caller().
		Dur("timeout", cfg.CLI.Timeout).
		Msgf("Setting timeout")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.CLI.Timeout)

	grpcOptions := []grpc.DialOption{
		grpc.WithBlock(),
	}

	address := cfg.CLI.Address

	// If the address is not set, we assume that we are on the server hosting ninjapanda.
	if address == "" {
		log.Debug().
			Caller().
			Str("socket", cfg.UnixSocket).
			Msgf("NINJAPANDA_CLI_ADDRESS environment is not set, connecting to unix socket.")

		address = cfg.UnixSocket

		// Try to give the user better feedback if we cannot write to the ninjapanda
		// socket.
		socket, err := os.OpenFile(
			cfg.UnixSocket,
			os.O_WRONLY,
			SocketWritePermissions,
		) //nolint
		if err != nil {
			if os.IsPermission(err) {
				log.Fatal().
					Caller().
					Err(err).
					Str("socket", cfg.UnixSocket).
					Msgf("Unable to read/write to ninjapanda socket, do you have the correct permissions?")
			}
		}
		socket.Close()

		grpcOptions = append(
			grpcOptions,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(ninjapanda.GrpcSocketDialer),
		)
	} else {
		// If we are not connecting to a local server, require an API key for authentication
		apiKey := cfg.CLI.APIKey
		if apiKey == "" {
			log.Fatal().Caller().Msgf("NINJAPANDA_CLI_API_KEY environment variable needs to be set.")
		}
		grpcOptions = append(grpcOptions,
			grpc.WithPerRPCCredentials(tokenAuth{
				token: apiKey,
			}),
		)

		if cfg.CLI.Insecure {
			tlsConfig := &tls.Config{
				// turn of gosec as we are intentionally setting
				// insecure.
				//nolint:gosec
				InsecureSkipVerify: true,
			}

			grpcOptions = append(grpcOptions,
				grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
			)
		} else {
			grpcOptions = append(grpcOptions,
				grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
			)
		}
	}

	log.Trace().Caller().Str("address", address).Msg("Connecting via gRPC")
	conn, err := grpc.DialContext(ctx, address, grpcOptions...)
	if err != nil {
		log.Fatal().Caller().Err(err).Msgf("Could not connect: %v", err)
		os.Exit(-1) // we get here if logging is suppressed (i.e., json output)
	}

	client := v1.NewNinjapandaServiceClient(conn)

	return ctx, client, conn, cancel
}

func SuccessOutput(result interface{}, override string, outputFormat string) {
	var jsonBytes []byte
	var err error
	switch outputFormat {
	case "json":
		jsonBytes, err = json.MarshalIndent(result, "", "\t")
		if err != nil {
			log.Fatal().Caller().Err(err)
		}
	case "json-line":
		jsonBytes, err = json.Marshal(result)
		if err != nil {
			log.Fatal().Caller().Err(err)
		}
	case "yaml":
		jsonBytes, err = yaml.Marshal(result)
		if err != nil {
			log.Fatal().Caller().Err(err)
		}
	default:
		//nolint
		fmt.Println(override)

		return
	}

	//nolint
	fmt.Println(string(jsonBytes))
}

func ErrorOutput(errResult error, override string, outputFormat string) {
	type errOutput struct {
		Error string `json:"error"`
	}

	SuccessOutput(errOutput{errResult.Error()}, override, outputFormat)
}

func HasMachineOutputFlag() bool {
	for _, arg := range os.Args {
		if arg == "json" || arg == "json-line" || arg == "yaml" {
			return true
		}
	}

	return false
}

type tokenAuth struct {
	token string
}

// Return value is mapped to request headers.
func (t tokenAuth) GetRequestMetadata(
	ctx context.Context,
	in ...string,
) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

func (tokenAuth) RequireTransportSecurity() bool {
	return true
}

func contains[T string](ts []T, t T) bool {
	for _, v := range ts {
		if reflect.DeepEqual(v, t) {
			return true
		}
	}

	return false
}
