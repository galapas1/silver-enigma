package cli

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"google.golang.org/grpc/status"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
	ninjapanda "optm.com/ninja-panda/src"
)

const (
	errPreAuthKeyMalformed = Error(
		"key is malformed. expected 64 hex characters with `nodekey` prefix",
	)
)

// Error is used to compare errors as per https://dave.cheney.net/2016/04/07/constant-errors
type Error string

func (e Error) Error() string { return string(e) }

func init() {
	rootCmd.AddCommand(debugCmd)

	createNodeCmd.Flags().StringP("name", "", "", "Name")
	err := createNodeCmd.MarkFlagRequired("name")
	if err != nil {
		log.Fatal().Caller().Err(err).Msg("")
	}
	createNodeCmd.Flags().StringP("namespace", "n", "", "Namespace")
	err = createNodeCmd.MarkFlagRequired("namespace")
	if err != nil {
		log.Fatal().Caller().Err(err).Msg("")
	}
	createNodeCmd.Flags().StringP("key", "k", "", "Key")
	err = createNodeCmd.MarkFlagRequired("key")
	if err != nil {
		log.Fatal().Caller().Err(err).Msg("")
	}
	createNodeCmd.Flags().
		StringSliceP("route", "r", []string{}, "List (or repeated flags) of routes to advertise")

	debugCmd.AddCommand(createNodeCmd)
}

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "debug and testing commands",
	Long:  "debug contains extra commands used for debugging and testing ninjapanda",
}

var createNodeCmd = &cobra.Command{
	Use:   "create-node",
	Short: "Create a node (machine) that can be registered with `nodes register <>` command",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		namespace, err := cmd.Flags().GetString("namespace")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting namespace: %s", err), output)

			return
		}

		ctx, client, conn, cancel := getNinjapandaCLIClient()
		defer cancel()
		defer conn.Close()

		name, err := cmd.Flags().GetString("name")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting node from flag: %s", err),
				output,
			)

			return
		}

		machineKey, err := cmd.Flags().GetString("key")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting key from flag: %s", err),
				output,
			)

			return
		}
		if !ninjapanda.NodePublicKeyRegex.Match([]byte(machineKey)) {
			err = errPreAuthKeyMalformed
			ErrorOutput(
				err,
				fmt.Sprintf("Error: %s", err),
				output,
			)

			return
		}

		routes, err := cmd.Flags().GetStringSlice("route")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting routes from flag: %s", err),
				output,
			)

			return
		}

		request := &v1.DebugCreateMachineRequest{
			Key:       machineKey,
			Name:      name,
			Namespace: namespace,
			Routes:    routes,
		}

		response, err := client.DebugCreateMachine(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot create machine: %s", status.Convert(err).Message()),
				output,
			)

			return
		}

		SuccessOutput(response.Machine, "Machine created", output)
	},
}
