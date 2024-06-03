package cli

import (
	"fmt"
	"time"

	"github.com/prometheus/common/model"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
	"optm.com/ninja-panda/src"
)

const (
	// 90 days.
	DefaultAPIKeyExpiry = "90d"
)

func init() {
	rootCmd.AddCommand(apiKeysCmd)
	apiKeysCmd.AddCommand(listAPIKeys)

	createAPIKeyCmd.Flags().
		StringP("expiration", "e", DefaultAPIKeyExpiry, "Human-readable expiration of the key (e.g. 30m, 24h)")

	apiKeysCmd.AddCommand(createAPIKeyCmd)

	expireAPIKeyCmd.Flags().StringP("prefix", "p", "", "ApiKey prefix")
	err := expireAPIKeyCmd.MarkFlagRequired("prefix")
	if err != nil {
		log.Fatal().Caller().Err(err).Msg("")
	}
	apiKeysCmd.AddCommand(expireAPIKeyCmd)
}

var apiKeysCmd = &cobra.Command{
	Use:     "apikeys",
	Short:   "Handle the Api keys in Ninjapanda",
	Aliases: []string{"apikey", "api"},
}

var listAPIKeys = &cobra.Command{
	Use:     "list",
	Short:   "List the Api keys for ninjapanda",
	Aliases: []string{"ls", "show"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		ctx, client, conn, cancel := getNinjapandaCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.ListApiKeysRequest{}

		response, err := client.ListApiKeys(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting the list of keys: %s", err),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response.ApiKeys, "", output)

			return
		}

		tableData := pterm.TableData{
			{"ApiKeyId", "Prefix", "Expiration", "Created"},
		}
		for _, key := range response.ApiKeys {
			expiration := "-"

			if len(key.GetExpiration()) > 0 {
				expiration = ColourTime(
					ninjapanda.ParseTime(key.GetExpiration()).AsTime(),
				)
			}

			d := ninjapanda.ParseTime(key.GetCreatedAt())
			tableData = append(tableData, []string{
				key.GetApikeyId(),
				key.GetPrefix(),
				expiration,
				d.AsTime().Format(NinjapandaDateTimeFormat),
			})

		}
		err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Failed to render pterm table: %s", err),
				output,
			)

			return
		}
	},
}

var createAPIKeyCmd = &cobra.Command{
	Use:   "create",
	Short: "Creates a new Api key",
	Long: `
Creates a new Api key, the Api key is only visible on creation
and cannot be retrieved again.
If you loose a key, create a new one and revoke (expire) the old one.`,
	Aliases: []string{"c", "new"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		request := &v1.CreateApiKeyRequest{}

		durationStr, _ := cmd.Flags().GetString("expiration")
		log.Trace().
			Caller().
			Str("duration", durationStr).
			Msg("Preparing to create ApiKey")

		duration, err := model.ParseDuration(durationStr)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Could not parse duration: %s\n", err),
				output,
			)

			return
		}

		exp := time.Now().UTC().Add(time.Duration(duration))
		expiration := ninjapanda.FormatTime(&exp)

		log.Trace().
			Caller().
			Dur("expiration_in_secs", time.Duration(duration)).
			Str("expiration_as_time", expiration).
			Msg("expiration has been set")

		request.Expiration = expiration

		ctx, client, conn, cancel := getNinjapandaCLIClient()
		defer cancel()
		defer conn.Close()

		response, err := client.CreateApiKey(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot create Api Key: %s\n", err),
				output,
			)

			return
		}

		SuccessOutput(response.ApiKey, response.ApiKey, output)
	},
}

var expireAPIKeyCmd = &cobra.Command{
	Use:     "expire",
	Short:   "Expire an ApiKey",
	Aliases: []string{"revoke", "exp", "e"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		prefix, err := cmd.Flags().GetString("prefix")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting prefix from CLI flag: %s", err),
				output,
			)

			return
		}

		ctx, client, conn, cancel := getNinjapandaCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.ExpireApiKeyRequest{
			Prefix: prefix,
		}

		response, err := client.ExpireApiKey(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot expire Api Key: %s\n", err),
				output,
			)

			return
		}

		SuccessOutput(response, "Key expired", output)
	},
}
