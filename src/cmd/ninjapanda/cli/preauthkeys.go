package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/common/model"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
	ninjapanda "optm.com/ninja-panda/src"
)

const (
	Base10                  = 10
	BitSize16               = 16
	DefaultPreAuthKeyExpiry = "1h"
)

func init() {
	rootCmd.AddCommand(preauthkeysCmd)
	preauthkeysCmd.PersistentFlags().StringP("namespace", "n", "", "Namespace")
	err := preauthkeysCmd.MarkPersistentFlagRequired("namespace")
	if err != nil {
		log.Fatal().Caller().Err(err).Msg("")
	}
	preauthkeysCmd.AddCommand(listPreAuthKeys)
	preauthkeysCmd.AddCommand(createPreAuthKeyCmd)
	preauthkeysCmd.AddCommand(expirePreAuthKeyCmd)
	createPreAuthKeyCmd.PersistentFlags().
		String("reuseCount", "0", "Limit number of reuses or 0 for unlimited")
	createPreAuthKeyCmd.PersistentFlags().
		Bool("ephemeral", false, "Preauthkey for ephemeral nodes")
	createPreAuthKeyCmd.Flags().
		StringP("expiration", "e", DefaultPreAuthKeyExpiry, "Human-readable expiration of the key (e.g. 30m, 24h)")
	createPreAuthKeyCmd.Flags().
		StringSlice("tags", []string{}, "Tags to automatically assign to node")
}

var preauthkeysCmd = &cobra.Command{
	Use:     "preauthkeys",
	Short:   "Handle the preauthkeys in Ninjapanda",
	Aliases: []string{"preauthkey", "authkey", "pre"},
}

var listPreAuthKeys = &cobra.Command{
	Use:     "list",
	Short:   "List the preauthkeys for this namespace",
	Aliases: []string{"ls", "show"},
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

		request := &v1.ListPreAuthKeysRequest{
			Namespace: namespace,
		}

		response, err := client.ListPreAuthKeys(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting the list of keys: %s", err),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response.PreAuthKeys, "", output)

			return
		}

		tableData := pterm.TableData{
			{
				"ID",
				"Key",
				"Reusable",
				"Ephemeral",
				"Used",
				"Expiration",
				"Created",
				"Revoked",
				"Tags",
			},
		}
		for _, key := range response.PreAuthKeys {
			expiration := "-"
			if len(key.GetExpiration()) > 0 {
				expiration = ColourTime(
					ninjapanda.ParseTime(key.GetExpiration()).AsTime(),
				)
			}

			revoked := "-"
			if len(key.GetRevokedAt()) > 0 {
				d := ninjapanda.ParseTime(key.GetRevokedAt())
				revoked = ColourTime(d.AsTime())
			}

			var reusable string
			if key.GetEphemeral() {
				reusable = "N/A"
			} else {
				reusable = fmt.Sprintf("%d", key.GetReuseCount())
			}

			aclTags := ""

			for _, tag := range key.AclTags {
				aclTags += "," + tag
			}

			aclTags = strings.TrimLeft(aclTags, ",")

			d := ninjapanda.ParseTime(key.GetCreatedAt())
			tableData = append(tableData, []string{
				key.GetPreAuthKeyId(),
				"<hidden>",
				reusable,
				strconv.FormatBool(key.GetEphemeral()),
				strconv.FormatUint(key.GetUsedCount(), Base10),
				expiration,
				d.AsTime().Format("2006-01-02 15:04:05"),
				revoked,
				aclTags,
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

var createPreAuthKeyCmd = &cobra.Command{
	Use:     "create",
	Short:   "Creates a new preauthkey in the specified namespace",
	Aliases: []string{"c", "new"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		namespace, err := cmd.Flags().GetString("namespace")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting namespace: %s", err), output)

			return
		}

		reuseCountStr, _ := cmd.Flags().GetString("reuseCount")
		reuseCount, err := strconv.ParseUint(reuseCountStr, Base10, BitSize16)
		if err != nil {
			return
		}

		ephemeral, _ := cmd.Flags().GetBool("ephemeral")
		tags, _ := cmd.Flags().GetStringSlice("tags")

		log.Trace().
			Caller().
			Str("reuseCount", reuseCountStr).
			Bool("ephemeral", ephemeral).
			Str("namespace", namespace).
			Msg("Preparing to create preauthkey")

		request := &v1.CreatePreAuthKeyRequest{
			Namespace:  namespace,
			ReuseCount: reuseCount,
			Ephemeral:  ephemeral,
			AclTags:    tags,
		}

		durationStr, _ := cmd.Flags().GetString("expiration")

		duration, err := model.ParseDuration(durationStr)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Could not parse duration: %s\n", err),
				output,
			)

			return
		}

		expiration := time.Now().UTC().Add(time.Duration(duration))

		log.Trace().
			Caller().
			Dur("expiration", time.Duration(duration)).
			Msg("expiration has been set")

		t := ninjapanda.FormatTime(&expiration)
		request.Expiration = &t

		ctx, client, conn, cancel := getNinjapandaCLIClient()
		defer cancel()
		defer conn.Close()

		response, err := client.CreatePreAuthKey(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot create Pre Auth Key: %s\n", err),
				output,
			)

			return
		}

		SuccessOutput(response.PreAuthKey, *response.PreAuthKey.Key, output)
	},
}

var expirePreAuthKeyCmd = &cobra.Command{
	Use:     "expire KEY",
	Short:   "Expire a preauthkey",
	Aliases: []string{"revoke", "exp", "e"},
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}

		return nil
	},
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

		request := &v1.ExpirePreAuthKeyRequest{
			Namespace:    namespace,
			PreAuthKeyId: args[0],
		}

		response, err := client.ExpirePreAuthKey(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot expire Pre Auth Key: %s\n", err),
				output,
			)

			return
		}

		SuccessOutput(response, "Key expired", output)
	},
}
