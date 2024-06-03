package cli

import (
	"fmt"

	survey "github.com/AlecAivazis/survey/v2"

	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"google.golang.org/grpc/status"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
	ninjapanda "optm.com/ninja-panda/src"
)

func init() {
	rootCmd.AddCommand(namespaceCmd)
	createNamespaceCmd.Flags().
		StringP("duration", "d", "30d", "Duration, in the form of amount and time unit (30d, 15h, 60m)")
	namespaceCmd.AddCommand(createNamespaceCmd)
	namespaceCmd.AddCommand(listNamespacesCmd)
	namespaceCmd.AddCommand(destroyNamespaceCmd)
	namespaceCmd.AddCommand(renameNamespaceCmd)
}

const (
	errMissingParameter = ninjapanda.Error("missing parameters")
)

var namespaceCmd = &cobra.Command{
	Use:     "namespaces",
	Short:   "Manage the namespaces of Ninjapanda",
	Aliases: []string{"namespace", "ns", "user", "users"},
}

var createNamespaceCmd = &cobra.Command{
	Use:     "create NAME",
	Short:   "Creates a new namespace",
	Aliases: []string{"c", "new"},
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		duration, _ := cmd.Flags().GetString("duration")
		namespaceName := args[0]

		ctx, client, conn, cancel := getNinjapandaCLIClient()
		defer cancel()
		defer conn.Close()

		log.Trace().Caller().Interface("client", client).Msg("Obtained gRPC client")

		request := &v1.CreateNamespaceRequest{
			Name:                 namespaceName,
			DefaultMachineKeyTtl: &duration,
		}

		log.Trace().
			Caller().
			Interface("request", request).
			Msg("Sending CreateNamespace request")
		response, err := client.CreateNamespace(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Cannot create namespace: %s",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		SuccessOutput(response.Namespace, "Namespace created", output)
	},
}

var destroyNamespaceCmd = &cobra.Command{
	Use:     "destroy NAME",
	Short:   "Destroys a namespace",
	Aliases: []string{"delete"},
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		namespaceName := args[0]

		request := &v1.GetNamespaceRequest{
			Name: namespaceName,
		}

		ctx, client, conn, cancel := getNinjapandaCLIClient()
		defer cancel()
		defer conn.Close()

		_, err := client.GetNamespace(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error: %s", status.Convert(err).Message()),
				output,
			)

			return
		}

		confirm := false
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			prompt := &survey.Confirm{
				Message: fmt.Sprintf(
					"Do you want to remove the namespace '%s' and any associated preauthkeys?",
					namespaceName,
				),
			}
			err := survey.AskOne(prompt, &confirm)
			if err != nil {
				return
			}
		}

		if confirm || force {
			request := &v1.DeleteNamespaceRequest{Name: namespaceName}

			response, err := client.DeleteNamespace(ctx, request)
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf(
						"Cannot destroy namespace: %s",
						status.Convert(err).Message(),
					),
					output,
				)

				return
			}
			SuccessOutput(response, "Namespace destroyed", output)
		} else {
			SuccessOutput(map[string]string{"Result": "Namespace not destroyed"}, "Namespace not destroyed", output)
		}
	},
}

var listNamespacesCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all the namespaces",
	Aliases: []string{"ls", "show"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		ctx, client, conn, cancel := getNinjapandaCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.ListNamespacesRequest{}

		response, err := client.ListNamespaces(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot get namespaces: %s", status.Convert(err).Message()),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response.Namespaces, "", output)

			return
		}

		tableData := pterm.TableData{{"Name", "Created"}}
		for _, namespace := range response.GetNamespaces() {
			d := ninjapanda.ParseTime(namespace.GetCreatedAt())
			tableData = append(
				tableData,
				[]string{
					namespace.GetName(),
					d.AsTime().Format("2006-01-02 15:04:05"),
				},
			)
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

var renameNamespaceCmd = &cobra.Command{
	Use:     "rename OLD_NAME NEW_NAME",
	Short:   "Renames a namespace",
	Aliases: []string{"mv"},
	Args: func(cmd *cobra.Command, args []string) error {
		expectedArguments := 2
		if len(args) < expectedArguments {
			return errMissingParameter
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		ctx, client, conn, cancel := getNinjapandaCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.RenameNamespaceRequest{
			OldName: args[0],
			NewName: args[1],
		}

		response, err := client.RenameNamespace(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Cannot rename namespace: %s",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		SuccessOutput(response.Namespace, "Namespace renamed", output)
	},
}
