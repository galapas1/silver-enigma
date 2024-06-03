package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

func init() {
	rootCmd.AddCommand(healthCmd)
}

var healthCmd = &cobra.Command{
	Use:     "health",
	Short:   "Check the health of Ninjapanda",
	Aliases: []string{"x", "health"},

	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		ctx, client, conn, cancel := getNinjapandaCLIClient()
		defer cancel()
		defer conn.Close()

		response, err := client.CheckHealth(ctx, &v1.CheckHealthRequest{})
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Failed to do health check : %s",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response, "", output)

			return
		}
	},
}
