package cli

import (
	"fmt"

	"github.com/Optm-Main/ztmesh-core/types/key"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.AddCommand(generatePrivateKeyCmd)
}

var generateCmd = &cobra.Command{
	Use:     "generate",
	Short:   "Generate commands",
	Aliases: []string{"gen"},
}

var generatePrivateKeyCmd = &cobra.Command{
	Use:   "private-key",
	Short: "Generate a private key for the ninjapanda server",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		machineKey := key.NewMachine()

		machineKeyStr, err := machineKey.MarshalText()
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting machine key from flag: %s", err),
				output,
			)
		}

		SuccessOutput(map[string]string{
			"private_key": string(machineKeyStr),
		},
			string(machineKeyStr), output)
	},
}
