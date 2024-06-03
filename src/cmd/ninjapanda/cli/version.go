package cli

import (
	"github.com/spf13/cobra"
	ninjapanda "optm.com/ninja-panda/src"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version.",
	Long:  "The version of ninjapanda.",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		SuccessOutput(
			map[string]string{"version": ninjapanda.Version},
			ninjapanda.Version,
			output,
		)
	},
}
