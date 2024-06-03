package cli

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(serveCmd)
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Launches the ninjapanda server",
	Args: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		app, err := getNinjapandaApp()
		if err != nil {
			log.Fatal().Caller().Err(err).Msg("Error initializing")
		}

		err = app.Serve()
		if err != nil {
			log.Fatal().Caller().Err(err).Msg("Error starting server")
		}
	},
}
