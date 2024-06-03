package ninjapanda

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/rs/zerolog/log"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/Optm-Main/ztmesh-core/control/controlbase"
	"github.com/Optm-Main/ztmesh-core/control/controlhttp"
	"github.com/Optm-Main/ztmesh-core/net/netutil"
)

const (
	// ts2021UpgradePath is the path that the server listens on for the WebSockets upgrade.
	ts2021UpgradePath  = "/ts2021"
	ztm2023UpgradePath = "/ztm2023"
)

type ts2021App struct {
	ninjapanda *Ninjapanda

	conn *controlbase.Conn
}

// NoiseUpgradeHandler is to upgrade the connection and hijack the net.Conn
// in order to use the Noise-based TS2021 protocol. Listens in /ts2021.
func (np *Ninjapanda) NoiseUpgradeHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Trace().Caller().
		Str(logtags.MakeTag("Upgrade"), req.Header.Get("Upgrade")).
		Str(logtags.MakeTag("ZtmeshUpgrade"), req.Header.Get(controlhttp.UpgradeHeaderName)).
		Str(logtags.MakeTag("Connection"), req.Header.Get("Connection")).
		Str(logtags.MakeTag("ZtmeshConnection"), req.Header.Get("X-ZTMesh-Connection")).
		Str(logtags.GetTag(logtags.httpRequest, "RemoteAddr"), req.RemoteAddr).
		Msg("Noise upgrade handler.")

	upgrade := req.Header.Get("Upgrade")
	if upgrade == "" {
		// This probably means that the user is running Ninjapanda behind an
		// improperly configured reverse proxy. TS2021 requires WebSockets to
		// be passed to Ninjapanda. Let's give them a hint.
		log.Warn().
			Caller().
			Msg("No Upgrade header in TS2021 request. If ninjapanda is behind a reverse proxy, make sure it is configured to pass WebSockets through.")
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		return
	}

	noiseConn, err := controlhttp.AcceptHTTP(
		req.Context(),
		writer,
		req,
		*np.noisePrivateKey,
		nil,
	)

	log.Trace().Caller().
		Str(logtags.MakeTag("Upgrade"), writer.Header().Get("Upgrade")).
		Str(logtags.MakeTag("Connection"), writer.Header().Get("Connection")).
		Msg("Response headers Noise upgrade handler.")

	if err != nil {
		log.Error().Caller().
			Err(err).
			Interface(logtags.GetTag(logtags.httpRequest, "Header"), req.Header).
			Msg("noise upgrade failed")
		http.Error(writer, err.Error(), http.StatusInternalServerError)

		return
	}

	ts2021App := ts2021App{
		ninjapanda: np,
		conn:       noiseConn,
	}

	// This router is served only over the Noise connection, and exposes only the new API.
	//
	// The HTTP2 server that exposes this router is created for
	// a single hijacked connection from /ts2021, using netutil.NewOneConnListener
	router := mux.NewRouter()

	router.HandleFunc("/machine/register", ts2021App.NoiseRegistrationHandler).
		Methods(http.MethodPost)
	router.HandleFunc("/machine/map", ts2021App.NoisePollNetMapHandler)

	server := http.Server{
		ReadTimeout: HTTPReadTimeout,
	}
	server.Handler = h2c.NewHandler(router, &http2.Server{})
	err = server.Serve(netutil.NewOneConnListener(noiseConn, nil))
	if err != nil {
		log.Info().Msg("The HTTP2 server was closed")
	}
}
