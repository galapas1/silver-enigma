package ninjapanda

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"

	ocodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/Optm-Main/ztmesh-core/types/key"
)

const (
	registrationHoldoff                      = time.Second * 5
	reservedResponseHeaderSize               = 4
	RegisterMethodAuthKey                    = "authkey"
	RegisterMethodOIDC                       = "oidc"
	RegisterMethodAPI                        = "api"
	RegisterMethodCallback                   = "callback"
	ErrRegisterMethodCLIDoesNotSupportExpire = Error(
		"machines registered with CLI does not support expire",
	)
)

func (np *Ninjapanda) HealthHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	span := trace.SpanFromContext(req.Context())

	respond := func(err error) {
		writer.Header().Set("Content-Type", "application/health+json; charset=utf-8")

		res := struct {
			Status string `json:"status"`
		}{
			Status: "pass",
		}

		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			log.Error().Caller().Err(err).Msg("health check failed")
			res.Status = "fail"

			span.SetStatus(ocodes.Error, "health check failed")
			span.RecordError(err)
		}

		buf, err := json.Marshal(res)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)
			log.Error().Caller().Err(err).Msg("marshal failed")
		}
		_, err = writer.Write(buf)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)
			log.Error().Caller().Err(err).Msg("write failed")
		}
	}

	span.AddEvent("pingDB")
	if err := np.pingDB(req.Context()); err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)
		respond(err)

		return
	}

	respond(nil)
}

type registerWebAPITemplateConfig struct {
	Key string
}

var registerWebAPITemplate = template.Must(
	template.New("registerweb").Parse(`
<html>
	<head>
		<title>Registration - Ninjapanda</title>
	</head>
	<body>
		<h1>ninjapanda</h1>
		<h2>Machine registration</h2>
		<p>
			Run the command below in the ninjapanda server to add this machine to your network:
		</p>
		<pre><code>ninjapanda -n NAMESPACE nodes register --key {{.Key}}</code></pre>
	</body>
</html>
`))

// RegisterWebAPI shows a simple message in the browser to point to the CLI
// Listens in /register/:nkey.
//
// This is not part of the control API, as we could send whatever URL
// in the RegisterResponse.AuthURL field.
func (np *Ninjapanda) RegisterWebAPI(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	nodeKeyStr, ok := vars["nkey"]

	if !NodePublicKeyRegex.Match([]byte(nodeKeyStr)) {
		log.Warn().
			Caller().
			Str(logtags.GetTag(logtags.machine, "NodeKey"), nodeKeyStr).
			Msg("invalid node key passed to registration url")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusUnauthorized)
		_, err := writer.Write([]byte("Unauthorized"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("failed to write response")
		}

		return
	}

	// We need to make sure we dont open for XSS style injections, if the parameter that
	// is passed as a key is not parsable/validated as a NodePublic key, then fail to render
	// the template and log an error.
	var nodeKey key.NodePublic
	err := nodeKey.UnmarshalText(
		[]byte(NodePublicKeyEnsurePrefix(nodeKeyStr)),
	)

	if !ok || nodeKeyStr == "" || err != nil {
		log.Warn().Caller().Err(err).Msg("Failed to parse incoming nodekey")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("Wrong params"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	var content bytes.Buffer
	if err := registerWebAPITemplate.Execute(&content, registerWebAPITemplateConfig{
		Key: nodeKeyStr,
	}); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not render register web API template")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err = writer.Write([]byte("Could not render register web API template"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("failed to write response")
		}

		return
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(content.Bytes())
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("failed to write response")
	}
}

func (np *Ninjapanda) VersionHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	type innerVersion struct {
		Version string
	}
	version := innerVersion{
		Version: Version,
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(version)
}
