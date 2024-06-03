package ninjapanda

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"

	textTemplate "text/template"

	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"

	"github.com/rs/zerolog/log"
)

//go:embed templates/apple.html
var appleTemplate string

//go:embed templates/windows.html
var windowsTemplate string

// WindowsConfigMessage shows a simple message in the browser for how to configure the Windows client.
func (np *Ninjapanda) WindowsConfigMessage(
	writer http.ResponseWriter,
	req *http.Request,
) {
	winTemplate := template.Must(template.New("windows").Parse(windowsTemplate))
	config := map[string]interface{}{
		"URL": np.cfg.ServerURL,
	}

	var payload bytes.Buffer
	if err := winTemplate.Execute(&payload, config); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not render Windows index template")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Could not render Windows index template"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err := writer.Write(payload.Bytes())
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

// WindowsRegConfig generates and serves a .reg file configured with the Ninjapanda server address.
func (np *Ninjapanda) WindowsRegConfig(
	writer http.ResponseWriter,
	req *http.Request,
) {
	config := WindowsRegistryConfig{
		URL: np.cfg.ServerURL,
	}

	var content bytes.Buffer
	if err := windowsRegTemplate.Execute(&content, config); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not render Apple macOS template")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Could not render Windows registry template"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	writer.Header().Set("Content-Type", "text/x-ms-regedit; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err := writer.Write(content.Bytes())
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

// AppleConfigMessage shows a simple message in the browser to point the user to the iOS/MacOS profile and instructions for how to install it.
func (np *Ninjapanda) AppleConfigMessage(
	writer http.ResponseWriter,
	req *http.Request,
) {
	appleTemplate := template.Must(template.New("apple").Parse(appleTemplate))

	config := map[string]interface{}{
		"URL": np.cfg.ServerURL,
	}

	var payload bytes.Buffer
	if err := appleTemplate.Execute(&payload, config); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not render Apple index template")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Could not render Apple index template"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err := writer.Write(payload.Bytes())
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

func (np *Ninjapanda) ApplePlatformConfig(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	platform, ok := vars["platform"]
	if !ok {
		log.Error().
			Caller().
			Msg("No platform specified")
		http.Error(writer, "No platform specified", http.StatusBadRequest)

		return
	}

	id, err := uuid.NewV4()
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed not create UUID")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Failed to create UUID"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	contentID, err := uuid.NewV4()
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed not create UUID")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Failed to create content UUID"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	platformConfig := AppleMobilePlatformConfig{
		UUID: contentID,
		URL:  np.cfg.ServerURL,
	}

	var payload bytes.Buffer
	handleMacError := func(ierr error) {
		log.Error().
			Caller().
			Err(ierr).
			Msg("Could not render Apple macOS template")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Could not render Apple macOS template"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}
	}

	switch platform {
	case "macos-standalone":
		if err := macosStandaloneTemplate.Execute(&payload, platformConfig); err != nil {
			handleMacError(err)

			return
		}
	case "macos-app-store":
		if err := macosAppStoreTemplate.Execute(&payload, platformConfig); err != nil {
			handleMacError(err)

			return
		}
	case "ios":
		if err := iosTemplate.Execute(&payload, platformConfig); err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Could not render Apple iOS template")

			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.WriteHeader(http.StatusInternalServerError)
			_, err := writer.Write([]byte("Could not render Apple iOS template"))
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Failed to write response")
			}

			return
		}
	default:
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write(
			[]byte(
				"Invalid platform. Only ios, macos-app-store and macos-standalone are supported",
			),
		)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	config := AppleMobileConfig{
		UUID:    id,
		URL:     np.cfg.ServerURL,
		Payload: payload.String(),
	}

	var content bytes.Buffer
	if err := commonTemplate.Execute(&content, config); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not render Apple platform template")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("Could not render Apple platform template"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	writer.Header().
		Set("Content-Type", "application/x-apple-aspen-config; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(content.Bytes())
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

type WindowsRegistryConfig struct {
	URL string
}

type AppleMobileConfig struct {
	UUID    uuid.UUID
	URL     string
	Payload string
}

type AppleMobilePlatformConfig struct {
	UUID uuid.UUID
	URL  string
}

var windowsRegTemplate = textTemplate.Must(
	textTemplate.New("windowsconfig").Parse(`Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\ZTMESH IPN]
"UnattendedMode"="always"
"LoginURL"="{{.URL}}"
`))

var commonTemplate = textTemplate.Must(
	textTemplate.New("mobileconfig").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>PayloadUUID</key>
    <string>{{.UUID}}</string>
    <key>PayloadDisplayName</key>
    <string>Ninjapanda</string>
    <key>PayloadDescription</key>
    <string>Configure ZTMesh login server to: {{.URL}}</string>
    <key>PayloadIdentifier</key>
    <string>optm.com/ninja-panda</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>
    {{.Payload}}
    </array>
  </dict>
</plist>`),
)

var iosTemplate = textTemplate.Must(textTemplate.New("iosTemplate").Parse(`
    <dict>
        <key>PayloadType</key>
        <string>io.optm.ipn.ios</string>
        <key>PayloadUUID</key>
        <string>{{.UUID}}</string>
        <key>PayloadIdentifier</key>
        <string>optm.com/ninja-panda</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>PayloadEnabled</key>
        <true/>

        <key>ControlURL</key>
        <string>{{.URL}}</string>
    </dict>
`))

var macosAppStoreTemplate = template.Must(template.New("macosTemplate").Parse(`
    <dict>
        <key>PayloadType</key>
        <string>io.optm.ipn.macos</string>
        <key>PayloadUUID</key>
        <string>{{.UUID}}</string>
        <key>PayloadIdentifier</key>
        <string>optm.com/ninja-panda</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>PayloadEnabled</key>
        <true/>
        <key>ControlURL</key>
        <string>{{.URL}}</string>
    </dict>
`))

var macosStandaloneTemplate = template.Must(
	template.New("macosStandaloneTemplate").Parse(`
    <dict>
        <key>PayloadType</key>
        <string>io.optm.ipn.macsys</string>
        <key>PayloadUUID</key>
        <string>{{.UUID}}</string>
        <key>PayloadIdentifier</key>
        <string>optm.com/ninja-panda</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>PayloadEnabled</key>
        <true/>
        <key>ControlURL</key>
        <string>{{.URL}}</string>
    </dict>
`),
)
