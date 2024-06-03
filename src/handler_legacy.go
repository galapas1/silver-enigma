package ninjapanda

import (
	"net/http"

	"github.com/gorilla/mux"
)

func (np *Ninjapanda) addLegacyHandlers(router *mux.Router) {
	router.HandleFunc("/machine/{mkey}/map", np.PollNetMapHandler).
		Methods(http.MethodPost)
	router.HandleFunc("/machine/{mkey}", np.RegistrationHandler).
		Methods(http.MethodPost)
}
