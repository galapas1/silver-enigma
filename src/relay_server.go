package ninjapanda

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/Optm-Main/ztmesh-core/net/stun"
	"github.com/Optm-Main/ztmesh-core/relay"
	"github.com/Optm-Main/ztmesh-core/types/key"
	"github.com/Optm-Main/ztmesh-core/ztcfg"
)

// fastStartHeader is the header (with value "1") that signals to the HTTP
// server that the RELAY HTTP client does not want the HTTP 101 response
// headers and it will begin writing & reading the RELAY protocol immediately
// following its HTTP request.
const fastStartHeader = "Relay-Fast-Start"

type RELAYServer struct {
	RELAY  *relay.Server
	region ztcfg.RELAYRegion
}

func (np *Ninjapanda) NewRELAYServer() (*RELAYServer, error) {
	log.Trace().Caller().Msg("Creating new embedded RELAY server")

	server := relay.NewServer(key.NodePrivate(*np.privateKey), log.Info().Caller().Msgf)
	region, err := np.generateRegionLocalRELAY()
	if err != nil {
		return nil, err
	}

	return &RELAYServer{server, region}, nil
}

func (np *Ninjapanda) generateRegionLocalRELAY() (ztcfg.RELAYRegion, error) {
	serverURL, err := url.Parse(np.cfg.ServerURL)
	if err != nil {
		return ztcfg.RELAYRegion{}, err
	}
	var host string
	var port int
	host, portStr, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		if serverURL.Scheme == "https" {
			host = serverURL.Host
			port = 443
		} else {
			host = serverURL.Host
			port = 80
		}
	} else {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return ztcfg.RELAYRegion{}, err
		}
	}

	localRELAYregion := ztcfg.RELAYRegion{
		RegionID:   np.cfg.RELAY.ServerRegionID,
		RegionCode: np.cfg.RELAY.ServerRegionCode,
		RegionName: np.cfg.RELAY.ServerRegionName,
		Avoid:      false,
		Nodes: []*ztcfg.RELAYNode{
			{
				Name:      fmt.Sprintf("%d", np.cfg.RELAY.ServerRegionID),
				RegionID:  np.cfg.RELAY.ServerRegionID,
				HostName:  host,
				RELAYPort: port,
			},
		},
	}

	_, portSTUNStr, err := net.SplitHostPort(np.cfg.RELAY.STUNAddr)
	if err != nil {
		return ztcfg.RELAYRegion{}, err
	}
	portSTUN, err := strconv.Atoi(portSTUNStr)
	if err != nil {
		return ztcfg.RELAYRegion{}, err
	}
	localRELAYregion.Nodes[0].STUNPort = portSTUN

	log.Info().Caller().Msgf("RELAY region: %+v", localRELAYregion)

	return localRELAYregion, nil
}

func (np *Ninjapanda) RELAYHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Trace().Caller().Msgf("/relay request from %v", req.RemoteAddr)
	upgrade := strings.ToLower(req.Header.Get("Upgrade"))

	if upgrade != "websocket" && upgrade != "relay" {
		if upgrade != "" {
			log.Warn().
				Caller().
				Msg("No Upgrade header in RELAY server request. If ninjapanda is behind a reverse proxy, make sure it is configured to pass WebSockets through.")
		}
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusUpgradeRequired)
		_, err := writer.Write([]byte("RELAY requires connection upgrade"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	fastStart := req.Header.Get(fastStartHeader) == "1"

	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		log.Error().Caller().Msg("RELAY requires Hijacker interface from Gin")
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("HTTP does not support general TCP support"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	netConn, conn, err := hijacker.Hijack()
	if err != nil {
		log.Error().Caller().Err(err).Msgf("Hijack failed")
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err = writer.Write([]byte("HTTP does not support general TCP support"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}
	log.Trace().Caller().Msgf("Hijacked connection from %v", req.RemoteAddr)

	if !fastStart {
		pubKey := np.privateKey.Public()
		pubKeyStr := pubKey.UntypedHexString() //nolint
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: RELAY\r\n"+
			"Connection: Upgrade\r\n"+
			"Relay-Version: %v\r\n"+
			"Relay-Public-Key: %s\r\n\r\n",
			relay.ProtocolVersion,
			pubKeyStr)
	}

	np.RELAYServer.RELAY.Accept(
		req.Context(),
		netConn,
		conn,
		netConn.RemoteAddr().String(),
	)
}

// RELAYProbeHandler is the endpoint that js/wasm clients hit to measure
// RELAY latency, since they can't do UDP STUN queries.
func (np *Ninjapanda) RELAYProbeHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	switch req.Method {
	case http.MethodHead, http.MethodGet:
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		writer.WriteHeader(http.StatusOK)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
		_, err := writer.Write([]byte("bogus probe method"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}
	}
}

func (np *Ninjapanda) RELAYBootstrapDNSHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	dnsEntries := make(map[string][]net.IP)

	resolvCtx, cancel := context.WithTimeout(req.Context(), time.Minute)
	defer cancel()
	var resolver net.Resolver
	for _, region := range np.RELAYMap.Regions {
		for _, node := range region.Nodes { // we don't care if we override some nodes
			addrs, err := resolver.LookupIP(resolvCtx, "ip", node.HostName)
			if err != nil {
				log.Trace().
					Caller().
					Err(err).
					Msgf("bootstrap DNS lookup failed %q", node.HostName)

				continue
			}
			dnsEntries[node.HostName] = addrs
		}
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	err := json.NewEncoder(writer).Encode(dnsEntries)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

// ServeSTUN starts a STUN server on the configured addr.
func (np *Ninjapanda) ServeSTUN() {
	packetConn, err := net.ListenPacket("udp", np.cfg.RELAY.STUNAddr)
	if err != nil {
		log.Fatal().Caller().Msgf("failed to open STUN listener: %v", err)
	}
	log.Info().Msgf("STUN server started at %s", packetConn.LocalAddr())

	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		log.Fatal().Msg("STUN listener is not a UDP listener")
	}
	serverSTUNListener(context.Background(), udpConn)
}

func serverSTUNListener(ctx context.Context, packetConn *net.UDPConn) {
	var buf [64 << 10]byte
	var (
		bytesRead int
		udpAddr   *net.UDPAddr
		err       error
	)
	for {
		bytesRead, udpAddr, err = packetConn.ReadFromUDP(buf[:])
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Error().Caller().Err(err).Msgf("STUN ReadFrom")
			time.Sleep(time.Second)

			continue
		}
		log.Trace().Caller().Msgf("STUN request from %v", udpAddr)
		pkt := buf[:bytesRead]
		if !stun.Is(pkt) {
			log.Trace().Caller().Msgf("UDP packet is not STUN")

			continue
		}
		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("STUN parse error")

			continue
		}

		addr, _ := netip.AddrFromSlice(udpAddr.IP)
		res := stun.Response(txid, netip.AddrPortFrom(addr, uint16(udpAddr.Port)))
		_, err = packetConn.WriteTo(res, udpAddr)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("Issue writing to UDP")

			continue
		}
	}
}
