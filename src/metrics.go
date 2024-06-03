package ninjapanda

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const prometheusNamespace = "ninjapanda"

var (
	requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "request_duration_seconds",
		Help:      "Time (in seconds) spent serving a given HTTP request.",
	}, []string{"method", "route", "status_code"})

	machineRegistrations = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "machine_registrations_total",
		Help:      "The total number of client registration attempts for a namespace",
	}, []string{"action", "auth", "status", "namespace"})

	machineMapRequests = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "machine_map_requests_duration_seconds",
		Help:      "Time (in seconds) spent serving machine map request when a client initially connects to ninjapanda",
	}, []string{"status"})

	updateRequestsSentToMachine = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "update_request_sent_to_node_total",
		Help:      "The number of updates issued on a node's update channel",
	}, []string{"namespace", "machine", "status"})

	redisCacheErrorCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "redis_cache_error_total",
		Help:      "The number of errors seen when communicating with Redis; non-zero indicates HA is in distress",
	})

	cacheCorrelationIdsInsertedCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "cache_correlation_ids_inserted_total",
		Help:      "The number of correlation IDs inserted in the cache; as a 'correlation ID' is unique for every registration request, this indicates total number of registration requests",
	})

	cacheCorrelationIdsCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Name:      "cache_correlation_ids_count",
		Help:      "The number of correlation IDs in the cache; this indicates total number of in-flight registrations happening",
	})

	totalConnectedClients = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Name:      "total_connected_clients",
		Help:      "Total number of clients connected to a given ninjapanda instance",
	})

	clientUpdateLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "client_update_latency",
		Help:      "Time (in seconds) spent serving a given change (see update_type for specific change applied).",
	}, []string{"update_type"})
)

func initMetrics() {
	initFeaturePicker()

	prometheus.MustRegister(clientUpdateLatency)
	prometheus.MustRegister(requestDuration)
	prometheus.MustRegister(machineMapRequests)
}
