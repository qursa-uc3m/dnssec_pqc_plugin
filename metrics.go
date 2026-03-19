package dnssec_pqc

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// cacheSize is the number of elements in the dnssec cache.
	cacheSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnssec_pqc",
		Name:      "cache_entries",
		Help:      "The number of elements in the dnssec_pqc cache.",
	}, []string{"server", "type"})
	// cacheHits is the count of cache hits.
	cacheHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnssec_pqc",
		Name:      "cache_hits_total",
		Help:      "The count of cache hits.",
	}, []string{"server"})
	// cacheMisses is the count of cache misses.
	cacheMisses = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnssec_pqc",
		Name:      "cache_misses_total",
		Help:      "The count of cache misses.",
	}, []string{"server"})
	// signDuration is a histogram of per-signing wall-clock time.
	signDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnssec_pqc",
		Name:      "sign_duration_seconds",
		Help:      "Histogram of DNSSEC signing latency (seconds), including any simulated delay.",
		Buckets:   []float64{0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	}, []string{"server"})
	// singleflightCoalesced counts how many goroutines joined an in-flight Do() call
	// instead of executing the signing function themselves.
	singleflightCoalesced = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnssec_pqc",
		Name:      "singleflight_coalesced_total",
		Help:      "Number of sign requests that shared an in-flight singleflight.Do() result.",
	}, []string{"server"})
	// singleflightExecs counts the actual signing executions (the "leader" of each Do group).
	singleflightExecs = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnssec_pqc",
		Name:      "singleflight_execs_total",
		Help:      "Number of actual signing executions (singleflight.Do leaders).",
	}, []string{"server"})
)
