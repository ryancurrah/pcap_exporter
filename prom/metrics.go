package prom

import (
	"github.com/prometheus/client_golang/prometheus"
)

const NameSpace = "pcap"

var (
	BytesTransferred *prometheus.CounterVec
	BufferLen        = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: NameSpace,
			Name:      "buffer_len",
			Help:      "Fill state of the internal buffer",
		},
	)
	Packets = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: NameSpace,
			Name:      "packets",
			Help:      "Amount of packets seen",
		},
	)
	DNSQueryDuration = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: NameSpace,
			Name:      "dns_query_duration",
			Help:      "Duration in seconds per DNS query",
		},
	)
)

func RegisterMetrics(labelNames []string) {
	BytesTransferred = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: NameSpace,
			Name:      "bytes_transferred",
			Help:      "Amount of bytes transferred",
		},
		labelNames,
	)
	prometheus.MustRegister(BytesTransferred)
	prometheus.MustRegister(BufferLen)
	prometheus.MustRegister(Packets)
	prometheus.MustRegister(DNSQueryDuration)
}
