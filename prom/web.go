package prom

import (
	"net/http"

	"github.com/ryancurrah/pcap_exporter/opt"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
)

const indexHTML = `<html>
	<head>
		<title>PCAP Exporter</title>
	</head>
	<body>
		<h1>PCAP Exporter</h1>
		<p>
			<a href='/metrics'>Metrics</a>
		</p>
		<p>
			<a href='/options'>Options</a>
		</p>
		<p>
			<a href='https://github.com/ryancurrah/pcap_exporter'>Source</a>
		</p>
	</body>
</html>`

func StartExporter(address *string, options opt.Options) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(indexHTML))
		if err != nil {
			log.Errorf("unable to write index html page: %s", err)
		}
	})
	http.HandleFunc("/options", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(options.ToHTML())
		if err != nil {
			log.Errorf("unable to write options html page: %s", err)
		}
	})
	http.Handle("/metrics", promhttp.Handler())

	go func() { _ = http.ListenAndServe(*address, nil) }()

	log.Infof("started exporter at %s", *address)
	log.Infof("metrics are available at %s/metrics", *address)
}
