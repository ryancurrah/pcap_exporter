package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/common/log"

	"github.com/ryancurrah/pcap_exporter/dns"
	"github.com/ryancurrah/pcap_exporter/opt"
	"github.com/ryancurrah/pcap_exporter/pcap"
	"github.com/ryancurrah/pcap_exporter/prom"
)

const (
	version = 0.2

	helpText = `   Name: pcap_exporter
Version: %v
License: Copyright (c) 2017 Philip Griesbacher
 Source: https://github.com/Griesbacher/pcap_exporter
 Source: https://github.com/ryancurrah/pcap_exporter

`

	usageText = `Notes:
- If 'l-sa' or 'l-da' is used but no address can be determined, '%s' will be set as the label value.
- If 'l-sp' or 'l-dp' is used but no port can be determined, '%s' will be set as the label value.
- If any protocol is used but no protocol can be determined, '' will be set as the label value.

Usage of %s:
`
)

var (
	device         = flag.String("i", "any", "Interface name to listen to. 'any' listens to all.")
	filter         = flag.String("f", "", "A pcap filter string. See http://www.tcpdump.org/manpages/pcap-filter.7.html for usage")
	snaplen        = flag.Int("s", 65536, "Number of bytes max to read per packet.")
	address        = flag.String("listen-address", ":9999", "Listen address with the port for the exporter.")
	promiscuous    = flag.Bool("p", false, "Use promiscuous mode.")
	resolve        = flag.Bool("r", false, "Resolve ip addresses with their DNS names.")
	listVersion    = flag.Bool("v", false, "Print exporter version.")
	listInterfaces = flag.Bool("list-interfaces", false, "Prints available interfaces and quits.")
	//logLevel       = flag.String("log-level", "error", "Log level.")
	sa = flag.Bool("l-sa", true, printLabel(opt.SourceAddress))
	sp = flag.Bool("l-sp", false, printLabel(opt.SourcePort))
	da = flag.Bool("l-da", true, printLabel(opt.DestinationAddress))
	dp = flag.Bool("l-dp", false, printLabel(opt.DestinationPort))
	lp = flag.Bool("l-lp", false, printLabel(opt.LinkProtocol))
	np = flag.Bool("l-np", false, printLabel(opt.NetworkProtocol))
	tp = flag.Bool("l-tp", false, printLabel(opt.TransportProtocol))
	ap = flag.Bool("l-ap", false, printLabel(opt.ApplicationProtocol))

	// labelFlags is a map of flag.Bool pointer options with the label name
	labelFlags = map[*bool]string{
		sa: opt.SourceAddress,
		sp: opt.SourcePort,
		da: opt.DestinationAddress,
		dp: opt.DestinationPort,
		lp: opt.LinkProtocol,
		np: opt.NetworkProtocol,
		tp: opt.TransportProtocol,
		ap: opt.ApplicationProtocol,
	}
)

func printLabel(label string) string {
	return fmt.Sprintf("Add %s to labels.", label)
}

func parseFlags() opt.Options {
	// parse user input
	flag.Parse()

	// determine which flag labels were set
	labelNames := []string{}
	for labelFlag, labelName := range labelFlags {
		if labelFlag != nil && *labelFlag {
			labelNames = append(labelNames, labelName)
		}
	}

	options := opt.Options{
		LabelNames:  labelNames,
		Device:      *device,
		Filter:      *filter,
		Snaplen:     *snaplen,
		Promiscuous: *promiscuous,
		ResolveDNS:  *resolve,
	}
	return options
}

func main() {
	// handle args
	flag.Usage = func() {
		fmt.Printf(helpText, version)
		fmt.Printf(usageText, pcap.UnknownIP, pcap.UnknownPort, os.Args[0])
		flag.PrintDefaults()
	}
	options := parseFlags()

	// list version
	if *listVersion {
		fmt.Print(version)
		os.Exit(0)
	}

	// list all interfaces
	if *listInterfaces {
		interfacesText, err := pcap.ListAvailableInterfaces()
		if err != nil {
			log.Fatalf("unable to get a list of all available interfaces: %s", err)
		}
		fmt.Printf("available interfaces:\n\n%s", interfacesText)
		os.Exit(0)
	}

	// listen for exit signal
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, os.Kill, syscall.SIGTERM)

	// register prometheus metrics
	prom.RegisterMetrics(options.GetLabelNames())

	// start dns storage cache
	dns.Start()
	defer dns.Stop()

	// start pcap capture and analysis
	err := pcap.StartCapture(*device, *filter, *snaplen, *promiscuous, options)
	if err != nil {
		log.Fatal(err)
	}
	defer pcap.StopCapture()

	// start prometheus exporter
	prom.StartExporter(address, options)

PcapExporterLoop:
	for {
		select {
		case sig := <-signals:
			log.Warnf("received exit signal %s, quitting now...", sig)
			break PcapExporterLoop
		}
	}
}
