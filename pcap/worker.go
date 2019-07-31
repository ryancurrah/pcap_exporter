package pcap

import (
	"time"

	"github.com/google/gopacket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/ryancurrah/pcap_exporter/dns"
	"github.com/ryancurrah/pcap_exporter/opt"
	"github.com/ryancurrah/pcap_exporter/prom"
)

var nilEndpoint = gopacket.NewEndpoint(-1, []byte(""))

const (
	UnknownIP   = "-1.-1.-1.-1"
	UnknownPort = "-1"
)

type worker struct {
	number       int
	stop         chan bool
	stopAck      chan bool
	packetStream chan gopacket.Packet
	options      opt.Options
}

func NewWorker(number int, packetStream chan gopacket.Packet, options opt.Options) *worker {
	w := &worker{
		number:       number,
		stop:         make(chan bool),
		stopAck:      make(chan bool),
		packetStream: packetStream,
		options:      options,
	}
	w.run()
	return w
}

func (w worker) run() {
	go func() {
		for true {
			select {
			case <-w.stop:
				w.stopAck <- true
				return
			case packet := <-w.packetStream:
				// analyse packet
				w.analysePacket(len(w.packetStream), packet)
			}
		}
	}()
	log.Infof("started packet analysis worker #%d", w.number)
}

func (w worker) Stop() {
	select {
	case w.stop <- true:
		select {
		case <-w.stopAck:
			log.Infof("stopped packet analysis worker #%d", w.number)
			return
		case <-time.After(10 * time.Second):
			log.Warnf("killing packet analysis worker #%d, due to not acknowledging stop", w.number)
		}
	case <-time.After(20 * time.Second):
		log.Warnf("killing packet analysis worker #%d, due to not stopping on time", w.number)
	}
}

func (w worker) analysePacket(bufferLen int, packet gopacket.Packet) {
	// add buffer_len metric
	prom.BufferLen.Set(float64(bufferLen))

	// add packet count metric
	prom.Packets.Add(1)

	// add bytes_transferred metric
	if packet != nil {
		srcAdr, dstAdr := nilEndpoint, nilEndpoint
		if packet.NetworkLayer() != nil {
			srcAdr, dstAdr = packet.NetworkLayer().NetworkFlow().Endpoints()
		}

		srcPort, dstPort := nilEndpoint, nilEndpoint
		if packet.TransportLayer() != nil {
			srcPort, dstPort = packet.TransportLayer().TransportFlow().Endpoints()
		}

		labels := prometheus.Labels{}
		for _, name := range w.options.GetLabelNames() {
			switch name {
			case opt.DestinationAddress:
				labels[name] = w.printHost(dstAdr)
			case opt.DestinationPort:
				labels[name] = w.printPort(dstPort)
			case opt.SourceAddress:
				labels[name] = w.printHost(srcAdr)
			case opt.SourcePort:
				labels[name] = w.printPort(srcPort)
			case opt.LinkProtocol, opt.NetworkProtocol, opt.TransportProtocol, opt.ApplicationProtocol:
				labels[name] = printProtocol(packet, name)
			default:
				log.Warnf("got unknown label name: %s", name)
			}
		}
		prom.BytesTransferred.With(labels).Add(float64(packet.Metadata().CaptureLength))
	}
}

func (w worker) printPort(e gopacket.Endpoint) string {
	if e.EndpointType() == nilEndpoint.EndpointType() {
		return UnknownPort
	}
	return e.String()
}

func (w worker) printHost(e gopacket.Endpoint) string {
	if e.EndpointType() == nilEndpoint.EndpointType() {
		return UnknownIP
	}

	if w.options.ResolveDNS {
		record, lookupTime, err := dns.ReverseLookup(e.String())
		if err != nil {
			log.Debug(err)
			return e.String()
		}

		if record != "" {
			if lookupTime != 0.0 {
				prom.DNSQueryDuration.Set(lookupTime)
			}
			return record
		}
	}
	return e.String()
}

func printProtocol(packet gopacket.Packet, labelName string) string {
	switch labelName {
	case opt.LinkProtocol:
		if packet.LinkLayer() != nil {
			return packet.LinkLayer().LayerType().String()
		}
	case opt.NetworkProtocol:
		if packet.NetworkLayer() != nil {
			return packet.NetworkLayer().LayerType().String()
		}
	case opt.TransportProtocol:
		if packet.TransportLayer() != nil {
			return packet.TransportLayer().LayerType().String()
		}
	case opt.ApplicationProtocol:
		if packet.ApplicationLayer() != nil {
			return packet.ApplicationLayer().LayerType().String()
		}
	}
	return ""
}
