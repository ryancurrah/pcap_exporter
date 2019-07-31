package pcap

import (
	"runtime"

	"github.com/pkg/errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/common/log"
	"github.com/ryancurrah/pcap_exporter/opt"
)

var (
	workers = make([]*worker, runtime.NumCPU())
	quit    = make(chan bool)
	quitAck = make(chan bool)
)

func StartCapture(device, filter string, snaplen int, promiscuous bool, options opt.Options) error {
	// start capture packets
	packetDataSource, err := pcap.OpenLive(device, int32(snaplen), promiscuous, pcap.BlockForever)
	if err != nil {
		return errors.Wrap(err, "unable to open pcap live capture")
	}
	err = packetDataSource.SetBPFFilter(filter)
	if err != nil {
		return errors.Wrap(err, "unable to set BPF filter for the pcap capture")
	}

	// start listening for packets
	packetSource := gopacket.NewPacketSource(packetDataSource, packetDataSource.LinkType())
	packetStream := make(chan gopacket.Packet, 1000)

	// start packet analysis workers
	for i := 0; i < len(workers); i++ {
		workers[i] = NewWorker(i+1, packetStream, options)
	}

	// when quit signal is sent stop packet capture
	go func() {
		<-quit
		packetDataSource.Close()
		quitAck <- true
	}()

	// keep looping packets
	go func() {
		for packet := range packetSource.Packets() {
			packetStream <- packet
		}
	}()

	log.Info("started packet capture")
	return nil
}

func StopCapture() {
	quit <- true
	<-quitAck
	log.Info("stopped packet capture")
	for _, worker := range workers {
		worker.Stop()
	}
}
