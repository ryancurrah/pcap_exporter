package opt

import (
	"fmt"
	"sort"
	"strings"
)

const (
	SourceAddress       = "SourceAddress"
	SourcePort          = "SourcePort"
	DestinationAddress  = "DestinationAddress"
	DestinationPort     = "DestinationPort"
	LinkProtocol        = "LinkProtocol"
	NetworkProtocol     = "NetworkProtocol"
	TransportProtocol   = "TransportProtocol"
	ApplicationProtocol = "ApplicationProtocol"
)

type LabelNames []string

type Options struct {
	LabelNames  LabelNames
	ResolveDNS  bool
	Device      string
	Filter      string
	Snaplen     int
	Promiscuous bool
}

func (o *Options) GetLabelNames() LabelNames {
	sort.Strings(o.LabelNames)
	return o.LabelNames
}

func (o Options) String() string {
	toPrint := fmt.Sprintf("Labels: %s", strings.Join(o.GetLabelNames(), ","))
	toPrint += fmt.Sprintf("\nResolveDNS: %t\n", o.ResolveDNS)
	toPrint += fmt.Sprintf("Device: %s\n", o.Device)
	toPrint += fmt.Sprintf("Filter: %s\n", o.Filter)
	toPrint += fmt.Sprintf("Snaplen: %d\n", o.Snaplen)
	toPrint += fmt.Sprintf("Promiscuous: %t\n", o.Promiscuous)
	return toPrint
}

func (o Options) ToHTML() []byte {
	return []byte(fmt.Sprintf("<html><body><pre>\n%s\n</pre></body></html>", o.String()))
}
