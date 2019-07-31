package pcap

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

func ListAvailableInterfaces() (devicesText string, err error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return devicesText, err
	}

	for _, dev := range devices {
		devicesText += fmt.Sprintf("Name: %s\nDescription: %s\nAddresses:\n", dev.Name, dev.Description)
		for _, addr := range dev.Addresses {
			devicesText += fmt.Sprintf(" - IP address: %s\n   Subnet mask: %s\n", addr.IP, addr.Netmask)
		}
		devicesText += "\n"
	}
	return devicesText, err
}
