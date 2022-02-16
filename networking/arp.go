package networking

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func CreatePacket(
	srcMAC net.HardwareAddr,
	srcIP net.IP,
	dstMAC net.HardwareAddr,
	dstIP net.IP,
	arpOpcode uint16) []byte {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         arpOpcode,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    []byte(dstIP.To4()),
	}
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	return buf.Bytes()
}
