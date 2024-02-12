// Allows sending of [gratuitous ARP] replies on an interface.
// This potentially populate the ARP table of the peer, speeding up
// connectivity between the two peers if they have not yet communicated.
//
// [gratuitous ARP]: https://wiki.wireshark.org/Gratuitous_ARP
package gratuitous_arp

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"net"

	"github.com/mdlayher/ethernet"
	"github.com/songgao/ether"
)

// Returns interfaces which are acceptable to send ARP replies on:
//
//   - They must not be Loopback
//   - They must be up
//   - They must have at least 1 IPv4 address
func ArpNetInterfaces() ([]net.Interface, error) {
	ret := []net.Interface{}
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifa := range ifas {
		if ifa.Flags&net.FlagLoopback == net.FlagLoopback {
			continue
		}
		if ifa.Flags&net.FlagUp == 0 {
			continue
		}

		ipas, err := ifa.Addrs()
		if err != nil {
			return nil, err
		}

		ipv4AddrCount := 0
		for _, ipa := range ipas {
			ip, _, err := net.ParseCIDR(ipa.String())
			if err != nil {
				return nil, err
			}
			if ip.To4() != nil {
				ipv4AddrCount++
			}
		}

		if ipv4AddrCount == 0 {
			continue
		}

		slog.Debug("Found netdev %s with hwaddr %s\n", ifa.Name, ifa.HardwareAddr.String())
		ret = append(ret, ifa)
	}
	return ret, nil
}

// Sends a gratuitous ARP on a net.Interface, provided
// the interface meets the same criteria as in ArpNetInterfaces.
func SendGarpOnIface(ifa net.Interface) error {
	if ifa.Flags&net.FlagUp == 0 {
		return errors.New("Interface is down")
	}

	ipas, err := ifa.Addrs()
	if err != nil {
		return err
	}

	for _, ipa := range ipas {
		slog.Debug("net: %s, str: %s\n", ipa.Network(), ipa.String())
		ip, net, err := net.ParseCIDR(ipa.String())
		if err != nil {
			return err
		}
		if ip.To4() == nil {
			continue
		}

		garp := makeGarp(ifa.HardwareAddr, ip, net.Mask)
		garpBytes, err := garp.MarshalBinary()
		if err != nil {
			return err
		}

		dev, err := ether.NewDev(&ifa, nil)
		if err != nil {
			return err
		}

		err = dev.Write(garpBytes)
		if err != nil {
			return err
		}

		slog.Info("ARP Sent", "interface", ifa.Name, "hwaddr", ifa.HardwareAddr.String(), "ip", ip.String())
	}
	return nil
}

func garpPayload(mac net.HardwareAddr, ip net.IP, mask net.IPMask) []byte {
	// https://datatracker.ietf.org/doc/html/rfc826
	// https://datatracker.ietf.org/doc/html/rfc5227
	ip = ip.To4()
	b := make([]byte, 28)
	// ethernet
	hwType := 1
	protoType := uint16(ethernet.EtherTypeIPv4)
	hwAddrLen := uint8(6)    // mac len
	protoAddrLen := uint8(4) // ipv4 len
	opcode := uint16(2)      // reply

	binary.BigEndian.PutUint16(b[0:2], uint16(hwType))
	binary.BigEndian.PutUint16(b[2:4], protoType)
	b[4] = hwAddrLen
	b[5] = protoAddrLen
	binary.BigEndian.PutUint16(b[6:8], opcode)
	copy(b[8:8+hwAddrLen], mac)
	copy(b[14:14+protoAddrLen], ip)
	copy(b[18:18+hwAddrLen], ethernet.Broadcast)
	copy(b[24:24+protoAddrLen], ip)
	return b
}

func makeGarp(mac net.HardwareAddr, ip net.IP, mask net.IPMask) ethernet.Frame {
	payload := garpPayload(mac, ip, mask)
	return ethernet.Frame{
		Destination: ethernet.Broadcast,
		Source:      mac,
		EtherType:   ethernet.EtherTypeARP,
		Payload:     payload,
	}
}
