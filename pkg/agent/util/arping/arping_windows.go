package arping

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/pcap"
	"k8s.io/klog/v2"
)

// GratuitousARPOverIface sends an gratuitous arp over interface 'iface' from 'srcIP'.
// It refers to "github.com/j-keck/arping" and is simplified and made thread-safe.
func GratuitousARPOverIface(srcIP net.IP, iface *net.Interface) error {
	ipv4 := srcIP.To4()
	if ipv4 == nil {
		return fmt.Errorf("IPv6 is not supported yet")
	}

	srcMac := iface.HardwareAddr
	broadcastMac := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	request := newARPRequest(srcMac, ipv4, broadcastMac, ipv4)

	handle, err := pcap.OpenLive(iface.Name, 65535, true, time.Second)
	if err != nil {
		klog.ErrorS(err, "Failed to open network interface", "name", iface.Name)
		return err
	}
	defer handle.Close()
	if err := handle.WritePacketData(request); err != nil {
		klog.ErrorS(err, "Failed to send GARP packet")
		return err
	}
	return nil
}
