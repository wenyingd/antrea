package arping

import (
	"fmt"
	"net"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"k8s.io/klog/v2"
)

// GratuitousARPOverIface sends an gratuitous arp over interface 'iface' from 'srcIP'.
// It refers to "github.com/j-keck/arping" and is simplified and made thread-safe.
func GratuitousARPOverIface(srcIP net.IP, iface *net.Interface) error {
	ipv4 := srcIP.To4()
	if ipv4 == nil {
		return fmt.Errorf("IPv6 is not supported yet")
	}

	arpPacket, err := arp.NewPacket(arp.OperationRequest, iface.HardwareAddr, srcIP, ethernet.Broadcast, srcIP)
	if err != nil {
		return fmt.Errorf("failed to generate GARP packet with IP %s: %v", srcIP.String(), err)
	}

	conn, err := arp.Dial(iface)
	if err != nil {
		return fmt.Errorf("creating ARP responder for %q: %s", iface.Name, err)
	}
	defer conn.Close()

	if err := conn.WriteTo(arpPacket, iface.HardwareAddr); err != nil {
		klog.ErrorS(err, "Failed to send GARP packet")
		return err
	}
	return nil
}
