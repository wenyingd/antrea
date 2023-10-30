// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipassigner

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/pkg/agent/ipassigner/responder"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/util/arping"
	"antrea.io/antrea/pkg/agent/util/ndp"
	"antrea.io/antrea/pkg/agent/util/sysctl"
)

type dummyInterfaceType netlink.Link

// getARPIgnoreForInterface gets the max value of conf/{all,interface}/arp_ignore form sysctl.
func getARPIgnoreForInterface(iface string) (int, error) {
	arpIgnoreAll, err := sysctl.GetSysctlNet("ipv4/conf/all/arp_ignore")
	if err != nil {
		return 0, fmt.Errorf("failed to get arp_ignore for all interfaces: %w", err)
	}
	arpIgnore, err := sysctl.GetSysctlNet(fmt.Sprintf("ipv4/conf/%s/arp_ignore", iface))
	if err != nil {
		return 0, fmt.Errorf("failed to get arp_ignore for %s: %w", iface, err)
	}
	if arpIgnore > arpIgnoreAll {
		return arpIgnore, nil
	}
	return arpIgnoreAll, nil
}

// ensureDummyDevice creates the dummy device if it doesn't exist.
func ensureDummyDevice(deviceName string) (dummyInterfaceType, error) {
	link, err := netlink.LinkByName(deviceName)
	if err == nil {
		return link, nil
	}
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: deviceName},
	}
	if err = netlink.LinkAdd(dummy); err != nil {
		return nil, err
	}
	return dummy, nil
}

// loadIPAddresses gets the IP addresses on the dummy device and caches them in memory.
func (a *ipAssigner) loadIPAddresses() (sets.Set[string], error) {
	addresses, err := netlink.AddrList(a.dummyDevice, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	newAssignIPs := sets.New[string]()
	for _, address := range addresses {
		newAssignIPs.Insert(address.IP.String())
	}
	return newAssignIPs, nil
}

func (a *ipAssigner) addIPOnDummy(parsedIP net.IP) error {
	addr := util.NewIPNet(parsedIP)
	if err := netlink.AddrAdd(a.dummyDevice, &netlink.Addr{IPNet: addr}); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("failed to add IP %v to interface %s: %v", parsedIP.String(), a.dummyDevice.Attrs().Name, err)
		} else {
			klog.InfoS("IP was already assigned to interface", "ip", parsedIP, "interface", a.dummyDevice.Attrs().Name)
		}
	} else {
		klog.InfoS("Assigned IP to interface", "ip", parsedIP, "interface", a.dummyDevice.Attrs().Name)
	}
	return nil
}

func (a *ipAssigner) deleteIPFromDummy(parsedIP net.IP) error {
	addr := util.NewIPNet(parsedIP)
	if err := netlink.AddrDel(a.dummyDevice, &netlink.Addr{IPNet: addr}); err != nil {
		if !errors.Is(err, unix.EADDRNOTAVAIL) {
			return fmt.Errorf("failed to delete IP %v from interface %s: %v", parsedIP.String(), a.dummyDevice.Attrs().Name, err)
		} else {
			klog.InfoS("IP does not exist on interface", "ip", parsedIP, "interface", a.dummyDevice.Attrs().Name)
		}
	}
	klog.InfoS("Deleted IP from interface", "ip", parsedIP.String(), "interface", a.dummyDevice.Attrs().Name)
	return nil
}

func (a *ipAssigner) syncIPsOnDummy(ips sets.Set[string]) error {
	assigned, err := a.loadIPAddresses()
	if err != nil {
		return fmt.Errorf("error when loading IP addresses from the system: %v", err)
	}
	for ip := range ips.Difference(assigned) {
		addr := util.NewIPNet(net.ParseIP(ip))
		if err := netlink.AddrAdd(a.dummyDevice, &netlink.Addr{IPNet: addr}); err != nil {
			if !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("failed to add IP %v to interface %s: %v", ip, a.dummyDevice.Attrs().Name, err)
			}
		}
	}
	for ip := range assigned.Difference(ips) {
		addr := util.NewIPNet(net.ParseIP(ip))
		if err := netlink.AddrDel(a.dummyDevice, &netlink.Addr{IPNet: addr}); err != nil {
			if !errors.Is(err, unix.EADDRNOTAVAIL) {
				return fmt.Errorf("failed to delete IP %v from interface %s: %v", ip, a.dummyDevice.Attrs().Name, err)
			}
		}
	}
	return nil
}

func getARPResponder(dummyDeviceName string, externalInterface *net.Interface) (responder.Responder, error) {
	// For the Egress scenario, the external IPs should always be present on the dummy
	// interface as they are used as tunnel endpoints. If arp_ignore is set to a value
	// other than 0, the host will not reply to ARP requests received on the transport
	// interface when the target IPs are assigned on the dummy interface. So a userspace
	// ARP responder is needed to handle ARP requests for the Egress IPs.
	arpIgnore, err := getARPIgnoreForInterface(externalInterface.Name)
	if err != nil {
		return nil, err
	}
	if dummyDeviceName == "" || arpIgnore > 0 {
		rsp, err := responder.NewARPResponder(externalInterface)
		if err != nil {
			return nil, fmt.Errorf("failed to create ARP responder for link %s: %v", externalInterface.Name, err)
		}
		return rsp, nil
	}
	return nil, nil
}

func (a *ipAssigner) advertise(ip net.IP) {
	if utilnet.IsIPv4(ip) {
		klog.V(2).InfoS("Sending gratuitous ARP", "ip", ip)
		if err := arping.GratuitousARPOverIface(ip, a.externalInterface); err != nil {
			klog.ErrorS(err, "Failed to send gratuitous ARP", "ip", ip)
		}
	} else {
		klog.V(2).InfoS("Sending neighbor advertisement", "ip", ip)
		if err := ndp.NeighborAdvertisement(ip, a.externalInterface); err != nil {
			klog.ErrorS(err, "Failed to send neighbor advertisement", "ip", ip)
		}
	}
}
