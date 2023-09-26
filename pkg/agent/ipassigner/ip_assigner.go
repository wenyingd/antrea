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
	"fmt"
	"net"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/pkg/agent/ipassigner/responder"
	"antrea.io/antrea/pkg/agent/util"
)

// IPAssigner provides methods to assign or unassign IP.
type IPAssigner interface {
	// AssignIP ensures the provided IP is assigned to the system.
	AssignIP(ip string, forceAdvertise bool) error
	// UnassignIP ensures the provided IP is not assigned to the system.
	UnassignIP(ip string) error
	// AssignedIPs return the IPs that are assigned to the system by this IPAssigner.
	AssignedIPs() sets.Set[string]
	// InitIPs ensures the IPs that are assigned to the system match the given IPs.
	InitIPs(sets.Set[string]) error
	// Run starts the IP assigner.
	Run(<-chan struct{})
}

// ipAssigner creates a dummy device and assigns IPs to it.
// It's supposed to be used in the cases that external IPs should be configured on the system so that they can be used
// for SNAT (egress scenario) or DNAT (ingress scenario). A dummy device is used because the IPs just need to be present
// in any device to be functional, and using dummy device avoids touching system managed devices and is easy to know IPs
// that are assigned by antrea-agent.
type ipAssigner struct {
	// externalInterface is the device that GARP (IPv4) and Unsolicited NA (IPv6) will be sent from.
	externalInterface *net.Interface
	// dummyDevice is the device that IPs will be assigned to.
	dummyDevice dummyInterfaceType
	// assignIPs caches the IPs that are assigned to the dummy device.
	// TODO: Add a goroutine to ensure that the cache is in sync with the IPs assigned to the dummy device in case the
	// IPs are removed by users accidentally.
	assignedIPs  sets.Set[string]
	mutex        sync.RWMutex
	arpResponder responder.Responder
	ndpResponder responder.Responder
}

// NewIPAssigner returns an *ipAssigner.
func NewIPAssigner(nodeTransportInterface string, dummyDeviceName string) (IPAssigner, error) {
	ipv4, ipv6, externalInterface, err := util.GetIPNetDeviceByName(nodeTransportInterface)
	if err != nil {
		return nil, fmt.Errorf("get IPNetDevice from name %s error: %+v", nodeTransportInterface, err)
	}
	a := &ipAssigner{
		externalInterface: externalInterface,
		assignedIPs:       sets.New[string](),
	}
	if ipv4 != nil {
		arpResponder, err := getARPResponder(dummyDeviceName, externalInterface)
		if err != nil {
			return nil, err
		}
		a.arpResponder = arpResponder
	}
	if ipv6 != nil {
		ndpResponder, err := getNDPResponder(externalInterface)
		if err != nil {
			return nil, err
		}
		a.ndpResponder = ndpResponder
	}
	if dummyDeviceName != "" {
		dummyDevice, err := ensureDummyDevice(dummyDeviceName)
		if err != nil {
			return nil, fmt.Errorf("error when ensuring dummy device exists: %v", err)
		}
		a.dummyDevice = dummyDevice
	}
	return a, nil
}

// AssignIP ensures the provided IP is assigned to the dummy device and the ARP/NDP responders.
func (a *ipAssigner) AssignIP(ip string, forceAdvertise bool) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP %s", ip)
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.assignedIPs.Has(ip) {
		klog.V(2).InfoS("The IP is already assigned", "ip", ip)
		if forceAdvertise {
			a.advertise(parsedIP)
		}
		return nil
	}

	if a.dummyDevice != nil {
		if err := a.addIPOnDummy(parsedIP); err != nil {
			return err
		}
	}

	if utilnet.IsIPv4(parsedIP) && a.arpResponder != nil {
		if err := a.arpResponder.AddIP(parsedIP); err != nil {
			return fmt.Errorf("failed to assign IP %v to ARP responder: %v", ip, err)
		}
	}
	if utilnet.IsIPv6(parsedIP) && a.ndpResponder != nil {
		if err := a.ndpResponder.AddIP(parsedIP); err != nil {
			return fmt.Errorf("failed to assign IP %v to NDP responder: %v", ip, err)
		}
	}
	// Always advertise the IP when the IP is newly assigned to this Node.
	a.advertise(parsedIP)
	a.assignedIPs.Insert(ip)
	return nil
}

// UnassignIP ensures the provided IP is not assigned to the dummy device.
func (a *ipAssigner) UnassignIP(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP %s", ip)
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if !a.assignedIPs.Has(ip) {
		klog.V(2).InfoS("The IP is not assigned", "ip", ip)
		return nil
	}

	if a.dummyDevice != nil {
		if err := a.deleteIPFromDummy(parsedIP); err != nil {
			return err
		}
	}

	if utilnet.IsIPv4(parsedIP) && a.arpResponder != nil {
		if err := a.arpResponder.RemoveIP(parsedIP); err != nil {
			return fmt.Errorf("failed to remove IP %v from ARP responder: %v", ip, err)
		}
	}
	if utilnet.IsIPv6(parsedIP) && a.ndpResponder != nil {
		if err := a.ndpResponder.RemoveIP(parsedIP); err != nil {
			return fmt.Errorf("failed to remove IP %v from NDP responder: %v", ip, err)
		}
	}

	a.assignedIPs.Delete(ip)
	return nil
}

// AssignedIPs return the IPs that are assigned to the dummy device.
func (a *ipAssigner) AssignedIPs() sets.Set[string] {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	// Return a copy.
	return a.assignedIPs.Union(nil)
}

// InitIPs loads the IPs from the dummy device and replaces the IPs that are assigned to it
// with the given ones. This function also adds the given IPs to the ARP/NDP responder if
// applicable. It can be used to recover the IP assigner to the desired state after Agent restarts.
func (a *ipAssigner) InitIPs(ips sets.Set[string]) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.dummyDevice != nil {
		if err := a.syncIPsOnDummy(ips); err != nil {
			return err
		}
	}
	for ipStr := range ips {
		ip := net.ParseIP(ipStr)
		var err error
		if utilnet.IsIPv4(ip) && a.arpResponder != nil {
			err = a.arpResponder.AddIP(ip)
		}
		if utilnet.IsIPv6(ip) && a.ndpResponder != nil {
			err = a.ndpResponder.AddIP(ip)
		}
		if err != nil {
			return err
		}
		a.advertise(ip)
	}
	a.assignedIPs = ips.Union(nil)
	return nil
}

// Run starts the ARP responder and NDP responder.
func (a *ipAssigner) Run(ch <-chan struct{}) {
	if a.arpResponder != nil {
		go a.arpResponder.Run(ch)
	}
	if a.ndpResponder != nil {
		go a.ndpResponder.Run(ch)
	}
	<-ch
}
