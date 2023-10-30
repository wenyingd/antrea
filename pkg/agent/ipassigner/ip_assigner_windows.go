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

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/pkg/agent/ipassigner/responder"
	"antrea.io/antrea/pkg/agent/util/arping"
	"antrea.io/antrea/pkg/agent/util/ndp"
)

type dummyInterfaceType *struct{}

// ensureDummyDevice creates the dummy device if it doesn't exist.
func ensureDummyDevice(deviceName string) (dummyInterfaceType, error) {
	return nil, nil
}

func (a *ipAssigner) addIPOnDummy(parsedIP net.IP) error {
	return nil
}

func (a *ipAssigner) deleteIPFromDummy(parsedIP net.IP) error {
	return nil
}

func (a *ipAssigner) syncIPsOnDummy(ips sets.Set[string]) error {
	return nil
}

// getARPResponder returns nil on Windows since the ARP request is responded with OpenFlow entries.
func getARPResponder(_ string, externalInterface *net.Interface) (responder.Responder, error) {
	rsp, err := responder.NewARPResponder(externalInterface)
	if err != nil {
		return nil, fmt.Errorf("failed to create ARP responder for link %s: %v", externalInterface.Name, err)
	}
	return rsp, nil
}

func (a *ipAssigner) advertise(ip net.IP) {
	if utilnet.IsIPv4(ip) {
		klog.V(2).InfoS("Sending gratuitous ARP", "ip", ip)
		if err := arping.GratuitousARPOverIface(ip, a.externalInterface); err != nil {
			klog.ErrorS(err, "Failed to send gratuitous ARP", "ip", ip)
		}
	} else {
		klog.V(2).InfoS("Sending neighbor advertisement", "ip", ip)
		if err := ndp.GratuitousNDPOverIface(ip, a.externalInterface); err != nil {
			klog.ErrorS(err, "Failed to send neighbor advertisement", "ip", ip)
		}
	}
}
