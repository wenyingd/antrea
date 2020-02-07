// Copyright 2019 Antrea Authors
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

package agent

import (
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/hcsshim"
	"github.com/containernetworking/plugins/pkg/ip"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
)

const (
	OVSExtensionID = "583CC151-73EC-4A6A-8B47-578297AD7623"
)

func (i *Initializer) configureGatewayInterface(gatewayIface *interfacestore.InterfaceConfig) error {
	// Set host gateway interface up.
	if err := util.EnableHostInterface(i.hostGateway); err != nil {
		klog.Errorf("Failed to set host link for %s up: %v", i.hostGateway, err)
		return err
	}

	// host link might not be queried at once after create OVS internal port, retry max 5 times with 1s
	// delay each time to ensure the link is ready. If still failed after max retry return error.
	gwLink, err := func() (*net.Interface, error) {
		for retry := 0; retry < maxRetryForHostLink; retry++ {
			if iface, err := net.InterfaceByName(i.hostGateway); err != nil {
				klog.V(2).Infof("Not found host iface for gateway %s, retry after 1s", i.hostGateway)
				if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "no such network interface" {
					time.Sleep(1 * time.Second)
				} else {
					return iface, err
				}
			} else {
				return iface, nil
			}
		}
		return nil, fmt.Errorf("link %s not found", i.hostGateway)
	}()
	if err != nil {
		klog.Errorf("Failed to find host link for gateway %s: %v", i.hostGateway, err)
		return err
	}

	// Configure host gateway IP using the first address of node localSubnet
	localSubnet := i.nodeConfig.PodCIDR
	subnetID := localSubnet.IP.Mask(localSubnet.Mask)
	gwIP := net.IPNet{IP: ip.NextIP(subnetID), Mask: localSubnet.Mask}
	gwMAC := gwLink.HardwareAddr
	i.nodeConfig.GatewayConfig = &types.GatewayConfig{Name: i.hostGateway, IP: gwIP.IP, MAC: gwMAC}
	gatewayIface.IP = gwIP.IP
	gatewayIface.MAC = gwMAC

	// Check IP address configuration on existing interface, return if already has target address
	// We perform this check unconditionally, even if the OVS port did not exist when this
	// function was called (i.e. portExists is false). Indeed, it may be possible for the Linux
	// interface to exist even if the OVS bridge does not exist.
	if addrs, err := gwLink.Addrs(); err != nil {
		klog.Errorf("Failed to query IPv4 address list for interface %s: %v", i.hostGateway, err)
		return err
	} else if addrs != nil {
		for _, addr := range addrs {
			// Check with IPv4 address.
			if net.ParseIP(addr.String()).To4() != nil {
				klog.V(4).Infof("Found IPv4 address %s for interface %s", addr.String(), i.hostGateway)
				if addr.String() == gwIP.String() {
					klog.V(2).Infof("IPv4 address %s already assigned to interface %s", gwIP.String(), i.hostGateway)
					return nil
				}
			}
		}
	} else {
		klog.V(2).Infof("Link %s has no configured IPv4 address", i.hostGateway)
	}

	klog.V(2).Infof("Adding address %v to gateway interface %s", gwIP, i.hostGateway)
	if err := util.ConfigureAddress(i.hostGateway, gwIP); err != nil {
		klog.Errorf("Failed to set gateway interface %s with address %v: %v", i.hostGateway, gwIP, err)
		return err
	}
	return nil
}

// prepareHostNetworking creates HNS Network for containers.
func (i *Initializer) prepareHostNetworking() error {
	_, err := hcsshim.GetHNSNetworkByName(util.LocalHNSNetwork)
	// If the HNS Network already exists, return immediately.
	if err == nil {
		return nil
	}
	// If an error occurs, and the error is not NetworkNotFoundError, return the error.
	if _, ok := err.(hcsshim.NetworkNotFoundError); !ok {
		return err
	}
	// Create new HNS Network.
	subnetCIDR := i.nodeConfig.PodCIDR
	hnsNet, err := util.CreateHNSNetwork(subnetCIDR)
	if err != nil {
		return err
	}

	// Enable OVS Extension on the HNS Network. If an error occurs, delete the HNS Network and return the error.
	if err = enableHNSOnOVS(hnsNet); err != nil {
		hnsNet.Delete()
		return err
	}
	klog.Infof("Created HNSNetwork with name %s id %s", hnsNet.Name, hnsNet.Id)
	return nil
}

func enableHNSOnOVS(hnsNet *hcsshim.HNSNetwork) error {
	// Release OS management for HNS Network if Hyper-V is enabled.
	hypervEnabled, err := util.WindowsHyperVInstalled()
	if err != nil {
		return err
	}
	if hypervEnabled {
		if err := util.ReleaseOSManagement(util.LocalHNSNetwork); err != nil {
			klog.Errorf("Failed to release OS management for HNSNetwork %s", util.LocalHNSNetwork)
			return err
		}
	}

	// Enable the HNS Network with OVS extension.
	if err := util.EnableHNSNetworkExtension(hnsNet.Id, OVSExtensionID); err != nil {
		return err
	}
	return err
}

// TODO: setupExternalNetworking installs Openflow entries to SNAT Pod using Node IP, and then Pod could access external addresses.
func (i *Initializer) setupExternalNetworking() error {
	return nil
}
