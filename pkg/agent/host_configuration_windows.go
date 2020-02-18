// Copyright 2020 Antrea Authors
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
	"strings"
	"time"

	"github.com/Microsoft/hcsshim"
	"github.com/containernetworking/plugins/pkg/ip"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
)

const HNSNetworkType = "Transparent"

func (i *Initializer) configureGatewayInterface(gatewayIface *interfacestore.InterfaceConfig) error {
	// Set host gateway interface up.
	// There's delay before gateway is realized by OS
	err := func() error {
		for retry := 0; retry < maxRetryForHostLink; retry++ {
			if err := util.EnableHostInterface(i.hostGateway); err != nil {
				klog.Info("Try to set gateway %s up failed: %v", i.hostGateway, err)
				time.Sleep(1 * time.Second)
			} else {
				return nil
			}
		}
		return fmt.Errorf("timeout to set gateway %s up", i.hostGateway)
	}()

	if err != nil {
		klog.Errorf("Failed to set gateway %s up: %v", i.hostGateway, err)
		return err
	}

	// host link might not be queried at once after create OVS internal port, retry max 5 times with 1s
	// delay each time to ensure the link is ready. If still failed after max retry return error.
	gwLink, err := func() (*net.Interface, error) {
		for retry := 0; retry < maxRetryForHostLink; retry++ {
			if iface, err := net.InterfaceByName(i.hostGateway); err != nil {
				klog.V(2).Infof("Not found host interface for gateway %s, retry after 1s", i.hostGateway)
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
	i.nodeConfig.GatewayConfig = &types.GatewayConfig{Link: i.hostGateway, IP: gwIP.IP, MAC: gwMAC}
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
			if ipNet, ok := addr.(*net.IPNet); ok {
				ip := ipNet.IP
				if ip.To4() != nil && ip.Equal(gwIP.IP) {
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
	_, uplink, err := util.GetIPNetDeviceFromIP(i.nodeConfig.NodeIPAddr.IP)
	if err != nil {
		return err
	}
	macAddr, err := util.GetAdapterMacAddr(uplink.Name)
	if err != nil {
		return err
	}
	hnsNet := &hcsshim.HNSNetwork{
		Name:               util.LocalHNSNetwork,
		Type:               HNSNetworkType,
		NetworkAdapterName: uplink.Name,
		Subnets: []hcsshim.Subnet{
			{
				AddressPrefix:  subnetCIDR.String(),
				GatewayAddress: i.nodeConfig.GatewayConfig.IP.String(),
			},
		},
		ManagementIP: i.nodeConfig.NodeIPAddr.IP.String(),
		SourceMac:    macAddr.String(),
	}
	if err != nil {
		return err
	}

	// Release management of uplink interface from OS
	// Do the operation twice because there is always error info in first operation
	util.ReleaseOSManagement(util.LocalHNSNetwork)
	if err := util.ReleaseOSManagement(util.LocalHNSNetwork); err != nil {
		klog.Errorf("Failed to release OS management for HNSNetwork %s", util.LocalHNSNetwork)
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
	if err := util.EnableHNSNetworkExtension(hnsNet.Id, util.OVSExtensionID); err != nil {
		return err
	}
	return err
}

// setupExternalNetworking installs Openflow entries to SNAT Pod using Node IP, and then Pod could access external addresses.
func (i *Initializer) setupExternalNetworking() error {
	subnetCIDR := i.nodeConfig.PodCIDR
	hnsNet, _ := hcsshim.GetHNSNetworkByName(util.LocalHNSNetwork)
	nodeIP := net.ParseIP(hnsNet.ManagementIP)
	if err := i.ofClient.InstallExternalFlows(nodeIP, *subnetCIDR); err != nil {
		klog.Errorf("Failed to setup SNAT openflow entries: %v", err)
		return err
	}
	return nil
}

// prepareOVSBridge config IP, MAC and add uplink interface on OVS bridge
func (i *Initializer) prepareOVSBridge() error {
	_, uplink, err := util.GetIPNetDeviceFromIP(i.nodeConfig.NodeIPAddr.IP)
	if err != nil {
		return err
	}
	// If uplink is already exists, return
	if _, err := i.ovsBridgeClient.GetOFPort(uplink.Name); err == nil {
		klog.Errorf("Uplink %s already exists, skip the configuration", uplink.Name)
		return err
	}

	// Get IP, MAC of uplink interface
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(util.LocalHNSNetwork)
	if err != nil {
		klog.Errorf("Failed to get hnsnetwork %s: %v", util.LocalHNSNetwork, err)
		return err
	}
	ipAddr, ipNet, err := net.ParseCIDR(hnsNetwork.ManagementIP)
	if err != nil {
		klog.Errorf("Failed to parse IP Address %s for HNSNetwork %s: %v",
			hnsNetwork.ManagementIP, util.LocalHNSNetwork, err)
		return err
	}
	ifIpAddr := net.IPNet{IP: ipAddr, Mask: ipNet.Mask}
	klog.Infof("Found hns network management ipAddr: %s", ifIpAddr.String())
	// Set datapathID of OVS bridge
	datapathID := strings.Replace(hnsNetwork.SourceMac, ":", "", -1)
	datapathID = "00" + datapathID
	if err = i.ovsBridgeClient.SetDatapathID(datapathID); err != nil {
		klog.Errorf("Failed to set datapath_id %s: %v", datapathID, err)
		return err
	}
	// Create uplink port
	uplinkPortUUId, err := i.ovsBridgeClient.CreateUplinkPort(uplink.Name, uplink.Name, types.UplinkOFPort, nil)
	if err != nil {
		klog.Errorf("Failed to add uplink port %s: %v", uplink.Name, err)
		return err
	}
	uplinkInterface := interfacestore.NewUplinkInterface(uplink.Name)
	uplinkInterface.OVSPortConfig = &interfacestore.OVSPortConfig{uplinkPortUUId, types.UplinkOFPort}
	i.ifaceStore.AddInterface(uplinkInterface)

	// Move IP, MAC of from uplink interface to OVS bridge
	brName, _ := i.ovsBridgeClient.GetOVSName()
	err = util.EnableHostInterface(brName)
	if err != nil {
		return err
	}
	macAddr, err := net.ParseMAC(hnsNetwork.SourceMac)
	if err != nil {
		return err
	}
	err = util.ConfigureMacAddress(brName, macAddr)
	if err != nil {
		klog.Errorf("Failed to set Mac Address %s for interface %v: ", macAddr, uplink.Name, err)
		return err
	}
	existingIpAddr, err := util.GetAdapterIPv4Addr(brName)
	if err != nil && existingIpAddr.String() == i.nodeConfig.NodeIPAddr.String() {
		return nil
	}
	if err := util.RemoveAddress(brName); err != nil {
		klog.Errorf("Failed to remove existing IP Addresses for interface %v: ", brName, err)
		return err
	}
	err = util.ConfigureAddress(brName, ifIpAddr)
	if err != nil {
		klog.Errorf("Failed to set IP Address %s for interface %v: ", ifIpAddr, brName, err)
		return err
	}
	return nil
}

// initHostNetworkFlow install Openflow entries for uplink/bridge to support host networking
func (i *Initializer) initHostNetworkFlow() error {
	if err := i.ofClient.InstallHostNetworkFlows(types.UplinkOFPort, types.BridgeOFPort); err != nil {
		return err
	}
	return nil
}
