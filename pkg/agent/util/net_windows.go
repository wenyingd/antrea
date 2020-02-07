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

package util

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/Microsoft/hcsshim"
	ps "github.com/benmoss/go-powershell"
	"github.com/benmoss/go-powershell/backend"
	"github.com/containernetworking/plugins/pkg/ip"
	"k8s.io/klog"
)

const (
	ContainerVNICPrefix = "vEthernet"
	HNSNetworkType      = "Transparent"
	LocalHNSNetwork     = "antrea-hnsnetwork"
	NetAdapterEnvKey    = "UPLINK_NET_ADAPTER"
	OVSExtensionID      = "583CC151-73EC-4A6A-8B47-578297AD7623"
)

// EnableHostInterface set the specified interface status as UP.
func EnableHostInterface(ifaceName string) error {
	cmd := fmt.Sprintf("Enable-NetAdapter -InterfaceAlias %s", ifaceName)
	return invokePSCommand(cmd)
}

// ConfigureAddress adds IPAddress on the specified interface.
func ConfigureAddress(ifaceName string, ipConfig net.IPNet) error {
	ipStr := strings.Split(ipConfig.String(), "/")
	cmd := fmt.Sprintf("New-NetIPAddress -InterfaceAlias %s -IPAddress %s -PrefixLength %s", ifaceName, ipStr[0], ipStr[1])
	return invokePSCommand(cmd)
}

func invokePSCommand(cmd string) error {
	// Create a backend shell.
	back := &backend.Local{}

	// start a local powershell process
	shell, err := ps.New(back)
	if err != nil {
		panic(err)
	}
	defer shell.Exit()
	_, stderr, err := shell.Execute(cmd)
	if err != nil {
		return err
	}
	if stderr != "" {
		return fmt.Errorf("%s", stderr)
	}
	return nil
}

func callPSCommand(cmd string) (string, error) {
	// Create a backend shell.
	back := &backend.Local{}

	// start a local powershell process
	shell, err := ps.New(back)
	if err != nil {
		panic(err)
	}
	defer shell.Exit()
	stdout, stderr, err := shell.Execute(cmd)
	if err != nil {
		return stdout, err
	}
	if stderr != "" {
		return stdout, fmt.Errorf("%s", stderr)
	}
	return stdout, nil
}

// ReleaseOSManagement releases the management interface of the HNS Network, and then the physical interface is able to
// add on the OVS bridge. This function is called only if Hyper-V feature is installed on the host.
func ReleaseOSManagement(networkName string) error {
	var err error
	var maxRetry = 3
	var i = 0
	cmd := fmt.Sprintf("Get-VMSwitch -Name %s  | Set-VMSwitch -AllowManagementOS $false ", networkName)
	// Retry the operation here because an error is returned at the first invocation.
	for i < maxRetry {
		err = invokePSCommand(cmd)
		if err == nil {
			return nil
		}
		i++
	}
	return err
}

// WindowsHyperVInstalled checks if the Hyper-V feature is enabled on the host.
func WindowsHyperVInstalled() (bool, error) {
	cmd := "$(Get-WindowsFeature Hyper-V).InstallState"
	result, err := callPSCommand(cmd)
	if err != nil {
		return true, err
	}
	return strings.HasPrefix(result, "Installed"), nil
}

// CreateHNSNetwork creates a new HNS Network, whose type is "Transparent", and NetworkAdapter is parsed from the
// environment variable "UPLINK_NET_ADAPTER". If the NetworkAdapter is not configured in the environment variables,
// Ethernet0 is used by default. HNS Network properties "ManagementIP" and "SourceMac" are used to record the original
// IP and MAC addresses on the physical network adapter
func CreateHNSNetwork(hnsNetName string, subnetCIDR *net.IPNet, nodeIP *net.IPNet) (*hcsshim.HNSNetwork, error) {
	_, adapter, err := GetIPNetDeviceFromIP(nodeIP.IP)
	if err != nil {
		return nil, err
	}
	adapterMAC := adapter.HardwareAddr
	adapterName := adapter.Name
	gateway := ip.NextIP(subnetCIDR.IP.Mask(subnetCIDR.Mask))
	network := &hcsshim.HNSNetwork{
		Name:               hnsNetName,
		Type:               HNSNetworkType,
		NetworkAdapterName: adapterName,
		Subnets: []hcsshim.Subnet{
			{
				AddressPrefix:  subnetCIDR.String(),
				GatewayAddress: gateway.String(),
			},
		},
		ManagementIP: nodeIP.String(),
		SourceMac:    adapterMAC.String(),
	}
	hnsNet, err := network.Create()
	if err != nil {
		return nil, err
	}
	return hnsNet, nil
}

type vSwitchExtensionPolicy struct {
	ExtensionID string `json:"Id,omitempty"`
	IsEnabled   bool
}

type ExtensionsPolicy struct {
	Extensions []vSwitchExtensionPolicy `json:"Extensions"`
}

// EnableHNSNetworkExtension enables the specified vSwitchExtension on the target HNS Network. Antrea calls this function
// to enable OVS Extension the HNS Network.
func EnableHNSNetworkExtension(hnsNetID string, vSwitchExtension string) error {
	extensionPolicy := vSwitchExtensionPolicy{
		ExtensionID: vSwitchExtension,
		IsEnabled:   true,
	}
	jsonString, _ := json.Marshal(
		ExtensionsPolicy{
			Extensions: []vSwitchExtensionPolicy{extensionPolicy},
		})

	_, err := hcsshim.HNSNetworkRequest("POST", hnsNetID, string(jsonString))
	if err != nil {
		return err
	}
	return nil
}

// GetIPNetDeviceFromIP returns a local IP/mask and associated device from IP.
func GetIPNetDeviceFromIP(localIP net.IP) (*net.IPNet, *net.Interface, error) {
	linkList, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, link := range linkList {
		addrList, err := link.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrList {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.Equal(localIP) {
					return ipNet, &link, nil
				}
			}
		}
	}
	return nil, nil, fmt.Errorf("unable to find local IP and device")
}

// GetNetLinkIndex returns the index of the dev link from name.
func GetNetLinkIndex(dev string) int {
	link, err := net.InterfaceByName(dev)
	if err != nil {
		klog.Fatalf("cannot find dev %s: %w", dev, err)
	}
	return link.Index
}
