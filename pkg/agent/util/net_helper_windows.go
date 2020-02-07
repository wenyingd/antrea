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

package util

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Microsoft/hcsshim"
	ps "github.com/benmoss/go-powershell"
	"github.com/benmoss/go-powershell/backend"
	"github.com/containernetworking/plugins/pkg/ip"
)

const (
	ContainerVNICPrefix = "vEthernet"
	HNSNetworkType      = "Transparent"
	LocalHNSNetwork     = "antrea-hnsnetwork"
	NetAdapterEnvKey    = "UPLINK_NET_ADAPTER"
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
	// choose a backend.
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
	// choose a backend
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

// GetAdapterIPv4Addr returns the IP address of the specific network adapter.
func GetAdapterIPv4Addr(adapterName string) (string, error) {
	adapter, err := net.InterfaceByName(adapterName)
	if err != nil {
		return "", err
	}
	addrs, err := adapter.Addrs()
	if err != nil {
		return "", err
	}
	for _, ip := range addrs {
		if strings.Contains(ip.String(), ":") {
			continue
		}
		return ip.String(), nil
	}
	return "", fmt.Errorf("failed to find a valid IP on adapter %s", adapterName)
}

// ReleaseOSManagement releases the management interface of the HNS Network.
func ReleaseOSManagement(networkName string) error {
	var err error
	var maxRetry = 3
	var i = 0
	cmd := fmt.Sprintf("Get-VMSwitch -Name %s  | Set-VMSwitch -AllowManagementOS $false ", networkName)
	// Retry to do the operation here because there always error info at the first invocation.
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

// GetNetworkAdapter gets the network adapter name from the environment settings with key "UPLINK_NET_ADAPTER". If the
// variable is not set, use Ethernet0 by default.
func GetNetworkAdapter() string {
	adapter := os.Getenv(NetAdapterEnvKey)
	if adapter != "" {
		return adapter
	}
	// Todo: find the network adapter using Node's internal IP.
	return "Ethernet0"
}

// CreateHNSNetwork creates a new HNS Network, whose type is "Transparent", and NetworkAdapter is parsed from the
// environment variable "UPLINK_NET_ADAPTER". If the NetworkAdapter is not configured in the environment variables,
// Ethernet0 is used by default. HNS Network properties "ManagementIP" and "SourceMac" are used to record the original
// IP and MAC addresses on the physical network adapter
func CreateHNSNetwork(subnetCIDR *net.IPNet) (*hcsshim.HNSNetwork, error) {
	adapterName := GetNetworkAdapter()
	adapter, err := net.InterfaceByName(adapterName)
	if err != nil {
		return nil, err
	}
	adapterMAC := adapter.HardwareAddr
	adapterIP, _ := GetAdapterIPv4Addr(adapterName)
	gateway := ip.NextIP(subnetCIDR.IP.Mask(subnetCIDR.Mask))
	network := &hcsshim.HNSNetwork{
		Name:               LocalHNSNetwork,
		Type:               HNSNetworkType,
		NetworkAdapterName: adapterName,
		Subnets: []hcsshim.Subnet{
			{
				AddressPrefix:  subnetCIDR.String(),
				GatewayAddress: gateway.String(),
			},
		},
		ManagementIP: adapterIP,
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
