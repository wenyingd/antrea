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
	"fmt"
	"net"
	"strings"

	ps "github.com/benmoss/go-powershell"
	"github.com/benmoss/go-powershell/backend"
)

const (
	LocalHNSNetwork     = "antrea-hnsnetwork"
	ContainerVNICPrefix = "vEthernet"
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
	// choose a backend
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
