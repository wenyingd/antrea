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

package types

import (
	"net"
)

const (
	DefaultTunPortName = "tun0"
	DefaultTunOFPort   = 1
	HostGatewayOFPort  = 2
	UplinkOFPort       = 3
	BridgeOFPort       = 0xfffffffe
)

type GatewayConfig struct {
	IP   net.IP
	MAC  net.HardwareAddr
	Name string
}

type NodeConfig struct {
	Bridge  string
	Name    string
	PodCIDR *net.IPNet
	*GatewayConfig
}
