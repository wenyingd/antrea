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

package route

import (
	"fmt"
	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"net"

	"github.com/rakelkar/gonetsh/netroute"

	"github.com/vmware-tanzu/antrea/pkg/agent/util"
)

type hRoute struct {
	route *netroute.Route
}

func (r *hRoute) add() error {
	nr := netroute.New()
	defer nr.Exit()
	routes, err := nr.GetNetRoutes(r.route.LinkIndex, r.route.DestinationSubnet)
	if err != nil {
		return err
	}
	// This is likely to be caused by an agent restart or the caller retry. Remove the existing routes to avoid
	// configuration conflict.
	if len(routes) != 0 {
		for _, r := range routes {
			nr.RemoveNetRoute(r.LinkIndex, r.DestinationSubnet, r.GatewayAddress)
		}
	}
	if err := nr.NewNetRoute(r.route.LinkIndex, r.route.DestinationSubnet, r.route.GatewayAddress); err != nil {
		return fmt.Errorf("failed to install route with netsh: %v", err)
	}
	return nil
}

// delete removes netlink.Route entry.
func (r *hRoute) delete() error {
	nr := netroute.New()
	defer nr.Exit()
	err := nr.RemoveNetRoute(r.route.LinkIndex, r.route.DestinationSubnet, r.route.GatewayAddress)
	if err != nil {
		return err
	}
	return nil
}

// ListPeerCIDRRoute reads all existing routes for the gateway and returns them as a map with the destination
// subnet as the key.
func (c *Client) ListPeerCIDRRoute() (map[string][]HostRoute, error) {
	nr := netroute.New()
	winRoutes, err := nr.GetNetRoutesAll()
	if err != nil {
		return nil, err
	}
	gwLinkIndex := util.GetNetLinkIndex(c.nodeConfig.GatewayConfig.Link)
	rtMap := make(map[string][]HostRoute)
	for _, rt := range winRoutes {
		if rt.LinkIndex == gwLinkIndex && rt.DestinationSubnet != nil {
			hr := hRoute{
				route: &rt,
			}
			rtMap[rt.DestinationSubnet.String()] = append(rtMap[rt.DestinationSubnet.String()], &hr)
		}
	}
	return rtMap, nil
}

// Initialize returns immediately on Window.
// TODO: Add support for host-gw mode.
func (c *Client) Initialize(nodeConfig *types.NodeConfig, encapMode config.TrafficEncapModeType) error {
	c.nodeConfig = nodeConfig
	c.encapMode = encapMode

	return nil
}

// AddPeerCIDRRoute adds routes to route tables for Antrea use.
func (c *Client) AddPeerCIDRRoute(peerPodCIDR *net.IPNet, gwLinkIdx int, peerNodeIP, peerGwIP net.IP) ([]HostRoute, error) {
	if peerPodCIDR == nil {
		return nil, fmt.Errorf("empty peer pod CIDR")
	}

	rt := &hRoute{route: &netroute.Route{
		LinkIndex:         gwLinkIdx,
		DestinationSubnet: peerPodCIDR,
		GatewayAddress:    peerGwIP,
	}}

	if err := rt.add(); err != nil {
		return nil, err
	}
	return []HostRoute{rt}, nil
}
