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

package noderoute

import (
	"fmt"
	"net"

	"github.com/rakelkar/gonetsh/netroute"
	"k8s.io/klog"
)

// getGatewayIndex parses the index of the gateway interface.
func getGatewayIndex(gwIfaceName string) int {
	link, _ := net.InterfaceByName(gwIfaceName)
	return link.Index
}

// addRoute adds the routing configuration for the new Node.
func addRoute(nodeName string, route *hostRoute) error {
	nr := netroute.New()
	routes, err := nr.GetNetRoutes(route.linkIndex, route.destination)
	if err != nil {
		return err
	}
	// This is likely to be caused by an agent restart and so should not happen once we
	// handle state reconciliation on restart properly. However, it is probably better
	// to handle this case gracefully for the time being.
	if len(routes) != 0 {
		klog.V(2).Infof("Route to Node %s already exists, replacing it", nodeName)
		for _, r := range routes {
			nr.RemoveNetRoute(r.LinkIndex, r.DestinationSubnet, r.GatewayAddress)
		}
	}
	if err := nr.NewNetRoute(route.linkIndex, route.destination, route.gateway); err != nil {
		return fmt.Errorf("failed to install route to Node %s with netsh: %v", nodeName, err)
	}
	return nil
}

// deleteRoute removes the routing configuration for the deleted Node.
func deleteRoute(route *hostRoute) error {
	nr := netroute.New()
	err := nr.RemoveNetRoute(route.linkIndex, route.destination, route.gateway)
	if err != nil {
		return err
	}
	return nil
}

// listRoutes reads all the routes for the gateway and returns them as a map with the destination
// subnet as the key.
func (c *Controller) listRoutes() (routes map[string]*hostRoute, err error) {
	nr := netroute.New()
	winRoutes, err := nr.GetNetRoutesAll()
	if err != nil {
		return nil, err
	}
	for _, rt := range winRoutes {
		if rt.LinkIndex == c.gatewayLink {
			hr := &hostRoute{
				destination: rt.DestinationSubnet,
				linkIndex:   c.gatewayLink,
				gateway:     rt.GatewayAddress,
			}
			routes[rt.DestinationSubnet.String()] = hr
		}
	}
	return
}
