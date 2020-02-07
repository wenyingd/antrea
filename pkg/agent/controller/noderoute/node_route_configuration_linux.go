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

	"github.com/vishvananda/netlink"
)

// getGatewayIndex parses the index of the gateway interface.
func getGatewayIndex(gwIfaceName string) int {
	link, _ := netlink.LinkByName(gwIfaceName)
	return link.Attrs().Index
}

// getRoute transforms the hostRoute to a netlink.Route object.
func getRoute(route *hostRoute) *netlink.Route {
	return &netlink.Route{
		LinkIndex: route.linkIndex,
		Dst:       route.destination,
		Gw:        route.gateway,
		Flags:     int(netlink.FLAG_ONLINK),
	}
}

// addRoute adds the routing configuration for the new Node.
func addRoute(nodeName string, route *hostRoute) error {
	r := getRoute(route)
	// RouteReplace will add the route if it's missing or update it if it's already
	// present (as is the case for agent restarts).
	if err := netlink.RouteReplace(r); err != nil {
		return fmt.Errorf("failed to install route to Node %s with netlink: %v", nodeName, err)
	}
	return nil
}

// deleteRoute removes the routing configuration for the deleted Node.
func deleteRoute(route *hostRoute) error {
	r := getRoute(route)
	if err := netlink.RouteDel(r); err != nil {
		return err
	}
	return nil
}

// listRoutes reads all the routes for the gateway and returns them as a map with the destination
// subnet as the key.
func (c *Controller) listRoutes() (routes map[string]*hostRoute, err error) {
	routes = make(map[string]*hostRoute)
	link, _ := netlink.LinkByIndex(c.gatewayLink)
	routeList, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return routes, err
	}
	for idx := 0; idx < len(routeList); idx++ {
		route := &routeList[idx]
		hr := &hostRoute{
			destination: route.Dst,
			linkIndex:   route.LinkIndex,
			gateway:     route.Gw,
		}
		routes[route.Dst.String()] = hr
	}
	return routes, nil
}
