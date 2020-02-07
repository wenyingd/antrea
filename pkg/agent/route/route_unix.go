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
//
// +build linux darwin

package route

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/iptables"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
)

const (
	// AntreaServiceTable is route table name for Antrea service traffic.
	AntreaServiceTable = "Antrea-service"
	// AntreaServiceTableIdx is route table index for Antrea service traffic.
	AntreaServiceTableIdx = 300
	routeTableConfigPath  = "/etc/iproute2/rt_tables"
	// AntreaIPRulePriority is Antrea IP rule priority
	AntreaIPRulePriority = 300
)

type serviceRtTableConfig struct {
	Idx  int
	Name string
}

var (
	// ServiceRtTable contains Antrea service route table information.
	ServiceRtTable = &serviceRtTableConfig{Idx: 254, Name: "main"}
)

type hRoute struct {
	route *netlink.Route
}

func (r *hRoute) add() error {
	return netlink.RouteReplace(r.route)
}

// delete removes netlink.Route entry.
func (r *hRoute) delete() error {
	if err := netlink.RouteDel(r.route); err != nil && err != unix.ESRCH {
		return err
	}
	return nil
}

func (s *serviceRtTableConfig) String() string {
	return fmt.Sprintf("%s: idx %d", s.Name, s.Idx)
}

func (s *serviceRtTableConfig) IsMainTable() bool {
	return s.Name == "main"
}

// Initialize sets up route tables for Antrea.
func (c *Client) Initialize(nodeConfig *types.NodeConfig, encapMode config.TrafficEncapModeType) error {
	c.nodeConfig = nodeConfig
	c.encapMode = encapMode
	if c.encapMode.SupportsNoEncap() {
		ServiceRtTable.Idx = AntreaServiceTableIdx
		ServiceRtTable.Name = AntreaServiceTable
	}

	if ServiceRtTable.IsMainTable() {
		_ = c.RemoveServiceRouting()
		return nil
	}
	f, err := os.OpenFile(routeTableConfigPath, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		klog.Fatalf("Unable to create service route table(open):  %v", err)
	}
	defer func() { _ = f.Close() }()

	oldTablesRaw := make([]byte, 1024)
	bLen, err := f.Read(oldTablesRaw)
	if err != nil {
		klog.Fatalf("Unable to create service route table(read): %v", err)
	}
	oldTables := string(oldTablesRaw[:bLen])
	newTable := fmt.Sprintf("%d %s", ServiceRtTable.Idx, ServiceRtTable.Name)

	if strings.Index(oldTables, newTable) == -1 {
		if _, err := f.WriteString(newTable); err != nil {
			klog.Fatalf("Failed to add antrea service route table: %v", err)
		}
	}

	gwConfig := c.nodeConfig.GatewayConfig
	if gwConfig != nil && c.nodeConfig.PodCIDR != nil {
		// Add local podCIDR if applicable to service rt table.
		route := &netlink.Route{
			LinkIndex: util.GetNetLinkIndex(gwConfig.Link),
			Scope:     netlink.SCOPE_LINK,
			Dst:       c.nodeConfig.PodCIDR,
			Table:     ServiceRtTable.Idx,
		}
		if err := netlink.RouteReplace(route); err != nil {
			klog.Fatalf("Failed to add link route to service table: %v", err)
		}
	}

	// create ip rule to select route table
	ipRule := netlink.NewRule()
	ipRule.IifName = c.nodeConfig.GatewayConfig.Link
	ipRule.Mark = iptables.RtTblSelectorValue
	ipRule.Mask = 0xffffffff
	ipRule.Table = ServiceRtTable.Idx
	ipRule.Priority = AntreaIPRulePriority

	ruleList, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		klog.Fatalf("Failed to get ip rule: %v", err)
	}
	// Check for ip rule presence.
	for _, rule := range ruleList {
		if rule == *ipRule {
			return nil
		}
	}
	err = netlink.RuleAdd(ipRule)
	if err != nil {
		klog.Fatalf("Failed to create ip rule for service route table: %v", err)
	}
	return nil
}

// AddPeerCIDRRoute adds routes to route tables for Antrea use.
func (c *Client) AddPeerCIDRRoute(peerPodCIDR *net.IPNet, gwLinkIdx int, peerNodeIP, peerGwIP net.IP) ([]HostRoute, error) {
	if peerPodCIDR == nil {
		return nil, fmt.Errorf("empty peer pod CIDR")
	}

	// install routes
	routes := []*netlink.Route{
		{
			Dst:       peerPodCIDR,
			Flags:     int(netlink.FLAG_ONLINK),
			LinkIndex: gwLinkIdx,
			Gw:        peerGwIP,
			Table:     ServiceRtTable.Idx,
		},
	}

	// If service route table and main route table is not the same , add
	// peer CIDR to main route table too (i.e in NoEncap and hybrid mode)
	if !ServiceRtTable.IsMainTable() {
		if c.encapMode.NeedsEncapToPeer(peerNodeIP, c.nodeConfig.NodeIPAddr) {
			// need overlay tunnel
			routes = append(routes, &netlink.Route{
				Dst:       peerPodCIDR,
				Flags:     int(netlink.FLAG_ONLINK),
				LinkIndex: gwLinkIdx,
				Gw:        peerGwIP,
			})
		} else if !c.encapMode.NeedsRoutingToPeer(peerNodeIP, c.nodeConfig.NodeIPAddr) {
			routes = append(routes, &netlink.Route{
				Dst: peerPodCIDR,
				Gw:  peerNodeIP,
			})
		}
		// If Pod traffic needs underlying routing support, it is handled by host default route.
	}

	// clean up function if any route add failed
	deleteRtFn := func() {
		for _, route := range routes {
			_ = netlink.RouteDel(route)
		}
	}

	var err error = nil
	for _, route := range routes {
		if err := netlink.RouteReplace(route); err != nil {
			deleteRtFn()
			err = fmt.Errorf("failed to install route to peer %s with netlink for route %+v: %v", peerNodeIP, route, err)
			return nil, err
		}
	}
	hrs := []HostRoute{}
	for _, rt := range routes {
		hrs = append(hrs, &hRoute{rt})
	}
	return hrs, err
}

// ListPeerCIDRRoute returns list of routes from peer and local CIDRs
func (c *Client) ListPeerCIDRRoute() (map[string][]HostRoute, error) {
	// get all routes on gw0 from service table.
	filter := &netlink.Route{
		Table:     ServiceRtTable.Idx,
		LinkIndex: util.GetNetLinkIndex(c.nodeConfig.GatewayConfig.Link)}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	if err != nil {
		return nil, err
	}

	rtMap := make(map[string][]*netlink.Route)
	for _, rt := range routes {
		// rt is reference to actual data, as it changes,
		// it cannot be used for assignment
		tmpRt := rt
		rtMap[rt.Dst.String()] = append(rtMap[rt.Dst.String()], &tmpRt)
	}

	if !ServiceRtTable.IsMainTable() {
		// get all routes on gw0 from main table.
		filter.Table = 0
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_OIF)
		if err != nil {
			return nil, err
		}
		for _, rt := range routes {
			// rt is reference to actual data, as it changes,
			// it cannot be used for assignment
			tmpRt := rt
			rtMap[rt.Dst.String()] = append(rtMap[rt.Dst.String()], &tmpRt)
		}

		// now get all routes gw0 on other interfaces from main table.
		routes, err = netlink.RouteListFiltered(netlink.FAMILY_V4, nil, 0)
		if err != nil {
			return nil, err
		}
		for _, rt := range routes {
			if rt.Dst == nil {
				continue
			}
			// insert the route if it is CIDR route and has not been added already.
			// routes with same dst are different if table or linkIndex differs.
			if rl, ok := rtMap[rt.Dst.String()]; ok && (rl[len(rl)-1].LinkIndex != rt.LinkIndex || rl[len(rl)-1].Table != rt.Table) {
				tmpRt := rt
				rtMap[rt.Dst.String()] = append(rl, &tmpRt)
			}
		}
	}
	hrtMap := make(map[string][]HostRoute)
	for key, rts := range rtMap {
		rls := make([]HostRoute, len(rts))
		for i := range rts {
			rls[i] = &hRoute{rts[i]}
		}
		hrtMap[key] = rls
	}
	return hrtMap, nil
}

func (c *Client) readRtTable() (string, error) {
	f, err := os.OpenFile(routeTableConfigPath, os.O_RDONLY, 0)
	if err != nil {
		return "", fmt.Errorf("route table(open): %w", err)
	}
	defer func() { _ = f.Close() }()

	tablesRaw := make([]byte, 1024)
	bLen, err := f.Read(tablesRaw)
	if err != nil {
		return "", fmt.Errorf("route table(read): %w", err)
	}
	return string(tablesRaw[:bLen]), nil
}

// RemoveServiceRouting removes service routing setup.
func (c *Client) RemoveServiceRouting() error {
	// remove service table
	tables, err := c.readRtTable()
	if err != nil {
		return err
	}
	newTable := fmt.Sprintf("%d %s", AntreaServiceTableIdx, AntreaServiceTable)
	if strings.Index(tables, newTable) != -1 {
		tables = strings.Replace(tables, newTable, "", -1)
		f, err := os.OpenFile(routeTableConfigPath, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return fmt.Errorf("route table(open): %w", err)
		}
		defer func() { _ = f.Close() }()
		if _, err = f.WriteString(tables); err != nil {
			return fmt.Errorf("route table(write): %w", err)
		}
	}

	// flush service table
	filter := &netlink.Route{
		Table:     AntreaServiceTableIdx,
		LinkIndex: util.GetNetLinkIndex(c.nodeConfig.GatewayConfig.Link)}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	if err != nil {
		return fmt.Errorf("route table(list): %w", err)
	}
	for _, route := range routes {
		if err = netlink.RouteDel(&route); err != nil {
			return fmt.Errorf("route delete: %w", err)
		}
	}

	// delete ip rule for service table
	ipRule := netlink.NewRule()
	ipRule.IifName = c.nodeConfig.GatewayConfig.Link
	ipRule.Mark = iptables.RtTblSelectorValue
	ipRule.Table = AntreaServiceTableIdx
	ipRule.Priority = AntreaIPRulePriority
	if err = netlink.RuleDel(ipRule); err != nil {
		return fmt.Errorf("ip rule delete: %w", err)
	}
	return nil
}
