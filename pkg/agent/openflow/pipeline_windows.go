//go:build windows
// +build windows

// Copyright 2021 Antrea Authors
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

package openflow

import (
	"net"

	binding "antrea.io/antrea/pkg/ovs/openflow"
)

// hostBridgeUplinkFlows generates the flows that forward traffic between the bridge local port and the uplink port to
// support the host traffic with outside.
func (f *featurePodConnectivity) hostBridgeUplinkFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	flows := f.hostBridgeLocalFlows()
	if f.networkConfig.IPv4Enabled {
		flows = append(flows,
			// This generates the flow to forward ARP packets from uplink port to bridge local port since uplink port is set
			// to disable flood.
			ARPSpoofGuardTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchInPort(f.uplinkPort).
				Action().Output(f.hostIfacePort).
				Done(),
			// This generates the flow to forward ARP packets from bridge local port to uplink port since uplink port is set
			// to disable flood.
			ARPSpoofGuardTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchInPort(f.hostIfacePort).
				Action().Output(f.uplinkPort).
				Done())
	}
	if f.networkConfig.TrafficEncapMode.SupportsNoEncap() {
		// TODO: support IPv6
		localSubnetMap := map[binding.Protocol]net.IPNet{binding.ProtocolIP: *f.nodeConfig.PodIPv4CIDR}
		// If NoEncap is enabled, the reply packets from remote Pod can be forwarded to local Pod directly.
		// by explicitly resubmitting them to ConntrackState stage and marking "macRewriteMark" at same time.
		for ipProtocol, localSubnet := range localSubnetMap {
			flows = append(flows, ClassifierTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchInPort(f.uplinkPort).
				MatchDstIPNet(localSubnet).
				Action().LoadRegMark(FromUplinkRegMark, RewriteMACRegMark).
				Action().GotoStage(stageConntrackState).
				Done())
		}
	}
	return flows
}

func (f *featurePodConnectivity) l3FwdFlowToRemoteViaRouting(localGatewayMAC net.HardwareAddr,
	remoteGatewayMAC net.HardwareAddr,
	peerIP net.IP,
	peerPodCIDR *net.IPNet) []binding.Flow {
	var flows []binding.Flow

	if f.networkConfig.NeedsDirectRoutingToPeer(peerIP, f.nodeConfig.NodeTransportIPv4Addr) && remoteGatewayMAC != nil {
		ipProtocol := getIPProtocol(peerIP)
		cookieID := f.cookieAllocator.Request(f.category).Raw()
		// It enhances Windows Noencap mode performance by bypassing host network.
		flows = append(flows,
			// Output the reply packet to the uplink interface if the destination is another Node's IP.
			// This is for the scenario that another Node directly accesses Pods on this Node. Since the request
			// packet enters OVS from the uplink interface, the reply should go back in the same path. Otherwise,
			// Windows host will perform stateless SNAT on the reply, and the packets are possibly dropped on peer
			// Node because of the wrong source address.
			L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchDstIP(peerIP).
				MatchCTStateRpl(true).
				MatchCTStateTrk(true).
				Action().SetSrcMAC(f.nodeConfig.UplinkNetConfig.MAC).
				Action().SetDstMAC(remoteGatewayMAC).
				Action().NextTable().
				Done(),
			// This generates the flow to match the packets destined for remote Node by matching destination MAC, then
			// load the ofPort number of uplink to TargetOFPortField.
			L2ForwardingCalcTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchDstMAC(remoteGatewayMAC).
				Action().LoadToRegField(TargetOFPortField, f.uplinkPort).
				Action().LoadRegMark(OutputToOFPortRegMark).
				Action().GotoStage(stageConntrack).
				Done(),
		)
		flows = append(flows, f.l3FwdFlowToRemoteViaUplink(remoteGatewayMAC, *peerPodCIDR, false))
	} else {
		flows = append(flows, f.l3FwdFlowToRemoteViaGW(localGatewayMAC, *peerPodCIDR))
	}
	return flows
}

func (f *featureEgress) snatMarkFlows(snatIP net.IP, mark uint32) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	flows := []binding.Flow{f.snatIPFromTunnelFlow(cookieID, snatIP, mark)}
	for _, ipProto := range f.ipProtocols {
		flows = append(flows,
			// Commit the new connection into DNAT conntrack zone and set with EgressSNATCTMark if it is configured
			// with pkt_mark.
			SNATMarkTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProto).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegFieldWithValue(PacketMarkField, mark).
				Action().CT(true, SNATMarkTable.GetNext(), f.dnatCtZones[ipProto], nil).
				LoadToCtMark(EgressSNATCTMark).
				CTDone().
				Done(),
			// Perform SNAT on the packet with the corresponding snatIP if mark is set. In the meanwhile,
			// EgressSNATCTMark is set on the packet which is consumed in L2Forwarding table.
			SNATTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProto).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegFieldWithValue(PacketMarkField, mark).
				Action().CT(true, SNATTable.GetNext(), f.snatCtZones[ipProto], nil).
				SNAT(&binding.IPRange{StartIP: snatIP, EndIP: snatIP}, nil).
				LoadToCtMark(EgressSNATCTMark).
				CTDone().
				Done(),
		)
		if ipProto == binding.ProtocolIP {
			flows = append(flows,
				ARPSpoofGuardTable.ofTable.BuildFlow(priorityHigh).
					Cookie(cookieID).
					MatchInPort(f.uplinkPort).
					MatchProtocol(binding.ProtocolARP).
					MatchARPTpa(snatIP).
					Action().LoadRegMark(FromEgressRegMark).
					Action().NextTable().
					Done())
		}
	}
	return flows
}

func (f *featureEgress) podLocalSNATFlow(cookieID uint64, ipProtocol binding.Protocol, ofPort uint32, snatIP net.IP, snatMark uint32) binding.Flow {
	return EgressMarkTable.ofTable.BuildFlow(priorityNormal).
		Cookie(cookieID).
		MatchProtocol(ipProtocol).
		MatchCTStateNew(true).
		MatchCTStateTrk(true).
		MatchInPort(ofPort).
		Action().LoadToRegField(PacketMarkField, snatMark).
		Action().NextTable().
		Done()
}

// snatIPFromTunnelFlow generates the flow that marks SNAT packets tunnelled from remote Nodes. The SNAT IP matches the
// packet's tunnel destination IP.
func (f *featureEgress) snatIPFromTunnelFlow(cookieID uint64, snatIP net.IP, mark uint32) binding.Flow {
	ipProtocol := getIPProtocol(snatIP)
	return EgressMarkTable.ofTable.BuildFlow(priorityNormal).
		Cookie(cookieID).
		MatchProtocol(ipProtocol).
		MatchCTStateNew(true).
		MatchCTStateTrk(true).
		MatchTunnelDst(snatIP).
		Action().LoadToRegField(PacketMarkField, mark).
		Action().NextTable().
		Done()
}
