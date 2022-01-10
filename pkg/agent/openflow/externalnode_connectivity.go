package openflow

import (
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featureExternalNodeConnectivity struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol
	ctZones         map[binding.Protocol]int
	category        cookie.Category

	uplinkFlowCache *flowCategoryCache
}

func (f *featureExternalNodeConnectivity) getFeatureName() string {
	return "ExternalNodeConnectivity"
}

func newFeatureVMBMConnectivity(
	cookieAllocator cookie.Allocator,
	ipProtocols []binding.Protocol) *featureExternalNodeConnectivity {
	ctZones := make(map[binding.Protocol]int)
	for _, ipProtocol := range ipProtocols {
		if ipProtocol == binding.ProtocolIP {
			ctZones[ipProtocol] = CtZone
		} else if ipProtocol == binding.ProtocolIPv6 {
			ctZones[ipProtocol] = CtZoneV6
		}
	}

	return &featureExternalNodeConnectivity{
		cookieAllocator: cookieAllocator,
		ipProtocols:     ipProtocols,
		uplinkFlowCache: newFlowCategoryCache(),
		ctZones:         ctZones,
		category:        cookie.VMConnectivity,
	}
}

func (f *featureExternalNodeConnectivity) hostUplinkFlows(hostOFPort, uplinkOFPort uint32) []binding.Flow {
	return []binding.Flow{
		ClassifierTable.ofTable.BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchInPort(hostOFPort).
			Action().LoadRegMark(OFPortFoundRegMark).
			Action().LoadToRegField(TargetOFPortField, uplinkOFPort).
			Action().NextTable().
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			Done(),
		ClassifierTable.ofTable.BuildFlow(priorityNormal).
			MatchInPort(uplinkOFPort).
			MatchProtocol(binding.ProtocolIP).
			Action().LoadRegMark(OFPortFoundRegMark).
			Action().LoadToRegField(TargetOFPortField, hostOFPort).
			Action().NextTable().
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			Done(),
		NotIPTable.ofTable.BuildFlow(priorityNormal).
			MatchInPort(hostOFPort).
			Action().Output(uplinkOFPort).
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			Done(),
		NotIPTable.ofTable.BuildFlow(priorityNormal).
			MatchInPort(uplinkOFPort).
			Action().Output(hostOFPort).
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			Done(),
	}
}

func (f *featureExternalNodeConnectivity) initFlows() []binding.Flow {
	flows := []binding.Flow{
		L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal).
			MatchRegMark(OFPortFoundRegMark).
			Action().OutputToRegField(TargetOFPortField).
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			Done(),
	}
	for _, proto := range f.ipProtocols {
		ctZone := CtZone
		if proto == binding.ProtocolIPv6 {
			ctZone = CtZoneV6
		}
		flows = append(flows,
			// This generates the flow to maintain tracked connection in CT zone.
			ConntrackTable.ofTable.BuildFlow(priorityNormal).
				Cookie(f.cookieAllocator.Request(f.category).Raw()).
				MatchProtocol(proto).
				Action().CT(false, ConntrackTable.ofTable.GetNext(), ctZone, nil).
				CTDone().
				Done(),
			ConntrackStateTable.ofTable.BuildFlow(priorityLow).MatchProtocol(proto).
				MatchCTStateInv(true).MatchCTStateTrk(true).
				Action().Drop().
				Cookie(f.cookieAllocator.Request(f.category).Raw()).
				Done(),
			ConntrackCommitTable.ofTable.BuildFlow(priorityLow).MatchProtocol(proto).
				MatchCTStateNew(true).MatchCTStateTrk(true).
				Action().CT(true, ConntrackCommitTable.GetNext(), ctZone, nil).CTDone().
				Cookie(f.cookieAllocator.Request(f.category).Raw()).
				Done(),
		)
	}

	return flows
}

func (f *featureExternalNodeConnectivity) replayFlows() []binding.Flow {
	var flows []binding.Flow
	rangeFunc := func(key, value interface{}) bool {
		cachedFlows := value.([]binding.Flow)
		for _, flow := range cachedFlows {
			flow.Reset()
			flows = append(flows, flow)
		}
		return true
	}
	f.uplinkFlowCache.Range(rangeFunc)
	return flows
}

func (c *client) InstallHostUplinkFlows(hostIFName string, hostPort int32, uplinkPort int32) error {
	flows := c.featureExNodeConnectivity.hostUplinkFlows(uint32(hostPort), uint32(uplinkPort))
	return c.addFlows(c.featureExNodeConnectivity.uplinkFlowCache, hostIFName, flows)
}

func (c *client) UninstallHostUplinkFlows(hostIFName string) error {
	return c.deleteFlows(c.featureExNodeConnectivity.uplinkFlowCache, hostIFName)
}

// notIPPipelineClassifyFlow generates a flow in PipelineClassifierTable to resubmit packets not using IP protocols to
// pipelineNotIP.
func notIPPipelineClassifyFlow(cookieID uint64, pipeline binding.Pipeline) binding.Flow {
	targetTable := pipeline.GetFirstTable()
	return PipelineRootClassifierTable.ofTable.BuildFlow(priorityLow).
		Cookie(cookieID).
		Action().ResubmitToTables(targetTable.GetID()).
		Done()
}
