package openflow

import binding "antrea.io/antrea/pkg/ovs/openflow"

// Fields used reg.
var (
	// reg0 (NXM_NX_REG0)
	// reg0[0..3]: Field to mark the packet source. Marks in this field include,
	//   - 0: from the tunnel port
	//   - 1: from antrea-gw0
	//   - 2: from the local Pods
	//   - 4: from the Bridge interface
	//   - 5: from the uplink interface
	PktSourceField  = binding.NewRegField(0, 0, 3)
	FromTunnelMark  = binding.NewRegMarkWithField(PktSourceField, 0)
	FromGatewayMark = binding.NewRegMarkWithField(PktSourceField, 1)
	FromLocalMark   = binding.NewRegMarkWithField(PktSourceField, 2)
	FromUplinkMark  = binding.NewRegMarkWithField(PktSourceField, 4)
	FromBridgeMark  = binding.NewRegMarkWithField(PktSourceField, 5)
	// reg0[16]: Mark to indicate the ofPort number of an interface is found.
	OFPortFoundMark = createOneBitRegMark(0, 16)
	// reg0[17]: Mark to indicate the packet needs to be SNATed with Node's IP.
	SNATNodeIPMark = createOneBitRegMark(0, 17)
	// reg0[18]: Mark to indicate the packet needs DNAT to virtual IP.
	// If a packet uses markHairpin, it will be output to the port where it enters OVS pipeline in L2ForwardingOutTable.
	markHairpin = createOneBitRegMark(0, 18)
	// reg0[19]: Mark to indicate the packet's MAC address needs to be rewritten.
	RewriteMACMark = createOneBitRegMark(0, 19)
	// reg0[20]: Mark to indicate the packet is denied(Drop/Reject).
	CnpDenyMark = createOneBitRegMark(0, 20)
	// reg0[21..22]: Field to indicate disposition of Antrea Policy. It could have more bits to support more disposition
	// that Antrea policy support in the future.
	// Marks in this field include,
	//   - 0b00: allow
	//   - 0b01: drop
	//   - 0b10: reject
	APDispositionField   = binding.NewRegField(0, 21, 22)
	DispositionAllowMark = binding.NewRegMarkWithField(APDispositionField, DispositionAllow)
	DispositionDropMark  = binding.NewRegMarkWithField(APDispositionField, DispositionDrop)
	DispositionRejMark   = binding.NewRegMarkWithField(APDispositionField, DispositionRej)
	// reg0[24..26]: Field to indicate the reasons of sending packet to the controller.
	// Marks in this field include,
	//   - 0b00: logging
	//   - 0b01: reject
	//   - 0b10: drop
	CustomReasonField       = binding.NewRegField(0, 24, 26)
	MarkCustomReasonLogging = binding.NewRegMarkWithField(CustomReasonField, CustomReasonLogging)
	MarkCustomReasonReject  = binding.NewRegMarkWithField(CustomReasonField, CustomReasonReject)
	MarkCustomReasonDeny    = binding.NewRegMarkWithField(CustomReasonField, CustomReasonDeny)

	// reg1(NXM_NX_REG1)
	// Field to cache the ofPort of the OVS interface where to output packet.
	TargetOFPortField = binding.NewRegField(1, 0, 31)

	// reg2(NXM_NX_REG2)
	// Field to help swap values in two different flow fields in the OpenFlow actions. This field is only used in func
	// `arpResponderStaticFlow`.
	SwapField = binding.NewRegField(2, 0, 31)

	// reg3(NXM_NX_REG3)
	// Field to store the selected Service Endpoint IP
	EndpointIPField = binding.NewRegField(3, 0, 31)
	// Field to store the conjunction ID which is for "deny" rule in CNP. It shares the same register with EndpointIPField,
	// since the service selection will finish when a packet hitting NetworkPolicy related rules.
	CNPDenyConjIDField = binding.NewRegField(3, 0, 31)

	// reg4(NXM_NX_REG4)
	// reg4[0..15]: Field to store the selected Service Endpoint port.
	EndpointPortField = binding.NewRegField(4, 0, 15)
	// reg4[16..18]: Field to store the state of a packet accessing a Service. Marks in this field include,
	//	- 0b001: packet need to do service selection.
	//	- 0b010: packet has done service selection.
	//	- 0b011: packet has done service selection and the selection result needs to be cached.
	ServiceEPStateField = binding.NewRegField(4, 16, 18)
	EpToSelectMark      = binding.NewRegMarkWithField(ServiceEPStateField, 0b001)
	EpSelectedMark      = binding.NewRegMarkWithField(ServiceEPStateField, 0b010)
	EpToLearnMark       = binding.NewRegMarkWithField(ServiceEPStateField, 0b011)
	// reg4[0..18]: Field to cache the union value of Endpoint port and Endpoint status. It is used as a single match
	// when needed.
	EpUnionField = binding.NewRegField(4, 0, 18)

	// reg5(NXM_NX_REG5)
	// Field to cache the Egress conjunction ID hit by TraceFlow packet.
	TFEgressConjIDField = binding.NewRegField(5, 0, 31)

	// reg(N6XM_NX_REG6)
	// Field to cache the Ingress conjunction ID hit by TraceFlow packet.
	TFIngressConjIDField = binding.NewRegField(6, 0, 31)
)

// Fields used xxreg.
var (
	// xxreg3(NXM_NX_XXREG3)
	// xxreg3: Field to cache Endpoint IPv6 address. It occupies reg12-reg15 in the meanwhile.
	EndpointIP6Field = binding.NewXXRegField(3, 0, 127)
)

// Marks used in conntrack
var (
	// Mark to indicate the connection is initiated through the host gateway interface
	// (i.e. for which the first packet of the connection was received through the gateway).
	gatewayCTMark = binding.NewCtMark(0x20, 0, 31)
	// Mark to indicate DNAT is performed on the connection for Service.
	ServiceCTMark = binding.NewCtMark(0x21, 0, 31)
)

func createOneBitRegMark(regID int, bit uint32) *binding.RegMark {
	return binding.NewRegMark(regID, 1, bit, bit)
}
