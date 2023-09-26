package arping

import (
	"bytes"
	"encoding/binary"
)

func newARPRequest(sha, spa, tha, tpa []byte) []byte {
	frame := bytes.NewBuffer(nil)
	// Ethernet header.
	frame.Write(tha)                // Destination MAC address.
	frame.Write(sha)                // Source MAC address.
	frame.Write([]byte{0x08, 0x06}) // Ethernet protocol type, 0x0806 for ARP.
	// ARP message.
	binary.Write(frame, binary.BigEndian, uint16(1))      // Hardware Type, Ethernet is 1.
	binary.Write(frame, binary.BigEndian, uint16(0x0800)) // Protocol type, IPv4 is 0x0800.
	binary.Write(frame, binary.BigEndian, uint8(6))       // Hardware length, Ethernet address length is 6.
	binary.Write(frame, binary.BigEndian, uint8(4))       // Protocol length, IPv4 address length is 4.
	binary.Write(frame, binary.BigEndian, uint16(1))      // Operation, request is 1.
	frame.Write(sha)                                      // Sender hardware address.
	frame.Write(spa)                                      // Sender protocol address.
	frame.Write(tha)                                      // Target hardware address.
	frame.Write(tpa)                                      // Target protocol address.
	return frame.Bytes()
}
