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

package arping

import (
	"fmt"
	"net"
	"syscall"
)

const (
	// 1544 = htons(ETH_P_ARP)
	protoARP = 1544
)

// GratuitousARPOverIface sends an gratuitous arp over interface 'iface' from 'srcIP'.
// It refers to "github.com/j-keck/arping" and is simplified and made thread-safe.
func GratuitousARPOverIface(srcIP net.IP, iface *net.Interface) error {
	ipv4 := srcIP.To4()
	if ipv4 == nil {
		return fmt.Errorf("IPv6 is not supported yet")
	}

	srcMac := iface.HardwareAddr
	broadcastMac := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	request := newARPRequest(srcMac, ipv4, broadcastMac, ipv4)

	toSockaddr := &syscall.SockaddrLinklayer{Ifindex: iface.Index}

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, protoARP)
	if err != nil {
		return err
	}
	defer syscall.Close(sock)

	return syscall.Sendto(sock, request, 0, toSockaddr)
}
