// +build !windows

package cni

import "net"

// AntreaCNISocketAddr is the UNIX socket used by the CNI Protobuf / gRPC service.
const AntreaCNISocketAddr = "/var/run/antrea/cni.sock"

func Dial(address string) (net.Conn, error) {
	return net.Dial("unix", address)
}
