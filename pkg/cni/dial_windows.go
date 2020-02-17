package cni

import (
	"github.com/Microsoft/go-winio"
	"net"
)

// AntreaCNISocketAddr is the named pipe used by the CNI Protobuf / gRPC service.
const AntreaCNISocketAddr = `\\.\pipe\C:varrunantreacni.sock`

// Support connect to named pipe by specifying network as "winpipe"
func Dial(address string) (net.Conn, error) {
	return winio.DialPipe(address, nil)
}
