package cniserver

import (
	"github.com/Microsoft/go-winio"
	"net"
)

func Listen(address string) (net.Listener, error) {
	return winio.ListenPipe(address, nil)
}
