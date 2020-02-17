// +build !windows

package cniserver

import (
	"k8s.io/klog"
	"net"
	"os"
	"path/filepath"
)

func Listen(address string) (net.Listener, error) {
	// remove before bind to avoid "address already in use" errors
	os.Remove(s.cniSocket)

	if err := os.MkdirAll(filepath.Dir(address), 0755); err != nil {
		klog.Fatalf("Failed to create directory %s: %v", filepath.Dir(address), err)
	}
	return net.Listen("unix", address)
}
