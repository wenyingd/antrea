// +build !windows

package ovsconfig

const (
	defaultConnNetwork = "unix"
	defaultConnAddress = "/run/openvswitch/db.sock"
	// Wait up to 1 second when get port
	defaultGetPortTimeout = 1000
)
