package ovsconfig

const (
	defaultConnNetwork = "winpipe"
	defaultConnAddress = `\\.\pipe\C:openvswitchvarrunopenvswitchdb.sock`
	// Wait up to 2 seconds when get port, the operation of port creation
	// cost more time on Windows platform than on Linux
	defaultGetPortTimeout = 2000
)
