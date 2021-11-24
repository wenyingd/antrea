package ethtool

import (
	"bytes"
	"errors"
	"k8s.io/klog/v2"
	"os/exec"
	"syscall"
)

// RunCommand will run a linux command and gather its output and exit code
func RunCommand(name string, args ...string) (stdout string, stderr string, exitCode int) {
	klog.Infof("Run command: %s %s", name, args)
	var outbuf, errbuf bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = &outbuf
	cmd.Stderr = &errbuf

	err := cmd.Run()
	stdout = outbuf.String()
	stderr = errbuf.String()

	if err != nil {
		// try to get the exit code
		if exitError, ok := err.(*exec.ExitError); ok {
			ws := exitError.Sys().(syscall.WaitStatus)
			exitCode = ws.ExitStatus()
		} else {
			exitCode = 1
			if stderr == "" {
				stderr = err.Error()
			}
		}
	} else {
		// success, exitCode should be 0 if go is ok
		ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
		exitCode = ws.ExitStatus()
	}
	return
}

// EthtoolDisableUdpTunnelOffload disable udp tunnel offloading on target interface using ethtool.
func EthtoolDisableUdpTunnelOffload(name string) error {
	_, errStr, exit := RunCommand("ethtool", "-K", name,
		"tx-udp_tnl-segmentation", "off", "tx-udp_tnl-csum-segmentation", "off")
	if exit != 0 {
		return errors.New(errStr)
	}
	return nil
}
