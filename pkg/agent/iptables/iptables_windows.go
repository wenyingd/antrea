package iptables

import (
	"net"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
)

type dummyClient struct {
}

// Initialize is not implemented on Windows.
func (c *dummyClient) Initialize(hostGateway string, serviceCIDR *net.IPNet, nodeConfig *types.NodeConfig, encapMode config.TrafficEncapModeType) error {
	return nil
}

// AddPeerCIDR is not implemented on Windows.
func (c *dummyClient) AddPeerCIDR(peerPodCIDR *net.IPNet, peerNodeIP net.IP) error {
	return nil
}

// Reconcile is not implemented on Windows.
func (c *dummyClient) Reconcile() error {
	return nil
}

func NewClient() (Client, error) {
	return &dummyClient{}, nil
}
