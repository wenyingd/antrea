package main

import (
	"fmt"

	"antrea.io/antrea/pkg/agent/util/ethtool"
	"antrea.io/antrea/pkg/agenttweaker"
	"antrea.io/antrea/pkg/util/k8s"
)

func run(opts *Options) error {
	cfg := opts.config

	k8sClient, _, _, _, _, _, err := k8s.CreateClients(cfg.ClientConnection, "")
	if err != nil {
		return fmt.Errorf("error creating K8s clients: %v", err)
	}

	init := agenttweaker.NewInitializer(k8sClient)

	// If user want to disable udp tunnel offloading on node, we use ethtool to do it. Otherwise, we do nothing.
	// Error can happen if the iface does not support toggle the related flags.
	if cfg.DisableUdpTunnelOffload {
		name, err := init.GetNodeInterfaceName()
		if err != nil {
			return fmt.Errorf("error get node iface name: %v", err)
		}
		if err := ethtool.EthtoolDisableUdpTunnelOffload(name); err != nil {
			return fmt.Errorf("error disable vxlan offload on interface %s: %s", name, err.Error())
		}
	}

	return nil
}
