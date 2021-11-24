package main

import componentbaseconfig "k8s.io/component-base/config"

type AgentTweakerConfig struct {

	// clientConnection specifies the kubeconfig file and client connection settings for the agent
	// to communicate with the apiserver.
	ClientConnection componentbaseconfig.ClientConnectionConfiguration `yaml:"clientConnection"`

	// DisableUdpTunnelOffload decides whether we will disable udp tunnel offloading on node's default interface. By
	// default, we do nothing
	DisableUdpTunnelOffload bool `yaml:"disableUdpTunnelOffload"`
}
