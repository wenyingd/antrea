package agenttweaker

import (
	"context"
	"fmt"

	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/k8s"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// Initializer knows how to setup agent tweaker.
type Initializer struct {
	client clientset.Interface
}

func NewInitializer(k8sClient clientset.Interface) *Initializer {
	return &Initializer{
		client: k8sClient,
	}
}

// GetNodeInterfaceName retrieves node's iface name
func (i *Initializer) GetNodeInterfaceName() (string, error) {
	nodeName, err := env.GetNodeName()
	if err != nil {
		return "", nil
	}
	node, err := i.client.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		klog.Errorf("Failed to get node from K8s with name %s: %v", nodeName, err)
		return "", err
	}

	ipAddr, err := k8s.GetNodeAddrs(node)
	if err != nil {
		return "", fmt.Errorf("failed to obtain local IP address from k8s: %w", err)
	}
	_, _, localIntf, err := util.GetIPNetDeviceFromIP(ipAddr, sets.New[string]())
	if err != nil {
		return "", fmt.Errorf("failed to get local IPNet:  %v", err)
	}
	return localIntf.Name, nil
}
