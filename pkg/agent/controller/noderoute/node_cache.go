package noderoute

import (
	"fmt"
	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
	"net"
)

const (
	nodeIPIndex = "nodeIP"
	nodeLSIndex = "nodeLSID"
)

type NSXNodeNotFoundError struct {
	nodeName string
}

func (e *NSXNodeNotFoundError) Error() string {
	return fmt.Sprintf("not found NodeConfig with name %s", e.nodeName)
}

func newNSXNodeNotFoundError(nodeName string) *NSXNodeNotFoundError {
	return &NSXNodeNotFoundError{nodeName: nodeName}
}

type NodeCache struct {
	nodes cache.Indexer
}

func NewNodeCache() *NodeCache {
	nodes := cache.NewIndexer(
		nodeKeyFunc,
		cache.Indexers{nodeIPIndex: nodeIPIndexFunc, nodeLSIndex: nodeLSIndexFunc},
	)
	return &NodeCache{nodes: nodes}
}

func nodeKeyFunc(obj interface{}) (string, error) {
	node := obj.(*config.NSXNodeConfig)
	return node.Name, nil
}

func nodeIPIndexFunc(obj interface{}) ([]string, error) {
	node := obj.(*config.NSXNodeConfig)
	return []string{node.NodeIP.String()}, nil
}

func nodeLSIndexFunc(obj interface{}) ([]string, error) {
	node := obj.(*config.NSXNodeConfig)
	return []string{node.LogicalSwitchID}, nil
}

func (c *NodeCache) addNode(nodeConfig *config.NSXNodeConfig) {
	c.nodes.Add(nodeConfig)
}

func (c *NodeCache) DeleteNode(nodeConfig *config.NSXNodeConfig) {
	c.nodes.Delete(nodeConfig)
}

func (c *NodeCache) GetNodeByName(nodeName string) (*config.NSXNodeConfig, error) {
	obj, exist, err := c.nodes.GetByKey(nodeName)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, newNSXNodeNotFoundError(nodeName)
	}
	nodeConfig := obj.(*config.NSXNodeConfig)
	return nodeConfig, nil
}

func (c *NodeCache) GetNodeByIP(nodeIP net.IP) ([]*config.NSXNodeConfig, error) {
	nodes, err := c.nodes.ByIndex(nodeIPIndex, nodeIP.String())
	if err != nil {
		return nil, err
	}
	nodeConfigs := make([]*config.NSXNodeConfig, len(nodes))
	for i, node := range nodes {
		nodeConfigs[i] = node.(*config.NSXNodeConfig)
	}
	return nodeConfigs, nil
}

func (c *NodeCache) AddNSXNodeConfig(nodeName string, node *v1.Node) error {
	_, err := c.GetNodeByName(nodeName)
	// NSX node is already added into the cache, and return directly.
	if err == nil {
		return nil
	}
	// Return the error if it is not NSXNodeNotFoundError.
	if _, ok := err.(*NSXNodeNotFoundError); !ok {
		return err
	}
	// Parse the NSX Node configuration from K8s Node configuration.
	nodeConfig, err := ParseNSXNodeConfig(node)
	if err != nil {
		return err
	}

	// Todo: sync node config from nestdb

	c.addNode(nodeConfig)
	klog.Infof("Added NSX Node config into the cache: %v", nodeConfig)
	return nil
}

func (c *NodeCache) DeleteNSXNodeConfig(nodeName string) error {
	nodeConfig, err := c.GetNodeByName(nodeName)
	if err != nil {
		if _, ok := err.(*NSXNodeNotFoundError); !ok {
			return err
		} else {
			return nil
		}
	}
	// Todo: delete node config from nestdb

	c.DeleteNode(nodeConfig)
	klog.Infof("Deleted NSX Node config into the cache: %s", nodeName)
	return nil
}

func ParseNSXNodeConfig(node *v1.Node) (*config.NSXNodeConfig, error) {
	nodeName := node.Name
	ipAddr, err := GetNodeAddr(node)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain local IP address from k8s: %w", err)
	}

	// Spec.PodCIDR can be empty due to misconfiguration
	if node.Spec.PodCIDR == "" {
		klog.Errorf("Spec.PodCIDR is empty for Node %s. Please make sure --allocate-node-cidrs is enabled "+
			"for kube-controller-manager and --cluster-cidr specifies a sufficient CIDR range", nodeName)
		return nil, fmt.Errorf("CIDR string is empty for node %s", nodeName)
	}
	_, localSubnet, err := net.ParseCIDR(node.Spec.PodCIDR)
	if err != nil {
		klog.Errorf("Failed to parse subnet from CIDR string %s: %v", node.Spec.PodCIDR, err)
		return nil, err
	}

	// Parse Node annotations for LogicalSwitch ID and VTEP IP.
	lsKey := "antrea/logical-switch-id"
	vtepKey := "antrea/vtep-ip"
	annotations := node.GetAnnotations()

	lsID, found := annotations[lsKey]
	if !found {
		return nil, fmt.Errorf("logical switch ID is not found in the annotation for Node %s", nodeName)
	}
	vtep, found := annotations[vtepKey]
	if !found {
		return nil, fmt.Errorf("vtep IP is not found in the annotation for Node %s", nodeName)
	}

	return &config.NSXNodeConfig{
		Name:            node.Name,
		NodeIP:          ipAddr,
		PodCIDR:         localSubnet,
		LogicalSwitchID: lsID,
		VtepIP:          net.ParseIP(vtep),
	}, nil
}
