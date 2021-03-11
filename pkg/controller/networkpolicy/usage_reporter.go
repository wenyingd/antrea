package networkpolicy

import (
	"fmt"

	"k8s.io/apimachinery/pkg/labels"

	"antrea.io/antrea/pkg/features"
)

type NetworkPolicyUsageReporter interface {
	GetNumTiers() (int, error)
	GetNumNetworkPolicies() (int, error)
	GetNumAntreaNetworkPolicies() (int, error)
	GetNumAntreaClusterNetworkPolicies() (int, error)
}

func (n *NetworkPolicyController) GetNumTiers() (int, error) {
	if !features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		return 0, nil
	}
	list, err := n.tierLister.List(labels.Everything())
	if err != nil {
		return 0, fmt.Errorf("error when listing Tiers: %v", err)
	}
	return len(list), nil
}

func (n *NetworkPolicyController) GetNumNetworkPolicies() (int, error) {
	list, err := n.networkPolicyLister.List(labels.Everything())
	if err != nil {
		return 0, fmt.Errorf("error when listing NetworkPolicies: %v", err)
	}
	return len(list), nil
}

func (n *NetworkPolicyController) GetNumAntreaNetworkPolicies() (int, error) {
	if !features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		return 0, nil
	}
	list, err := n.annpLister.List(labels.Everything())
	if err != nil {
		return 0, fmt.Errorf("error when listing AntreaNetworkPolicies: %v", err)
	}
	return len(list), nil
}

func (n *NetworkPolicyController) GetNumAntreaClusterNetworkPolicies() (int, error) {
	if !features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		return 0, nil
	}
	list, err := n.acnpLister.List(labels.Everything())
	if err != nil {
		return 0, fmt.Errorf("error when listing AntreaClusterNetworkPolicies: %v", err)
	}
	return len(list), nil
}
