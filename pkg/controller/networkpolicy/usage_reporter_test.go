package networkpolicy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// waitForIdleController waits for the controller's heartbeat channel to be idle for the provided
// duration, at which time we can consider the computation is done.
func (c *networkPolicyController) waitForIdleController(idleTimeout time.Duration) {
	timer := time.NewTimer(idleTimeout)
	for {
		timer.Reset(idleTimeout)
		select {
		case <-c.heartbeatCh:
			continue
		case <-timer.C:
			return
		}
	}
}

func TestNetworkPolicyUsageReporter(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "nsA",
		},
	}
	pod := getPod("p1", "nsA", "", "1.1.1.1", false)
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "npA", UID: "uidA"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}
	_, c := newController([]runtime.Object{ns, pod, np}, nil)
	stopCh := make(chan struct{})
	defer close(stopCh)
	c.informerFactory.Start(stopCh)
	go c.Run(stopCh)

	c.informerFactory.WaitForCacheSync(stopCh)

	numNetworkPolicies, err := c.GetNumNetworkPolicies()
	assert.NoError(t, err, "Error when calling GetNumNetworkPolicies")
	assert.Equal(t, 1, numNetworkPolicies)

	numTiers, err := c.GetNumTiers()
	assert.NoError(t, err, "Error when calling GetNumTiers")
	assert.Equal(t, 0, numTiers)

	numAntreaNetworkPolicies, err := c.GetNumAntreaNetworkPolicies()
	assert.NoError(t, err, "Error when calling GetNumAntreaNetworkPolicies")
	assert.Equal(t, 0, numAntreaNetworkPolicies)

	numAntreaClusterNetworkPolicies, err := c.GetNumAntreaClusterNetworkPolicies()
	assert.NoError(t, err, "Error when calling GetNumAntreaClusterNetworkPolicies")
	assert.Equal(t, 0, numAntreaClusterNetworkPolicies)
}
