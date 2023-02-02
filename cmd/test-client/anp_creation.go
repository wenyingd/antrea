package main

import (
	"context"
	"fmt"
	"k8s.io/klog/v2"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdclientset "antrea.io/antrea/pkg/client/clientset/versioned"
)

type client struct {
	round      int
	kubeClient crdclientset.Interface
	namespace  string
	number     int
	count      int
}

func (c *client) createANP() {
	start := time.Now()
	defer func() {
		klog.InfoS("Complete creating ANP", "round", c.round, "number", c.number, "cost(s)", time.Now().Sub(start).Seconds())
	}()
	appliedToSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"role": "db"}}
	ingressAction := crdv1alpha1.RuleActionAllow
	egressAction := crdv1alpha1.RuleActionDrop
	ruleProtocol := v1.ProtocolTCP
	egressPort := intstr.FromInt(5978)
	ingressPodSelector1 := &metav1.LabelSelector{MatchLabels: map[string]string{"role": "frontend"}}
	ingressPodSelector2 := &metav1.LabelSelector{MatchLabels: map[string]string{"role": "nondb"}}
	for i := 0; i < c.number; i++ {
		name := fmt.Sprintf("test-anp-%d.%d", c.round, i)
		anp := &crdv1alpha1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: c.namespace, Name: name},
			Spec: crdv1alpha1.NetworkPolicySpec{
				Priority: 5,
				Tier:     "securityops",
				AppliedTo: []crdv1alpha1.AppliedTo{
					{PodSelector: appliedToSelector},
				},
				Ingress: []crdv1alpha1.Rule{
					{
						Name:          "AllowFromFrontend",
						EnableLogging: false,
						Ports: []crdv1alpha1.NetworkPolicyPort{
							{
								Protocol: &ruleProtocol,
							},
						},
						From: []crdv1alpha1.NetworkPolicyPeer{
							{
								PodSelector: ingressPodSelector1,
							},
							{
								PodSelector:       ingressPodSelector2,
								NamespaceSelector: appliedToSelector,
							},
						},
						Action: &ingressAction,
					},
				},
				Egress: []crdv1alpha1.Rule{
					{
						Name:          "DropToThirdParty",
						EnableLogging: false,
						Action:        &egressAction,
						Ports: []crdv1alpha1.NetworkPolicyPort{
							{
								Protocol: &ruleProtocol,
								Port:     &egressPort,
							},
						},
						To: []crdv1alpha1.NetworkPolicyPeer{
							{
								IPBlock: &crdv1alpha1.IPBlock{
									CIDR: "10.0.10.0/24",
								},
							},
						},
					},
				},
			},
		}
		c.kubeClient.CrdV1alpha1().NetworkPolicies(c.namespace).Create(context.Background(), anp, metav1.CreateOptions{})
	}
}

func newANPTester(crdClient crdclientset.Interface, round int, number int) *client {
	c := &client{
		kubeClient: crdClient,
		round:      round,
		namespace:  "default",
		number:     number,
	}
	return c
}
