// Copyright 2024 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by client-gen. DO NOT EDIT.

package v1beta1

import (
	"context"

	v1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	scheme "antrea.io/antrea/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// NetworkPoliciesGetter has a method to return a NetworkPolicyInterface.
// A group's client should implement this interface.
type NetworkPoliciesGetter interface {
	NetworkPolicies(namespace string) NetworkPolicyInterface
}

// NetworkPolicyInterface has methods to work with NetworkPolicy resources.
type NetworkPolicyInterface interface {
	Create(ctx context.Context, networkPolicy *v1beta1.NetworkPolicy, opts v1.CreateOptions) (*v1beta1.NetworkPolicy, error)
	Update(ctx context.Context, networkPolicy *v1beta1.NetworkPolicy, opts v1.UpdateOptions) (*v1beta1.NetworkPolicy, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, networkPolicy *v1beta1.NetworkPolicy, opts v1.UpdateOptions) (*v1beta1.NetworkPolicy, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1beta1.NetworkPolicy, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1beta1.NetworkPolicyList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1beta1.NetworkPolicy, err error)
	NetworkPolicyExpansion
}

// networkPolicies implements NetworkPolicyInterface
type networkPolicies struct {
	*gentype.ClientWithList[*v1beta1.NetworkPolicy, *v1beta1.NetworkPolicyList]
}

// newNetworkPolicies returns a NetworkPolicies
func newNetworkPolicies(c *CrdV1beta1Client, namespace string) *networkPolicies {
	return &networkPolicies{
		gentype.NewClientWithList[*v1beta1.NetworkPolicy, *v1beta1.NetworkPolicyList](
			"networkpolicies",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *v1beta1.NetworkPolicy { return &v1beta1.NetworkPolicy{} },
			func() *v1beta1.NetworkPolicyList { return &v1beta1.NetworkPolicyList{} }),
	}
}
