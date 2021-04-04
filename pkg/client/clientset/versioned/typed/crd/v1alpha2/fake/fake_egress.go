// Copyright 2021 Antrea Authors
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

package fake

import (
	"context"

	v1alpha2 "github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha2"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeEgresses implements EgressInterface
type FakeEgresses struct {
	Fake *FakeCrdV1alpha2
}

var egressesResource = schema.GroupVersionResource{Group: "crd.antrea.io", Version: "v1alpha2", Resource: "egresses"}

var egressesKind = schema.GroupVersionKind{Group: "crd.antrea.io", Version: "v1alpha2", Kind: "Egress"}

// Get takes name of the egress, and returns the corresponding egress object, and an error if there is any.
func (c *FakeEgresses) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha2.Egress, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(egressesResource, name), &v1alpha2.Egress{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha2.Egress), err
}

// List takes label and field selectors, and returns the list of Egresses that match those selectors.
func (c *FakeEgresses) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha2.EgressList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(egressesResource, egressesKind, opts), &v1alpha2.EgressList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha2.EgressList{ListMeta: obj.(*v1alpha2.EgressList).ListMeta}
	for _, item := range obj.(*v1alpha2.EgressList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested egresses.
func (c *FakeEgresses) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(egressesResource, opts))
}

// Create takes the representation of a egress and creates it.  Returns the server's representation of the egress, and an error, if there is any.
func (c *FakeEgresses) Create(ctx context.Context, egress *v1alpha2.Egress, opts v1.CreateOptions) (result *v1alpha2.Egress, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(egressesResource, egress), &v1alpha2.Egress{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha2.Egress), err
}

// Update takes the representation of a egress and updates it. Returns the server's representation of the egress, and an error, if there is any.
func (c *FakeEgresses) Update(ctx context.Context, egress *v1alpha2.Egress, opts v1.UpdateOptions) (result *v1alpha2.Egress, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(egressesResource, egress), &v1alpha2.Egress{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha2.Egress), err
}

// Delete takes name of the egress and deletes it. Returns an error if one occurs.
func (c *FakeEgresses) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(egressesResource, name), &v1alpha2.Egress{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeEgresses) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(egressesResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha2.EgressList{})
	return err
}

// Patch applies the patch and returns the patched egress.
func (c *FakeEgresses) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha2.Egress, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(egressesResource, name, pt, data, subresources...), &v1alpha2.Egress{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha2.Egress), err
}
