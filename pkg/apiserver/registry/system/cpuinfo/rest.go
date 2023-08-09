// Copyright 2023 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cpuinfo

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/rest"

	"antrea.io/antrea/pkg/agent/apiserver/handlers/cpuinfo"
	systemv1beta1 "antrea.io/antrea/pkg/apis/system/v1beta1"
)

func NewREST() *REST {
	return &REST{
		cache: &systemv1beta1.NodeCPUInfo{
			ObjectMeta: metav1.ObjectMeta{},
		},
	}
}

var (
	_ rest.Scoper = &REST{}
	_ rest.Getter = &REST{}
)

type REST struct {
	cache *systemv1beta1.NodeCPUInfo
}

func (r *REST) New() runtime.Object {
	return &systemv1beta1.NodeCPUInfo{}
}

func (r *REST) Destroy() {
}

func (r *REST) Get(_ context.Context, _ string, _ *metav1.GetOptions) (runtime.Object, error) {
	cpuInfo, err := cpuinfo.ParseCPUInfoFromSys()
	if err != nil {
		return nil, err
	}
	return cpuInfo, nil
}

func (r *REST) NamespaceScoped() bool {
	return false
}
