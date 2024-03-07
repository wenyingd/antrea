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

package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWindowsNodeCPUInfo(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	nodes, err := data.clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	for _, node := range nodes.Items {
		nodeCPUInfo, err := getNodeCPUInfo(data, node)
		assert.NoError(t, err)

		assert.Equal(t, true, nodeCPUInfo.Cores > 0)
		assert.Equal(t, true, nodeCPUInfo.CPUs > 0)
	}
}
