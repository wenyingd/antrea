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
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"

	"antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/apis/system/v1beta1"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
)

func getNodeInternalIP(addresses []v1.NodeAddress) (string, error) {
	for _, nodeAddr := range addresses {
		if nodeAddr.Type == v1.NodeInternalIP {
			return nodeAddr.Address, nil
		}
	}
	return "", fmt.Errorf("internal Node IP not found")
}

func getNodeCPUInfo(data *TestData, node v1.Node) (*v1beta1.NodeCPUInfo, error) {
	agentInfo, err := data.crdClient.CrdV1beta1().AntreaAgentInfos().Get(context.TODO(), node.Name, metav1.GetOptions{})

	nodeInternalIP, err := getNodeInternalIP(node.Status.Addresses)
	if err != nil {
		return nil, err
	}

	localConfig := rest.CopyConfig(data.kubeConfig)
	localConfig.Host = net.JoinHostPort(nodeInternalIP, strconv.Itoa(apis.AntreaAgentAPIPort))
	localConfig.Insecure = false
	localConfig.CAFile = ""
	localConfig.CAData = agentInfo.APICABundle
	localConfig.ServerName = "localhost"
	localConfig.NegotiatedSerializer = serializer.CodecFactory{}
	client, err := clientset.NewForConfig(localConfig)
	if err != nil {
		return nil, err
	}

	return client.SystemV1beta1().NodeCPUInfos().Get(context.TODO(), "node", metav1.GetOptions{})
}

func TestNodeCPUInfo(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	nodes, err := data.clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	for _, node := range nodes.Items {
		nodeCPUInfo, err := getNodeCPUInfo(data, node)
		assert.NoError(t, err)

		code, stdout, stderr, err := data.RunCommandOnNode(node.Name, "lscpu")
		assert.NoError(t, err)
		assert.Equal(t, "", stderr)
		assert.Equal(t, 0, code)

		cpuInfoMap := parseCPUInfo(stdout)
		nodesNum, err := strconv.Atoi(cpuInfoMap["NUMA node(s)"])
		assert.NoError(t, err)
		cpuNum, err := strconv.Atoi(cpuInfoMap["CPU(s)"])
		assert.NoError(t, err)
		assert.Equal(t, nodeCPUInfo.Nodes, nodesNum)
		assert.Equal(t, nodeCPUInfo.CPUs, cpuNum)
		assert.NoError(t, err)
		socketNum, err := strconv.Atoi(cpuInfoMap["Socket(s)"])
		assert.NoError(t, err)
		// As in a VM, Thread(s) per core:, Core(s) per socket:, Socket(s):, NUMA: is not reliable. They cannot report the physical host status.
		// So comment out these assert lines.
		// coresPerSocket, err := strconv.Atoi(cpuInfoMap["Core(s) per socket"])
		// assert.Equal(t, nodeCPUInfo.Cores, coresPerSocket*socketNum)
		assert.Equal(t, nodeCPUInfo.Sockets, socketNum)
	}
}

func parseCPUInfo(output string) map[string]string {
	cpuInfo := make(map[string]string)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			cpuInfo[key] = value
		}
	}
	return cpuInfo
}
