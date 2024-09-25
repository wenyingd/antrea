//go:build windows
// +build windows

// Copyright 2024 Antrea Authors
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

package cniserver

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"antrea.io/libOpenflow/openflow15"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclientset "k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/types"
)

var (
	fakeOFClient *openflowtest.MockClient

	podIPs              = []net.IP{net.ParseIP("192.168.9.10")}
	podMac, _           = net.ParseMAC("00:15:5D:B2:6F:38")
	podIfName           = "test"
	podName             = "iis-7b544f899f-kqdh6"
	podNamespace        = "default"
	podInfraContainerID = "261a1970-5b6c-11ed-8caf-000c294e5d03"
	podIfaceConfig      = &interfacestore.InterfaceConfig{
		InterfaceName: podIfName,
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
			PodNamespace: podNamespace,
			PodName:      podName,
			ContainerID:  podInfraContainerID,
		},
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: "test-port-uuid",
		},
		IPs: podIPs,
		MAC: podMac,
	}
)

func TestUpdateUnReadyPod(t *testing.T) {
	portStatusMsg := &openflow15.PortStatus{
		Reason: openflow15.PR_MODIFY,
		Desc: openflow15.Port{
			PortNo: 1,
			Length: 72,
			Name:   []byte("test"),
			State:  openflow15.PS_LIVE,
		},
	}

	for _, tc := range []struct {
		name               string
		podIfaceUnReady    bool
		podIfaceIsCached   bool
		installOpenFlow    bool
		installOpenFlowErr error
		ifConfigUpdated    bool
	}{
		{
			name:             "updated Port is not in unready state",
			podIfaceUnReady:  false,
			podIfaceIsCached: false,
			installOpenFlow:  false,
		}, {
			name:             "updated Port is not cached",
			podIfaceUnReady:  true,
			podIfaceIsCached: false,
			installOpenFlow:  false,
		}, {
			name:               "failed to install OpenFlow entries for updated Port",
			podIfaceUnReady:    true,
			podIfaceIsCached:   true,
			ifConfigUpdated:    true,
			installOpenFlow:    true,
			installOpenFlowErr: fmt.Errorf("failure to install flow"),
		}, {
			name:               "succeeded",
			podIfaceUnReady:    true,
			podIfaceIsCached:   true,
			ifConfigUpdated:    true,
			installOpenFlow:    true,
			installOpenFlowErr: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: podNamespace,
					Annotations: map[string]string{
						types.PodNotReadyAnnotationKey: "",
					},
				},
			}
			fakeKubeClient := fakeclientset.NewClientset(pod)
			fakeOFClient = openflowtest.NewMockClient(controller)
			fakeOFClient.EXPECT().SubscribeOFPortStatusMessage(gomock.Any()).Times(1)
			fakeIfaceStore := interfacestore.NewInterfaceStore()
			waiter := newAsyncWaiter(podName, podInfraContainerID)
			monitor := newPodInterfaceMonitor(fakeKubeClient, fakeOFClient, fakeIfaceStore, waiter.notifier)
			updated := false
			if tc.podIfaceIsCached {
				fakeIfaceStore.AddInterface(podIfaceConfig)
			}
			if tc.podIfaceUnReady {
				monitor.addUnReadyPodInterface(podIfaceConfig)
			}
			if tc.installOpenFlow {
				fakeOFClient.EXPECT().InstallPodFlows(podIfName, podIPs, podMac, portStatusMsg.Desc.PortNo, uint16(0), nil).Times(1).Return(tc.installOpenFlowErr)
				if tc.installOpenFlowErr == nil {
					updated = true
				}
			}

			monitor.updateUnReadyPod(portStatusMsg)

			if tc.ifConfigUpdated {
				actCfg, found := fakeIfaceStore.GetContainerInterface(podIfaceConfig.ContainerID)
				assert.True(t, found)
				assert.Equal(t, int32(portStatusMsg.Desc.PortNo), actCfg.OVSPortConfig.OFPort)
			}
			if updated {
				waiter.wait()
				annotated, err := checkAnnotation(fakeKubeClient, podNamespace, podName)
				require.NoError(t, err)
				require.False(t, annotated)
				_, found := monitor.unReadyInterfaces.Load(podIfName)
				require.False(t, found)
			}
		})
	}
}

func TestCheckUnReadyPods(t *testing.T) {
	for _, tc := range []struct {
		name        string
		existingPod *corev1.Pod
		podInfo     *unReadyPodInfo
		annotated   bool
	}{
		{
			name: "unready Pod is already annotated",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: podNamespace,
					Annotations: map[string]string{
						types.PodNotReadyAnnotationKey: "",
					},
				},
			},
			podInfo: &unReadyPodInfo{
				podName:      podName,
				podNamespace: podNamespace,
				annotated:    true,
			},
			annotated: true,
		}, {
			name: "unready Pod is not annotated and sync time is not up",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: podNamespace,
				},
			},
			podInfo: &unReadyPodInfo{
				podName:      podName,
				podNamespace: podNamespace,
				annotated:    false,
				createTime:   time.Now(),
			},
			annotated: false,
		}, {
			name: "annotate unready Pod",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: podNamespace,
				},
			},
			podInfo: &unReadyPodInfo{
				podName:      podName,
				podNamespace: podNamespace,
				annotated:    false,
				createTime:   time.Now().Add((-40) * time.Second),
			},
			annotated: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			fakeKubeClient := fakeclientset.NewClientset(tc.existingPod)
			fakeOFClient = openflowtest.NewMockClient(controller)
			fakeOFClient.EXPECT().SubscribeOFPortStatusMessage(gomock.Any()).Times(1)
			fakeIfaceStore := interfacestore.NewInterfaceStore()
			monitor := newPodInterfaceMonitor(fakeKubeClient, fakeOFClient, fakeIfaceStore, nil)
			monitor.unReadyInterfaces.Store(podIfName, tc.podInfo)

			monitor.checkUnReadyPods()

			obj, found := monitor.unReadyInterfaces.Load(podIfName)
			require.True(t, found)
			newPodInfo, _ := obj.(*unReadyPodInfo)
			assert.Equal(t, tc.annotated, newPodInfo.annotated)

			annotated, err := checkAnnotation(fakeKubeClient, tc.existingPod.Namespace, tc.existingPod.Name)
			require.NoError(t, err)
			assert.Equal(t, tc.annotated, annotated)
		})
	}
}

func TestUpdatePodUnreadyAnnotation(t *testing.T) {
	for _, tc := range []struct {
		name          string
		existingPod   *corev1.Pod
		addAnnotation bool
		annotated     bool
	}{
		{
			name: "Pod is already annotated",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: podNamespace,
					Annotations: map[string]string{
						types.PodNotReadyAnnotationKey: "",
					},
				},
			},
			addAnnotation: true,
			annotated:     true,
		}, {
			name: "Pod needs to add annotation",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: podNamespace,
					Annotations: map[string]string{
						"unrelated": "",
					},
				},
			},
			addAnnotation: true,
			annotated:     true,
		}, {
			name: "Pod needs to add annotation, annotations field doesn't exist",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: podNamespace,
					Annotations: map[string]string{
						"unrelated": "",
					},
				},
			},
			addAnnotation: true,
			annotated:     true,
		}, {
			name: "Pod has removed annotation",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: podNamespace,
				},
			},
			addAnnotation: false,
			annotated:     false,
		}, {
			name: "Pod needs to remove annotation",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      podName,
					Namespace: podNamespace,
					Annotations: map[string]string{
						types.PodNotReadyAnnotationKey: "",
					},
				},
			},
			addAnnotation: false,
			annotated:     false,
		},
	} {
		controller := gomock.NewController(t)
		fakeKubeClient := fakeclientset.NewClientset(tc.existingPod)
		fakeOFClient = openflowtest.NewMockClient(controller)
		fakeOFClient.EXPECT().SubscribeOFPortStatusMessage(gomock.Any()).Times(1)
		fakeIfaceStore := interfacestore.NewInterfaceStore()
		monitor := newPodInterfaceMonitor(fakeKubeClient, fakeOFClient, fakeIfaceStore, nil)
		monitor.updatePodUnreadyAnnotation(tc.existingPod.Namespace, tc.existingPod.Name, tc.addAnnotation)

		annotated, err := checkAnnotation(fakeKubeClient, tc.existingPod.Namespace, tc.existingPod.Name)
		require.NoError(t, err)
		assert.Equal(t, tc.annotated, annotated)
	}
}

func checkAnnotation(kubeClient *fakeclientset.Clientset, namespace, name string) (bool, error) {
	updatedPod, err := kubeClient.CoreV1().Pods(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	if len(updatedPod.Annotations) == 0 {
		return false, nil
	}
	_, annotated := updatedPod.Annotations[types.PodNotReadyAnnotationKey]
	return annotated, nil
}
