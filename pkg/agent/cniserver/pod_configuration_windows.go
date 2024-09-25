//go:build windows
// +build windows

// Copyright 2021 Antrea Authors
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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"antrea.io/libOpenflow/openflow15"
	current "github.com/containernetworking/cni/pkg/types/100"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/cniserver/ipam"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	podNotReadyTimeInSeconds = 30
)

// connectInterfaceToOVSAsync waits for an interface to be created and connects it to OVS br-int asynchronously
// in another goroutine. The function is for containerd runtime. The host interface is created after
// CNI call completes.
func (pc *podConfigurator) connectInterfaceToOVSAsync(ifConfig *interfacestore.InterfaceConfig, containerAccess *containerAccessArbitrator) error {
	ovsPortName := ifConfig.InterfaceName
	// Add the OVS port into unReadyPorts. This operation is performed before we update OVSDB, otherwise we
	// need to think about the race condition between the current goroutine with the listener.
	// Note, we may add OVS port into "unReadyOVSPorts" map even if the update OVSDB operation is failed,
	// because it is also a case that the Pod's networking is not ready.
	pc.podIfMonitor.addUnReadyPodInterface(ifConfig)
	return pc.ifConfigurator.addPostInterfaceCreateHook(ifConfig.ContainerID, ovsPortName, containerAccess, func() error {
		if err := pc.ovsBridgeClient.SetInterfaceType(ovsPortName, "internal"); err != nil {
			return err
		}
		return nil
	})
}

// connectInterfaceToOVS connects an existing interface to the OVS bridge.
func (pc *podConfigurator) connectInterfaceToOVS(
	podName, podNamespace, containerID, netNS string,
	hostIface, containerIface *current.Interface,
	ips []*current.IPConfig,
	vlanID uint16,
	containerAccess *containerAccessArbitrator) (*interfacestore.InterfaceConfig, error) {
	// Use the outer veth interface name as the OVS port name.
	ovsPortName := hostIface.Name
	containerConfig := buildContainerConfig(ovsPortName, containerID, podName, podNamespace, containerIface, ips, vlanID)
	// The container interface is created after the CNI returns the network setup result.
	// Because of this, we need to wait asynchronously for the interface to be created: we create the OVS port
	// and set the OVS Interface type "" first, and change the OVS Interface type to "internal" to connect to the
	// container interface after it is created. After OVS connects to the container interface, an OFPort is allocated.
	klog.V(2).Infof("Adding OVS port %s for container %s", ovsPortName, containerID)
	ovsAttachInfo := BuildOVSPortExternalIDs(containerConfig)
	portUUID, err := pc.createOVSPort(ovsPortName, ovsAttachInfo, containerConfig.VLANID)
	if err != nil {
		return nil, err
	}
	containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID}
	// Add containerConfig into local cache
	pc.ifaceStore.AddInterface(containerConfig)
	return containerConfig, pc.connectInterfaceToOVSAsync(containerConfig, containerAccess)
}

func (pc *podConfigurator) configureInterfaces(
	podName, podNamespace, containerID, containerNetNS string,
	containerIFDev string, mtu int, sriovVFDeviceID string,
	result *ipam.IPAMResult, createOVSPort bool, containerAccess *containerAccessArbitrator) error {
	if !createOVSPort {
		return pc.ifConfigurator.configureContainerLink(
			podName, podNamespace, containerID, containerNetNS,
			containerIFDev, mtu, sriovVFDeviceID, "",
			&result.Result, containerAccess)
	}
	// Check if the OVS configurations for the container exists or not. If yes, return
	// immediately. This check is used on Windows, as kubelet on Windows will call CNI ADD
	// multiple times for the infrastructure container to query IP of the Pod. But there should
	// be only one OVS port created for the same Pod (identified by its sandbox container ID),
	// and if the OVS port is added more than once, OVS will return an error.
	// See: https://github.com/kubernetes/kubernetes/issues/57253#issuecomment-358897721.
	interfaceConfig, found := pc.ifaceStore.GetContainerInterface(containerID)
	if found {
		klog.V(2).Infof("Found an existing OVS port for container %s, returning", containerID)
		mac := interfaceConfig.MAC.String()
		hostIface := &current.Interface{
			Name:    interfaceConfig.InterfaceName,
			Mac:     mac,
			Sandbox: "",
		}
		containerIface := &current.Interface{
			Name:    containerIFDev,
			Mac:     mac,
			Sandbox: containerNetNS,
		}
		result.Interfaces = []*current.Interface{hostIface, containerIface}
		return nil
	}

	return pc.configureInterfacesCommon(podName, podNamespace, containerID, containerNetNS,
		containerIFDev, mtu, sriovVFDeviceID, result, containerAccess)
}

func (pc *podConfigurator) reconcileMissingPods(ifConfigs []*interfacestore.InterfaceConfig, containerAccess *containerAccessArbitrator) {
	for i := range ifConfigs {
		ifaceConfig := ifConfigs[i]
		pod := k8s.NamespacedName(ifaceConfig.PodNamespace, ifaceConfig.PodName)
		if err := pc.connectInterfaceToOVSAsync(ifaceConfig, containerAccess); err != nil {
			klog.Errorf("Failed to reconcile Pod %s: %v", pod, err)
		}
	}
}

type unReadyPodInfo struct {
	podName      string
	podNamespace string
	annotated    bool
	createTime   time.Time
}

type podIfaceMonitor struct {
	kubeClient        clientset.Interface
	ifaceStore        interfacestore.InterfaceStore
	ofClient          openflow.Client
	podUpdateNotifier channel.Notifier

	// unReadyInterfaces is a map to store the OVS ports which is waiting for the PortStatus from OpenFlow switch.
	// The key in the map is the OVS port name, and its value is unReadyPodInfo.
	// It is used only on Windows now.
	unReadyInterfaces sync.Map
	statusCh          chan *openflow15.PortStatus
}

func newPodInterfaceMonitor(kubeClient clientset.Interface,
	ofClient openflow.Client,
	ifaceStore interfacestore.InterfaceStore,
	podUpdateNotifier channel.Notifier,
) *podIfaceMonitor {
	statusCh := make(chan *openflow15.PortStatus)
	ofClient.SubscribeOFPortStatusMessage(statusCh)
	return &podIfaceMonitor{
		kubeClient:        kubeClient,
		ofClient:          ofClient,
		ifaceStore:        ifaceStore,
		podUpdateNotifier: podUpdateNotifier,
		unReadyInterfaces: sync.Map{},
		statusCh:          statusCh,
	}
}

func (m *podIfaceMonitor) monitorUnReadyInterface(stopCh <-chan struct{}) {
	klog.Info("Started the monitor to wait for new OpenFlow ports")
	go func() {
		for {
			select {
			case <-stopCh:
				return
			case status := <-m.statusCh:
				klog.V(2).InfoS("Received PortStatus message", "message", status)
				// Update Pod OpenFlow entries only after the OpenFlow port state is live.
				if status.Desc.State == openflow15.PS_LIVE {
					m.updateUnReadyPod(status)
				}
			case <-time.Tick(time.Second * 5):
				m.checkUnReadyPods()
			}
		}
	}()
}

func (m *podIfaceMonitor) updatePodFlows(ifName string, ofPort int32) error {
	ifConfig, found := m.ifaceStore.GetInterfaceByName(ifName)
	if !found {
		klog.Info("Interface config is not found", "name", ifName)
		return nil
	}
	containerID := ifConfig.ContainerID

	// Update interface config with the ofPort.
	ifConfig.OVSPortConfig.OFPort = ofPort
	m.ifaceStore.UpdateInterface(ifConfig)

	// Install OpenFlow entries for the Pod.
	klog.V(2).Infof("Setting up Openflow entries for container %s", containerID)
	if err := m.ofClient.InstallPodFlows(ifName, ifConfig.IPs, ifConfig.MAC, uint32(ofPort), ifConfig.VLANID, nil); err != nil {
		return fmt.Errorf("failed to add Openflow entries for container %s: %v", containerID, err)
	}

	// Notify the Pod update event to required components.
	event := types.PodUpdate{
		PodName:      ifConfig.PodName,
		PodNamespace: ifConfig.PodNamespace,
		IsAdd:        true,
		ContainerID:  ifConfig.ContainerID,
	}
	m.podUpdateNotifier.Notify(event)

	// Remove the annotation from Pod if exists.
	m.updatePodUnreadyAnnotation(ifConfig.PodNamespace, ifConfig.PodName, false)
	return nil
}

func (m *podIfaceMonitor) updatePodUnreadyAnnotation(podNamespace, podName string, addAnnotation bool) {
	pod, err := m.kubeClient.CoreV1().Pods(podNamespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		klog.ErrorS(err, "Failed to get Pod when trying to update 'unready' annotations", "Namespace", podNamespace, "Name", podName)
		return
	}

	annotated := false
	if pod.Annotations != nil {
		_, annotated = pod.Annotations[types.PodNotReadyAnnotationKey]
	}

	if addAnnotation && !annotated {
		// Add the annotation on Pod with '"pod.antrea.io/not-ready": ""'
		patch, _ := json.Marshal(map[string]interface{}{
			"metadata": map[string]interface{}{
				"annotations": map[string]interface{}{types.PodNotReadyAnnotationKey: ""},
			},
		})
		m.kubeClient.CoreV1().Pods(podNamespace).Patch(context.Background(), podName, apitypes.MergePatchType, patch, metav1.PatchOptions{})
	} else if !addAnnotation && annotated {
		// Remove the annotation on Pod with '"pod.antrea.io/not-ready": ""'
		patch, _ := json.Marshal(map[string]interface{}{
			"metadata": map[string]interface{}{
				"annotations": map[string]interface{}{types.PodNotReadyAnnotationKey: nil},
			},
		})
		m.kubeClient.CoreV1().Pods(podNamespace).Patch(context.Background(), podName, apitypes.MergePatchType, patch, metav1.PatchOptions{})
	}
}

func (m *podIfaceMonitor) updateUnReadyPod(status *openflow15.PortStatus) {
	ovsPort := string(bytes.Trim(status.Desc.Name, "\x00"))
	obj, found := m.unReadyInterfaces.Load(ovsPort)
	if !found {
		klog.InfoS("OVS port is not found", "ovsPort", ovsPort)
		return
	}
	podInfo := obj.(*unReadyPodInfo)
	ofPort := status.Desc.PortNo
	if err := m.updatePodFlows(ovsPort, int32(ofPort)); err != nil {
		klog.ErrorS(err, "Failed to update Pod's OpenFlow entries", "PodName", podInfo.podName, "PodNamespace", podInfo.podNamespace, "OVSPort", ovsPort)
		return
	}
	// Delete the Pod from unReadyPods
	m.unReadyInterfaces.Delete(ovsPort)
}

func (m *podIfaceMonitor) checkUnReadyPods() {
	m.unReadyInterfaces.Range(func(key, value any) bool {
		podInfo := value.(*unReadyPodInfo)
		if !podInfo.annotated && time.Now().Sub(podInfo.createTime).Seconds() > podNotReadyTimeInSeconds {
			m.updatePodUnreadyAnnotation(podInfo.podNamespace, podInfo.podName, true)
			podInfo.annotated = true
			m.unReadyInterfaces.Store(key, podInfo)
		}
		return true
	})
}

func (m *podIfaceMonitor) addUnReadyPodInterface(ifConfig *interfacestore.InterfaceConfig) {
	klog.InfoS("Added OVS port into unready interfaces", "ovsPort", ifConfig.InterfaceName,
		"podName", ifConfig.PodName, "podNamespace", ifConfig.PodNamespace)
	m.unReadyInterfaces.Store(ifConfig.InterfaceName, &unReadyPodInfo{
		podName:      ifConfig.PodName,
		podNamespace: ifConfig.PodNamespace,
		annotated:    false,
		createTime:   time.Now(),
	})
}

// getPortStatusCh returns the channel used to receive OpenFlow.PortStatus message.
// This function is added for test.
func (m *podIfaceMonitor) getPortStatusCh() chan *openflow15.PortStatus {
	return m.statusCh
}
