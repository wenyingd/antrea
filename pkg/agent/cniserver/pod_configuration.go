// Copyright 2019 Antrea Authors
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
	"encoding/json"
	"fmt"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog"
	"net"
)

type vethPair struct {
	name      string
	ifIndex   int
	peerIndex int
}

type k8sArgs struct {
	cnitypes.CommonArgs
	K8S_POD_NAME               cnitypes.UnmarshallableString
	K8S_POD_NAMESPACE          cnitypes.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID cnitypes.UnmarshallableString
}

const (
	ovsExternalIDMAC          = "attached-mac"
	ovsExternalIDIP           = "ip-address"
	ovsExternalIDContainerID  = "container-id"
	ovsExternalIDPodName      = "pod-name"
	ovsExternalIDPodNamespace = "pod-namespace"
)

func parseContainerIP(ips []*current.IPConfig) (net.IP, error) {
	for _, ipc := range ips {
		if ipc.Version == "4" {
			return ipc.Address.IP, nil
		}
	}
	return nil, fmt.Errorf("failed to find a valid IP address")
}

func buildContainerConfig(
	interfaceName, containerID, podName, podNamespace string,
	containerIface *current.Interface,
	ips []*current.IPConfig) *interfacestore.InterfaceConfig {
	containerIP, err := parseContainerIP(ips)
	if err != nil {
		klog.Errorf("Failed to find container %s IP", containerID)
	}
	// containerIface.Mac should be a valid MAC string, otherwise it should throw error before
	containerMAC, _ := net.ParseMAC(containerIface.Mac)
	return interfacestore.NewContainerInterface(
		interfaceName,
		containerID,
		podName,
		podNamespace,
		containerMAC,
		containerIP)
}

// BuildOVSPortExternalIDs parses OVS port external_ids from InterfaceConfig.
// external_ids are used to compare and sync container interface configuration.
func BuildOVSPortExternalIDs(containerConfig *interfacestore.InterfaceConfig) map[string]interface{} {
	externalIDs := make(map[string]interface{})
	externalIDs[ovsExternalIDMAC] = containerConfig.MAC.String()
	externalIDs[ovsExternalIDContainerID] = containerConfig.ContainerID
	externalIDs[ovsExternalIDIP] = containerConfig.IP.String()
	externalIDs[ovsExternalIDPodName] = containerConfig.PodName
	externalIDs[ovsExternalIDPodNamespace] = containerConfig.PodNamespace
	return externalIDs
}

// ParseOVSPortInterfaceConfig reads the Pod properties saved in the OVS port
// external_ids, initializes and returns an InterfaceConfig struct.
// nill will be returned, if the OVS port does not have external IDs or it is
// not created for a Pod interface.
func ParseOVSPortInterfaceConfig(portData *ovsconfig.OVSPortData, portConfig *interfacestore.OVSPortConfig) *interfacestore.InterfaceConfig {
	if portData.ExternalIDs == nil {
		klog.V(2).Infof("OVS port %s has no external_ids", portData.Name)
		return nil
	}

	containerID, found := portData.ExternalIDs[ovsExternalIDContainerID]
	if !found {
		klog.V(2).Infof("OVS port %s has no %s in external_ids", portData.Name, ovsExternalIDContainerID)
		return nil
	}
	containerIP := net.ParseIP(portData.ExternalIDs[ovsExternalIDIP])
	containerMAC, err := net.ParseMAC(portData.ExternalIDs[ovsExternalIDMAC])
	if err != nil {
		klog.Errorf("Failed to parse MAC address from OVS external config %s: %v",
			portData.ExternalIDs[ovsExternalIDMAC], err)
	}
	podName, _ := portData.ExternalIDs[ovsExternalIDPodName]
	podNamespace, _ := portData.ExternalIDs[ovsExternalIDPodNamespace]

	interfaceConfig := interfacestore.NewContainerInterface(
		portData.Name,
		containerID,
		podName,
		podNamespace,
		containerMAC,
		containerIP)
	interfaceConfig.OVSPortConfig = portConfig
	return interfaceConfig
}

func (pc *podConfigurator) configureInterfaces(
	podName string,
	podNameSpace string,
	containerID string,
	containerNetNS string,
	containerIFDev string,
	mtu int,
	result *current.Result,
) error {
	err := pc.configureContainerLink(podName, podNameSpace, containerID, containerNetNS, containerIFDev, mtu, result)
	if err != nil {
		return err
	}
	hostIface := result.Interfaces[0]
	containerIface := result.Interfaces[1]

	// Delete veth pair if any failure occurs in later manipulation.
	success := false
	defer func() {
		if !success {
			pc.removeContainerLink(containerID, hostIface.Name)
		}
	}()

	// Check if the OVS configurations for the container is existed or not. If yes, return immediately. This check is
	// used on Windows, for Kubelet on Windows will call CNI Add for both the infrastructure container and the workload
	// container. But there should be only one OVS port created for the same Pod. And if the OVS port is added more than
	// once, OVS will return an error.
	_, found := pc.ifaceStore.GetContainerInterface(podName, podNameSpace)
	if found {
		klog.V(2).Infof("Found an existed OVS port with podName %s podNamespace %s, returning", podName, podNameSpace)
		// Mark the operation as successful, otherwise the container link might be removed by mistake.
		success = true
		return nil
	}

	// Use the outer veth interface name as the OVS port name.
	ovsPortName := hostIface.Name
	containerConfig := buildContainerConfig(ovsPortName, containerID, podName, podNameSpace, containerIface, result.IPs)

	// create OVS Port and add attach container configuration into external_ids
	klog.V(2).Infof("Adding OVS port %s for container %s", ovsPortName, containerID)
	portUUID, err := pc.setupContainerOVSPort(containerConfig, ovsPortName)
	if err != nil {
		return fmt.Errorf("failed to add OVS port for container %s: %v", containerID, err)
	}
	// Remove OVS port if any failure occurs in later manipulation.
	defer func() {
		if !success {
			pc.ovsBridgeClient.DeletePort(portUUID)
		}
	}()

	// GetOFPort will wait for up to 1 second for OVSDB to report the OFPort number.
	ofPort, err := pc.ovsBridgeClient.GetOFPort(ovsPortName)
	if err != nil {
		return fmt.Errorf("failed to get of_port of OVS port %s: %v", ovsPortName, err)
	}

	klog.V(2).Infof("Setting up Openflow entries for container %s", containerID)
	err = pc.ofClient.InstallPodFlows(ovsPortName, containerConfig.IP, containerConfig.MAC, pc.gatewayMAC, uint32(ofPort))
	if err != nil {
		return fmt.Errorf("failed to add Openflow entries for container %s: %v", containerID, err)
	}
	defer func() {
		if !success {
			pc.ofClient.UninstallPodFlows(ovsPortName)
		}
	}()

	containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: ofPort}
	// Add containerConfig into local cache
	pc.ifaceStore.AddInterface(containerConfig)

	// Note that the gratuitous ARP must be executed after Pod Openflow entries are installed, otherwise gratuitous
	// ARP would be dropped.
	if err = pc.advertiseContainerAddr(containerNetNS, containerIface.Name, result); err != nil {
		klog.Errorf("Failed to send gratuitous ARP for container %s: %v", containerID, err)
	}
	// Mark the manipulation as success to cancel deferred operations.
	success = true
	klog.Infof("Configured interfaces for container %s", containerID)
	return nil
}

func (pc *podConfigurator) removeInterfaces(podName, podNamespace, containerID string) error {
	containerConfig, found := pc.ifaceStore.GetContainerInterface(podName, podNamespace)
	if !found {
		klog.V(2).Infof("Did not find the port for container %s in local cache", containerID)
		return nil
	}

	if err := pc.removeContainerLink(containerID, containerConfig.InterfaceName); err != nil {
		return err
	}

	klog.V(2).Infof("Deleting Openflow entries for container %s", containerID)
	if err := pc.ofClient.UninstallPodFlows(containerConfig.InterfaceName); err != nil {
		return fmt.Errorf("failed to delete Openflow entries for container %s: %v", containerID, err)
	}

	klog.V(2).Infof("Deleting OVS port %s for container %s", containerConfig.PortUUID, containerID)
	// TODO: handle error and introduce garbage collection for failure on deletion
	if err := pc.ovsBridgeClient.DeletePort(containerConfig.PortUUID); err != nil {
		return fmt.Errorf("failed to delete OVS port for container %s: %v", containerID, err)
	}
	// Remove container configuration from cache.
	pc.ifaceStore.DeleteInterface(containerConfig)
	klog.Infof("Removed interfaces for container %s", containerID)
	return nil
}

func (pc *podConfigurator) checkInterfaces(
	containerID, containerNetNS, podName, podNamespace string,
	containerIface *current.Interface,
	prevResult *current.Result) error {
	netns, err := ns.GetNS(containerNetNS)
	if err != nil {
		klog.Errorf("Failed to check netns config %s: %v", containerNetNS, err)
		return err
	}
	defer netns.Close()

	if containerVeth, err := pc.checkContainerInterface(
		containerNetNS,
		containerID,
		netns,
		containerIface,
		prevResult.IPs,
		prevResult.Routes); err != nil {
		return err
	} else if err := pc.checkHostInterface(
		containerID,
		podName,
		podNamespace,
		containerIface,
		containerVeth,
		prevResult.IPs,
		prevResult.Interfaces); err != nil {
		return err
	}
	return nil
}

func (pc *podConfigurator) checkHostInterface(
	containerID, podName, podNamespace string,
	containerIntf *current.Interface,
	containerVeth *vethPair,
	containerIPs []*current.IPConfig,
	interfaces []*current.Interface) error {
	hostVeth, errlink := validateContainerPeerInterface(interfaces, containerVeth)
	if errlink != nil {
		klog.Errorf("Failed to check container %s interface on the host: %v",
			containerID, errlink)
		return errlink
	}
	if err := pc.validateOVSInterfaceConfig(containerID,
		podName,
		podNamespace,
		containerIntf.Mac,
		containerIPs); err != nil {
		klog.Errorf("Failed to check host link %s for container %s attaching status on ovs. err: %v",
			hostVeth.name, containerID, err)
		return err
	}
	return nil
}

func (pc *podConfigurator) validateOVSInterfaceConfig(
	containerID, podName, podNamespace string,
	containerMAC string,
	ips []*current.IPConfig) error {
	if containerConfig, found := pc.ifaceStore.GetContainerInterface(podName, podNamespace); found {
		if containerConfig.MAC.String() != containerMAC {
			return fmt.Errorf("interface MAC %s does not match container %s MAC",
				containerConfig.MAC.String(), containerID)
		}

		for _, ipc := range ips {
			if ipc.Version == "4" {
				if containerConfig.IP.Equal(ipc.Address.IP) {
					return nil
				}
			}
		}
		return fmt.Errorf("interface IP %s does not match container %s IP",
			containerConfig.IP.String(), containerID)
	} else {
		return fmt.Errorf("container %s interface not found from local cache", containerID)
	}
}

func parsePrevResult(conf *NetworkConfig) error {
	if conf.RawPrevResult == nil {
		return nil
	}

	resultBytes, err := json.Marshal(conf.RawPrevResult)
	if err != nil {
		return fmt.Errorf("could not serialize prevResult: %v", err)
	}
	conf.RawPrevResult = nil
	conf.PrevResult, err = version.NewResult(conf.CNIVersion, resultBytes)
	if err != nil {
		return fmt.Errorf("could not parse prevResult: %v", err)
	}
	return nil
}

func (pc *podConfigurator) reconcile(pods []corev1.Pod) error {
	// desiredInterfaces is the exact set of interfaces that should be present, based on the
	// current list of Pods.
	desiredInterfaces := make(map[string]bool)
	// knownInterfaces is the list of interfaces currently in the local cache.
	knownInterfaces := pc.ifaceStore.GetInterfaceKeysByType(interfacestore.ContainerInterface)

	for _, pod := range pods {
		// Skip Pods for which we are not in charge of the networking.
		if pod.Spec.HostNetwork {
			continue
		}

		// We rely on the interface cache / store - which is initialized from the persistent
		// OVSDB - to map the Pod to its interface configuration. The interface
		// configuration includes the parameters we need to replay the flows.
		containerConfig, found := pc.ifaceStore.GetContainerInterface(pod.Name, pod.Namespace)
		if !found {
			// This should not happen since OVSDB is persisted on the Node.
			// TODO: is there anything else we should be doing? Assuming that the Pod's
			// interface still exists, we can repair the interface store since we can
			// retrieve the name of the host interface for the Pod by calling
			// GenerateContainerInterfaceName. One thing we would not be able to
			// retrieve is the container ID which is part of the container configuration
			// we store in the cache, but this ID is not used for anything at the
			// moment. However, if the interface does not exist, there is nothing we can
			// do since we do not have the original CNI parameters.
			klog.Warningf("Interface for Pod %s/%s not found in the interface store", pod.Namespace, pod.Name)
			continue
		}
		klog.V(4).Infof("Syncing interface %s for Pod %s/%s", containerConfig.InterfaceName, pod.Namespace, pod.Name)
		if err := pc.ofClient.InstallPodFlows(
			containerConfig.InterfaceName,
			containerConfig.IP,
			containerConfig.MAC,
			pc.gatewayMAC,
			uint32(containerConfig.OFPort),
		); err != nil {
			klog.Errorf("Error when re-installing flows for Pod %s/%s", pod.Namespace, pod.Name)
			continue
		}
		desiredInterfaces[util.GenerateContainerInterfaceKey(pod.Name, pod.Namespace)] = true
	}

	for _, ifaceID := range knownInterfaces {
		if _, found := desiredInterfaces[ifaceID]; found {
			// this interface matches an existing Pod.
			continue
		}
		// clean-up and delete interface
		containerConfig, found := pc.ifaceStore.GetInterface(ifaceID)
		if !found {
			// should not happen, nothing should have concurrent access to the interface
			// store.
			klog.Errorf("Interface %s can no longer be found in the interface store", ifaceID)
			continue
		}
		klog.V(4).Infof("Deleting interface %s", ifaceID)
		if err := pc.removeInterfaces(
			containerConfig.PodName,
			containerConfig.PodNamespace,
			containerConfig.ContainerID,
		); err != nil {
			klog.Errorf("Failed to delete interface %s: %v", ifaceID, err)
		}
		// interface should no longer be in store after the call to removeInterfaces
	}
	return nil
}
