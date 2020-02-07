package cniserver

import (
	"fmt"
	"net"
	"time"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/j-keck/arping"
	"github.com/vishvananda/netlink"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/ethtool"
	cnipb "github.com/vmware-tanzu/antrea/pkg/apis/cni/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

type podConfigurator struct {
	ovsBridgeClient ovsconfig.OVSBridgeClient
	ofClient        openflow.Client
	ifaceStore      interfacestore.InterfaceStore
	gatewayMAC      net.HardwareAddr
	ovsDatapathType string
}

func newPodConfigurator(
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	ofClient openflow.Client,
	ifaceStore interfacestore.InterfaceStore,
	gatewayMAC net.HardwareAddr,
	ovsDatapathType string,
) *podConfigurator {
	return &podConfigurator{ovsBridgeClient, ofClient, ifaceStore, gatewayMAC, ovsDatapathType}
}

// setupInterfaces creates a veth pair: containerIface is in the container
// network namespace and hostIface is in the host network namespace.
func (pc *podConfigurator) setupInterfaces(
	podName, podNamespace, ifname string,
	netns ns.NetNS,
	mtu int) (hostIface *current.Interface, containerIface *current.Interface, err error) {
	hostVethName := util.GenerateContainerInterfaceName(podName, podNamespace)
	hostIface = &current.Interface{}
	containerIface = &current.Interface{}

	if err := netns.Do(func(hostNS ns.NetNS) error {
		hostVeth, containerVeth, err := ip.SetupVethWithName(ifname, hostVethName, mtu, hostNS)
		if err != nil {
			return err
		}
		klog.V(2).Infof("Setup interfaces host: %s, container %s", hostVeth.Name, containerVeth.Name)
		containerIface.Name = containerVeth.Name
		containerIface.Mac = containerVeth.HardwareAddr.String()
		containerIface.Sandbox = netns.Path()
		hostIface.Name = hostVeth.Name
		hostIface.Mac = hostVeth.HardwareAddr.String()
		// OVS netdev datapath doesn't support TX checksum offloading, i.e. if packet
		// arrives with bad/no checksum it will be sent to the output port with same bad/no checksum.
		if pc.ovsDatapathType == ovsconfig.OVSDatapathNetdev {
			if err := ethtool.EthtoolTXHWCsumOff(containerVeth.Name); err != nil {
				return fmt.Errorf("error when disabling TX checksum offload on container veth: %v", err)
			}
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}

	return hostIface, containerIface, nil
}

// configureContainerAddr takes the result of the IPAM plugin, and adds the appropriate IP
// addresses and routes to the interface. It then sends a gratuitous ARP to the network.
func configureContainerAddr(netns ns.NetNS, containerInterface *current.Interface, result *current.Result) error {
	if err := netns.Do(func(containerNs ns.NetNS) error {
		if err := ipam.ConfigureIface(containerInterface.Name, result); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// advertiseContainerAddr sends 3 GARP packets in another goroutine with 50ms interval. It's because Openflow entries are
// installed async, and the gratuitous ARP could be sent out after the Openflow entries are installed. Using another
// goroutine to ensure the processing of CNI ADD request is not blocked.
func (pc *podConfigurator) advertiseContainerAddr(containerNetNS string, containerIfaceName string, result *current.Result) error {
	netns, err := ns.GetNS(containerNetNS)
	if err != nil {
		klog.Errorf("Failed to open netns with %s: %v", containerNetNS, err)
		return err
	}
	defer netns.Close()
	if err := netns.Do(func(containerNs ns.NetNS) error {
		go func() {
			// The container veth must exist when this function is called, and do not check error here.
			containerVeth, err := net.InterfaceByName(containerIfaceName)
			if err != nil {
				klog.Errorf("Failed to find container interface %s in ns %s", containerIfaceName, netns.Path())
				return
			}
			var targetIP net.IP
			for _, ipc := range result.IPs {
				if ipc.Version == "4" {
					targetIP = ipc.Address.IP
					arping.GratuitousArpOverIface(ipc.Address.IP, *containerVeth)
				}
			}
			if targetIP == nil {
				klog.Warning("Failed to find a valid IP address for Gratuitous ARP, not send GARP")
				return
			}
			count := 0
			for count < 3 {
				select {
				case <-time.Tick(50 * time.Millisecond):
					// Send gratuitous ARP to network in case of stale mappings for this IP address
					// (e.g. if a previous - deleted - Pod was using the same IP).
					arping.GratuitousArpOverIface(targetIP, *containerVeth)
				}
				count += 1
			}
		}()
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func (pc *podConfigurator) configureContainerLink(
	podName string,
	podNameSpace string,
	containerID string,
	containerNetNS string,
	containerIFDev string,
	mtu int,
	result *current.Result,
) error {
	netns, err := ns.GetNS(containerNetNS)
	if err != nil {
		return fmt.Errorf("failed to open netns %s: %v", containerNetNS, err)
	}
	defer netns.Close()
	// Create veth pair and link up
	hostIface, containerIface, err := pc.setupInterfaces(podName, podNameSpace, containerIFDev, netns, mtu)
	if err != nil {
		return fmt.Errorf("failed to create veth devices for container %s: %v", containerID, err)
	}

	result.Interfaces = []*current.Interface{hostIface, containerIface}

	// Note that configuring IP will send gratuitous ARP, it must be executed
	// after Pod Openflow entries are installed, otherwise gratuitous ARP would
	// be dropped.
	klog.V(2).Infof("Configuring IP address for container %s", containerID)
	if err = configureContainerAddr(netns, containerIface, result); err != nil {
		return fmt.Errorf("failed to configure IP address for container %s: %v", containerID, err)
	}
	return nil
}

func (pc *podConfigurator) removeContainerLink(containerID, hostInterfaceName string) error {
	klog.V(2).Infof("Deleting veth devices for container %s", containerID)
	// Don't return an error if the device is already removed as CniDel can be called multiple times.
	if err := ip.DelLinkByName(hostInterfaceName); err != nil {
		if err != ip.ErrLinkNotFound {
			return fmt.Errorf("failed to delete veth devices for container %s: %v", containerID, err)
		}
		klog.V(2).Infof("Did not find interface %s for container %s", hostInterfaceName, containerID)
	}
	return nil
}

func parseContainerIfaceFromResults(cfgArgs *cnipb.CniCmdArgs, prevResult *current.Result) *current.Interface {
	for _, intf := range prevResult.Interfaces {
		if intf.Name == cfgArgs.Ifname {
			return intf
		}
	}
	return nil
}

func (pc *podConfigurator) checkContainerInterface(
	containerNetns, containerID string,
	netns ns.NetNS,
	containerIface *current.Interface,
	containerIPs []*current.IPConfig,
	containerRoutes []*cnitypes.Route) (*vethPair, error) {
	var contVeth *vethPair
	// Check netns configuration
	if containerNetns != containerIface.Sandbox {
		klog.Errorf("Sandbox in prevResult %s doesn't match configured netns: %s",
			containerIface.Sandbox, containerNetns)
		return nil, fmt.Errorf("sandbox in prevResult %s doesn't match configured netns: %s",
			containerIface.Sandbox, containerNetns)
	}
	// Check container interface configuration
	if err := netns.Do(func(netNS ns.NetNS) error {
		var errlink error
		// Check container link config
		contVeth, errlink = validateContainerInterface(containerIface)
		if errlink != nil {
			return errlink
		}
		// Check container IP config
		if err := ip.ValidateExpectedInterfaceIPs(containerIface.Name, containerIPs); err != nil {
			return err
		}
		// Check container route config
		if err := ip.ValidateExpectedRoute(containerRoutes); err != nil {
			return err
		}
		return nil
	}); err != nil {
		klog.Errorf("Failed to check container %s interface configurations in netns %s: %v",
			containerID, containerNetns, err)
		return nil, err
	}
	return contVeth, nil
}

func validateContainerInterface(intf *current.Interface) (*vethPair, error) {
	link, err := validateInterface(intf, true)
	if err != nil {
		return nil, err
	}

	linkName := link.Attrs().Name
	veth := &vethPair{}
	_, veth.peerIndex, err = ip.GetVethPeerIfindex(linkName)
	if err != nil {
		return nil, fmt.Errorf("failed to get veth peer index for veth %s: %v", linkName, err)
	}
	veth.ifIndex = link.Attrs().Index
	if intf.Mac != link.Attrs().HardwareAddr.String() {
		return nil, fmt.Errorf("interface %s MAC %s doesn't match container MAC: %s",
			intf.Name, intf.Mac, link.Attrs().HardwareAddr.String())
	}
	veth.name = linkName
	return veth, nil
}

func validateContainerPeerInterface(interfaces []*current.Interface, containerVeth *vethPair) (*vethPair, error) {
	// Interate all the passed interfaces and look up the host interface by
	// matching the veth peer interface index.
	for _, hostIntf := range interfaces {
		if hostIntf.Sandbox != "" {
			// Not in the default Namespace. Must be the container interface.
			continue
		}
		link, err := validateInterface(hostIntf, false)
		if err != nil {
			klog.Errorf("Failed to validate interface %s: %v",
				hostIntf.Name, err)
			continue
		}

		if link.Attrs().Index != containerVeth.peerIndex {
			continue
		}

		hostVeth := &vethPair{ifIndex: link.Attrs().Index, name: link.Attrs().Name}
		_, hostVeth.peerIndex, err = ip.GetVethPeerIfindex(hostVeth.name)
		if err != nil {
			return nil, fmt.Errorf("failed to get veth peer index for host interface %s: %v",
				hostIntf.Name, err)
		}

		if hostVeth.peerIndex != containerVeth.ifIndex {
			return nil, fmt.Errorf("host interface %s peer index doesn't match container interface %s index",
				hostIntf.Name, containerVeth.name)
		}

		if hostIntf.Mac != "" {
			if hostIntf.Mac != link.Attrs().HardwareAddr.String() {
				klog.Errorf("Host interface %s MAC %s doesn't match link address %s",
					hostIntf.Name, hostIntf.Mac, link.Attrs().HardwareAddr.String())
				return nil, fmt.Errorf("host interface %s MAC %s doesn't match",
					hostIntf.Name, hostIntf.Mac)
			}
		}
		return hostVeth, nil

	}

	return nil, fmt.Errorf("peer veth interface not found for container interface %s",
		containerVeth.name)
}

func validateInterface(intf *current.Interface, inNetns bool) (netlink.Link, error) {
	if intf.Name == "" {
		return nil, fmt.Errorf("interface name is missing")
	}
	if inNetns {
		if intf.Sandbox == "" {
			return nil, fmt.Errorf("interface %s is expected in netns", intf.Name)
		}
	} else {
		if intf.Sandbox != "" {
			return nil, fmt.Errorf("interface %s is expected not in netns", intf.Name)
		}
	}

	link, err := netlink.LinkByName(intf.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to find link for interface %s", intf.Name)
	}

	_, isVeth := link.(*netlink.Veth)
	if !isVeth {
		return nil, fmt.Errorf("interface %s is not of type veth", intf.Name)
	}
	return link, nil
}

func (pc *podConfigurator) setupContainerOVSPort(
	containerConfig *interfacestore.InterfaceConfig,
	ovsPortName string) (string, error) {
	ovsAttchInfo := BuildOVSPortExternalIDs(containerConfig)
	if portUUID, err := pc.ovsBridgeClient.CreatePort(ovsPortName, ovsPortName, ovsAttchInfo); err != nil {
		klog.Errorf("Failed to add OVS port %s, remove from local cache: %v", ovsPortName, err)
		return "", err
	} else {
		return portUUID, nil
	}
}
