package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Microsoft/hcsshim"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/util"
	ps "antrea.io/antrea/pkg/agent/util/powershell"
	antreasyscall "antrea.io/antrea/pkg/agent/util/syscall"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/ovs/ovsctl"
)

func prepareHNSNetworkAndOVSExtension(adapterName string, brName string, subnetCIDR *net.IPNet) error {
	// If the HNS Network already exists, return immediately.
	_, err := hcsshim.GetHNSNetworkByName(util.LocalHNSNetwork)
	if err == nil {
		// Enable RSC for existing vSwitch.
		if err = util.EnableRSCOnVSwitch(util.LocalHNSNetwork); err != nil {
			return err
		}
		return nil
	}
	if _, ok := err.(hcsshim.NetworkNotFoundError); !ok {
		return err
	}
	// Get uplink network configuration. The uplink interface is the one used for transporting Pod traffic across Nodes.
	// Use the interface specified with "transportInterface" in the configuration if configured, otherwise the interface
	// configured with NodeIP is used as uplink.
	adapterIP, _, adapter, err := util.GetIPNetDeviceByName(adapterName)
	if err != nil {
		return err
	}
	// To forward container traffic to physical network, Transparent HNSNetwork must have a physical adapter attached,
	// otherwise creating it would fail with "The parameter is incorrect" if the provided adapter is virtual or "An
	// adapter was not found" if no adapter is provided and no physical adapter is available on the host.
	// If the discovered adapter is virtual, it likely means the physical adapter is already attached to another
	// HNSNetwork. For example, docker may create HNSNetworks which attach to the physical adapter.
	isVirtual, err := util.IsVirtualAdapter(adapter.Name)
	if err != nil {
		return err
	}
	if isVirtual {
		klog.Errorf("Transparent HNSNetwork requires a physical adapter while the uplink interface \"%s\" is virtual, please detach it from other HNSNetworks and try again", adapter.Name)
		return fmt.Errorf("uplink \"%s\" is not a physical adapter", adapter.Name)
	}
	defaultGW, err := util.GetDefaultGatewayByInterfaceIndex(adapter.Index)
	if err != nil {
		return err
	}
	if defaultGW == "" {
		klog.InfoS("No default gateway found on interface", "interface", adapter.Name)
	}
	dnsServers, err := util.GetDNServersByInterfaceIndex(adapter.Index)
	if err != nil {
		return err
	}
	// Save routes which are configured on the uplink interface, and configure them on the management virtual adapter
	// if Windows host doesn't move the configuration automatically.
	routes, err := getHostRoutes(adapter.Index, defaultGW)
	if err != nil {
		return err
	}

	klog.InfoS("Creating HNSNetwork", "name", util.LocalHNSNetwork, "subnet", subnetCIDR, "nodeIP", adapterIP, "adapter", adapterName)
	hnsNet, err := util.CreateHNSNetwork(util.LocalHNSNetwork, subnetCIDR, adapterIP, adapter)
	if err != nil {
		return fmt.Errorf("error creating HNSNetwork: %v", err)
	}
	if err := printNetIPInterface("created HNS Network"); err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			hnsNet.Delete()
		}
	}()

	var ipFound bool
	err = wait.PollImmediate(200*time.Millisecond, 1*time.Second, func() (done bool, err error) {
		adapter, ipFound, err = util.AdapterIPExists(adapterIP.IP, adapter.HardwareAddr, util.ContainerVNICPrefix)
		if err != nil {
			return false, err
		}
		return ipFound, nil
	})

	vNicName, index := adapter.Name, adapter.Index
	// By default, "ipFound" should be true after Windows creates the HNSNetwork. The following check is for some corner
	// cases that Windows fails to move the physical adapter's IP address to the virtual network adapter, e.g., DHCP
	// Server fails to allocate IP to new virtual network.
	if !ipFound {
		klog.InfoS("Moving uplink configuration to the management virtual network adapter", "adapter", vNicName)
		if err := util.ConfigureInterfaceAddressWithDefaultGateway(vNicName, adapterIP, defaultGW); err != nil {
			klog.ErrorS(err, "Failed to configure IP and gateway on the management virtual network adapter", "adapter", vNicName, "ip", adapterIP.String())
			return err
		}
		if dnsServers != "" {
			if err := util.SetAdapterDNSServers(vNicName, dnsServers); err != nil {
				klog.ErrorS(err, "Failed to configure DNS servers on the management virtual network adapter", "adapter", vNicName, "dnsServers", dnsServers)
				return err
			}
		}
		for _, route := range routes {
			rt := route.(util.Route)
			newRt := util.Route{
				LinkIndex:         index,
				DestinationSubnet: rt.DestinationSubnet,
				GatewayAddress:    rt.GatewayAddress,
				RouteMetric:       rt.RouteMetric,
			}
			if err := util.NewNetRoute(&newRt); err != nil {
				return err
			}
		}
		klog.InfoS("Moved uplink configuration to the management virtual network adapter", "adapter", vNicName)
	}
	if brName != "" {
		// Rename the vnic created by Windows host with the given newName, then it can be used by OVS when creating bridge port.
		uplinkMACStr := strings.Replace(adapter.HardwareAddr.String(), ":", "", -1)
		// Rename NetAdapter in the meanwhile, then the network adapter can be treated as a host network adapter other than
		// a vm network adapter.
		if err = util.RenameVMNetworkAdapter(util.LocalHNSNetwork, uplinkMACStr, brName, true); err != nil {
			return err
		}
		if err := printNetIPInterface("renamed adapter"); err != nil {
			return err
		}
	}

	// Enable OVS Extension on the HNS Network. If an error occurs, delete the HNS Network and return the error.
	if err = util.EnableHNSNetworkExtension(hnsNet.Id, util.OVSExtensionID); err != nil {
		return err
	}

	if err := printNetIPInterface("enabled OVS Extension"); err != nil {
		return err
	}

	if err = util.EnableRSCOnVSwitch(util.LocalHNSNetwork); err != nil {
		return err
	}

	if err := printNetIPInterface("enabled RSC on VSwitch"); err != nil {
		return err
	}
	success = true
	klog.InfoS("Created HNSNetwork", "name", hnsNet.Name, "id", hnsNet.Id)
	return nil

}

func getHostRoutes(adapterIndex int, gwIP string) ([]interface{}, error) {
	// IPv6 is not supported on Windows currently. Please refer to https://github.com/antrea-io/antrea/issues/5162
	// for more information.
	family := antreasyscall.AF_INET
	filter := &util.Route{
		LinkIndex:      adapterIndex,
		GatewayAddress: net.ParseIP(gwIP),
	}
	var hostRoutes []interface{}
	routes, err := util.RouteListFiltered(family, filter, util.RT_FILTER_IF|util.RT_FILTER_GW)
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		// Skip default route. The default route will be added automatically when
		// configuring IP address on OVS bridge interface.
		if route.DestinationSubnet.IP.IsUnspecified() {
			continue
		}
		klog.Infof("Got host route: %v", route)
		hostRoutes = append(hostRoutes, route)
	}
	return hostRoutes, nil
}

func prepareOVSBridge(ovsBridgeClient ovsconfig.OVSBridgeClient) error {
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(util.LocalHNSNetwork)
	if err != nil {
		return err
	}
	defer func() {
		if err := ovsBridgeClient.Delete(); err != nil {
			klog.Errorf("Failed to delete OVS bridge: %v", err)
		}
		if err := util.DeleteHNSNetwork(util.LocalHNSNetwork); err != nil {
			klog.Errorf("Failed to cleanup host networking: %v", err)
		}
	}()

	// Set datapathID of OVS bridge.
	// If no datapathID configured explicitly, the reconfiguration operation will change OVS bridge datapathID
	// and break the OpenFlow channel.
	datapathID := util.GenerateOVSDatapathID(hnsNetwork.SourceMac)
	if err = ovsBridgeClient.SetDatapathID(datapathID); err != nil {
		klog.ErrorS(err, "Failed to set OVS bridge datapath_id", "datapathID", datapathID)
		return err
	}

	// Create local port.
	brName := ovsBridgeClient.GetBridgeName()
	if _, err = ovsBridgeClient.GetOFPort(brName, false); err == nil {
		klog.Infof("OVS bridge local port %s already exists, skip the configuration", brName)
	} else {
		// OVS does not receive "ofport_request" param when creating local port, so here use config.AutoAssignedOFPort=0
		// to ignore this param.
		externalIDs := map[string]interface{}{
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
		}
		if _, err = ovsBridgeClient.CreateInternalPort(brName, config.AutoAssignedOFPort, "", externalIDs); err != nil {
			return err
		}
		if err := printNetIPInterface("created OVSBridge"); err != nil {
			return err
		}
	}

	// If uplink is already exists, return.
	uplink := hnsNetwork.NetworkAdapterName
	if ofport, err := ovsBridgeClient.GetOFPort(uplink, false); err == nil {
		klog.InfoS("Uplink already exists, skip the configuration", "uplink", uplink, "port", ofport)
		return nil
	}
	// Create uplink port.
	freePort, err := ovsBridgeClient.AllocateOFPort(config.UplinkOFPort)
	if err != nil {
		klog.ErrorS(err, "Failed to find a free port on OVS")
		return err
	}
	_, err = ovsBridgeClient.CreateUplinkPort(uplink, freePort, nil)
	if err != nil {
		klog.Errorf("Failed to add uplink port %s: %v", uplink, err)
		return err
	}
	uplinkOFPort, err := ovsBridgeClient.GetOFPort(uplink, false)
	if err != nil {
		return fmt.Errorf("failed to get uplink ofport %s: err=%w", uplink, err)
	}
	klog.InfoS("Allocated OpenFlow port for uplink interface", "port", uplink, "ofPort", uplinkOFPort)
	ovsCtlClient := ovsctl.NewClient(ovsBridgeClient.GetBridgeName())

	// Enable IP forwarding on the bridge local interface. Traffic from the uplink interface will be output to the bridge
	// local interface directly. When an external client connects to a LoadBalancer type Service, and the packets of the
	// connection are routed to the selected backend Pod via the bridge interface; if we do not enable IP forwarding on
	// the bridge interface, the packet will be discarded on the bridge interface as the destination of the packet
	// is not the Node.
	if err = util.EnableIPForwarding(brName); err != nil {
		return err
	}
	if err := printNetIPInterface("enabled IP Forwarding"); err != nil {
		return err
	}
	// Set the uplink with "no-flood" config, so that the IP of local Pods and "antrea-gw0" will not be leaked to the
	// underlay network by the "normal" flow entry.
	if err = ovsCtlClient.SetPortNoFlood(int(uplinkOFPort)); err != nil {
		klog.Errorf("Failed to set the uplink port with no-flood config: %v", err)
		return err
	}
	return nil
}

func setupOVSBridge(ovsBridgeClient ovsconfig.OVSBridgeClient) error {
	if err := ovsBridgeClient.Create(); err != nil {
		klog.ErrorS(err, "Failed to create OVS bridge")
		return err
	}

	if err := prepareOVSBridge(ovsBridgeClient); err != nil {
		return err
	}

	return nil
}

func printNetIPInterface(prefix string) error {
	klog.Infof("Step '%s': Print network adapter configuration with IPv4.", prefix)
	cmd := fmt.Sprintf(`Get-NetIPInterface -AddressFamily IPv4 | Select-Object -Property IfAlias,Dhcp | Format-Table -HideTableHeaders`)
	out, err := ps.RunCommand(cmd)
	if err != nil {
		return err
	}
	klog.InfoS("Result:")
	klog.InfoS("%s", strings.TrimSpace(out))
	return nil
}

func workflow(adapterName string, subnetCIDR *net.IPNet) error {
	ovsdbAddress := ovsconfig.GetConnAddress("C:\\openvswitch\\var\\run\\openvswitch")
	ovsdbConnection, err := ovsconfig.NewOVSDBConnectionUDS(ovsdbAddress)
	if err != nil {
		// TODO: ovsconfig.NewOVSDBConnectionUDS might return timeout in the future, need to add retry
		return fmt.Errorf("error connecting OVSDB: %v", err)
	}
	defer ovsdbConnection.Close()
	ovsDatapathType := ovsconfig.OVSDatapathType("system")
	ovsBridgeClient := ovsconfig.NewOVSBridge("br-int", ovsDatapathType, ovsdbConnection)
	if err := prepareHNSNetworkAndOVSExtension(adapterName, ovsBridgeClient.GetBridgeName(), subnetCIDR); err != nil {
		klog.ErrorS(err, "Failed to create HNSNetwork", "name", util.LocalHNSNetwork)
		return err
	}
	if err := setupOVSBridge(ovsBridgeClient); err != nil {
		klog.ErrorS(err, "Failed to setup OVS bridge")
		return err
	}
	return nil
}

func main() {
	_, subnetCIDR, _ := net.ParseCIDR("1.1.1.0/24")
	if err := workflow("Ethernet1", subnetCIDR); err != nil {
		os.Exit(1)
	}
}
