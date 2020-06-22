package cniserver

import (
	"fmt"
	"github.com/vmware-tanzu/antrea/pkg/agent/controller/noderoute"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"net"
	"strings"
	"time"

	json "github.com/json-iterator/go"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/cniserver/ipam"
	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	cnipb "github.com/vmware-tanzu/antrea/pkg/apis/cni/v1beta1"
)

const (
	ipamHostLocal  = "host-local"
	defaultCNIPath = "/opt/cni/bin"

	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second

	defaultWorkers = 4
)

// PodWatcher is responsible for watching Pod events.
type PodWatcher struct {
	kubeClient       clientset.Interface
	ifaceStore       interfacestore.InterfaceStore
	nodeConfig       *config.NodeConfig
	podLock          *containerAccessArbitrator
	queue            workqueue.RateLimitingInterface
	nsxNodeCache     *noderoute.NodeCache
	cniNetworkConfig []byte
}

func (w *PodWatcher) watch() {
	nodeName := w.nodeConfig.Name
	options := metav1.ListOptions{
		//FieldSelector: fields.AndSelectors(
		//	fields.OneTermEqualSelector("nodeName", nodeName),
		//	fields.OneTermEqualSelector("hostNetwork", "false"),
		//).String(),
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
	}

	watcher, err := w.kubeClient.CoreV1().Pods("").Watch(options)
	if err != nil {
		klog.Warningf("Failed to start watcher for Pod: %#v", err)
		return
	}

	klog.Infof("Started watch for Pods")
	eventCount := 0
	defer func() {
		klog.Infof("Stopped watcher for %s, total items received: %d", eventCount)
		watcher.Stop()
	}()

	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return
			}
			switch event.Type {
			case watch.Added:
				w.enqueuePod(event.Object)
				klog.V(2).Infof("Added Pod (%#v)", event.Object)
			case watch.Modified:
				w.enqueuePod(event.Object)
				klog.V(2).Infof("Updated Pod (%#v)", event.Object)
			case watch.Deleted:
				w.enqueuePod(event.Object)
				klog.V(2).Infof("Removed Pod (%#v)", event.Object)
			default:
				klog.Errorf("Unknown event: %v", event)
				return
			}
			eventCount++
		}
	}
}

func (w *PodWatcher) enqueuePod(obj interface{}) {
	pod, isPod := obj.(*v1.Pod)
	if !isPod {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Received unexpected object: %v", obj)
			return
		}
		pod, ok = deletedState.Obj.(*v1.Pod)
		if !ok {
			klog.Errorf("DeletedFinalStateUnknown contains non-Pod object: %v", deletedState.Obj)
			return
		}
	}
	if isPodSkipped(pod) {
		return
	}
	podKey := util.GenerateContainerInterfaceKey(pod.Name, pod.Namespace)
	klog.V(2).Infof("Enqueue key %s for Pod", podKey)
	w.queue.Add(podKey)
}

func isPodSkipped(pod *v1.Pod) bool {
	// Skip Pods configured with hostNetwork=true
	if (pod.Spec.HostNetwork)  {
		return true
	}
	// Skip terminated Pod.
	if pod.Status.Phase == v1.PodSucceeded || pod.Status.Phase == v1.PodFailed {
		return true
	}
	return false
}

// AddPod allocates IP from IPAM driver, sync it to nestdb, and then add into local cache.
func (w *PodWatcher) AddPod(pod *v1.Pod) error {
	podName := pod.Name
	podNameSpace := pod.Namespace
	containerID := string(pod.UID)
	// A Pod event might be sent out after the Pod is deleted. Check Pod's Name, and assign IP only for a Pod has valid Name.
	// Otherwise, a leak for IPAM might be introduced when deleting Pod.
	if podName == "" {
		klog.Infof("Pod name is not set, skip such Pod.")
		return nil
	}

	podKey := util.GenerateContainerInterfaceKey(podName, podNameSpace)

	w.podLock.lockContainer(podKey)
	defer w.podLock.unlockContainer(podKey)

	// Return if the target Pod is already added into the cache.
	_, found := w.ifaceStore.GetContainerInterface(podName, podNameSpace)
	if found {
		klog.V(2).Infof("Found an existing record with podName %s podNamespace %s, returning", podName, podNameSpace)
		return nil
	}

	var podIP net.IP
	if pod.Status.PodIP != ""  {
		// Retrieve PodIP from the Pod configuration. This might happen in restart case, and is used to avoid duplication
		// for IP allocation.
		podIP = net.ParseIP(pod.Status.PodIP)
	} else {
		// Prepare the CNI configuration.
		cniConfig := w.generateCNIConfig(podName, podNameSpace, containerID)

		// Request IP allocation.
		ipamResult, err := ipam.ExecIPAMAdd(cniConfig, ipamHostLocal, podKey)
		if err != nil {
			klog.Errorf("Failed to add IP addresses from IPAM driver with config %v: %v", cniConfig, err)
			return err
		}
		podIP, err = parseContainerIP(ipamResult.IPs)
		if err != nil {
			klog.Errorf("Failed to find container %s IP", containerID)
			return err
		}
		klog.V(2).Infof("Allocate IP for new Pod %s/%s from IPAM: %+v", podNameSpace, podName, ipamResult)

		// Todo: Sync the IPAM result to nestdb.
	}

	// Write the IPAM result into interface store.
	containerConfig := interfacestore.NewContainerInterface(podKey, containerID, podName, podNameSpace, nil, podIP)
	w.ifaceStore.AddInterface(containerConfig)
	klog.Infof("Added IP result %s into interface store for Pod %s/%s", podIP.String(), podNameSpace, podName)
	return nil
}

// DeletePod releases the IP from IPAM driver, deletes configuration from nestdb, and remove record from local cache.
func (w *PodWatcher) DeletePod(podName, podNameSpace string) error {
	podKey := util.GenerateContainerInterfaceKey(podName, podNameSpace)

	w.podLock.lockContainer(podKey)
	defer w.podLock.unlockContainer(podKey)

	// Return if the target Pod is already removed from the cache.
	containerConfig, found := w.ifaceStore.GetContainerInterface(podName, podNameSpace)
	if !found {
		klog.V(2).Infof("Not find record with podName %s podNamespace %s, returning", podName, podNameSpace)
		return nil
	}
	// Prepare the CNI configuration.
	cniConfig := w.generateCNIConfig(podName, podNameSpace, containerConfig.ContainerID)

	// Release IP to IPAM driver
	if err := ipam.ExecIPAMDelete(cniConfig, ipamHostLocal, podKey); err != nil {
		klog.Errorf("Failed to delete IP addresses by IPAM driver: %v", err)
		return err
	}

	klog.V(2).Infof("Deleted IP for Pod %s/%s from IPAM", podNameSpace, podName)

	// Todo: delete from nestdb

	w.ifaceStore.DeleteInterface(containerConfig)
	klog.Infof("Deleted IP result from interface store for Pod %s/%s", podNameSpace, podName)
	return nil
}

func (w *PodWatcher) generateCNIConfig(podName, podNamespace, containerID string) *cnipb.CniCmdArgs {
	return &cnipb.CniCmdArgs{
		ContainerId:          containerID,
		Ifname:               "eth0",
		Args:                 generateArgs(podName, podNamespace, containerID),
		Netns:                "none",
		NetworkConfiguration: w.cniNetworkConfig,
		Path:                 defaultCNIPath,
	}
}

func generateArgs(podName, podNamespace, infraContainer string) string {
	argsFormat := "IgnoreUnknown=1;K8S_POD_NAMESPACE=%s;K8S_POD_NAME=%s;K8S_POD_INFRA_CONTAINER_ID=%s"
	return fmt.Sprintf(argsFormat, podNamespace, podName, infraContainer)
}

func (w *PodWatcher) generateNetworkConfiguration() []byte {
	netCfg := &NetworkConfig{
		Name:       "antrea",
		CNIVersion: "0.3.0",
		Type:       "antrea",
		IPAM: ipam.IPAMConfig{
			Type:    ipamHostLocal,
			Subnet:  w.nodeConfig.PodCIDR.String(),
			Gateway: w.nodeConfig.GatewayConfig.IP.String(),
		},
	}
	cfgBytes, _ := json.Marshal(netCfg)
	return cfgBytes
}

func (w *PodWatcher) handlePodEvent(podKey string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing NSX Node config for %s. (%v)", podKey, time.Since(startTime))
	}()

	keys := strings.Split(podKey, "/")
	if len(keys) < 3 {
		return fmt.Errorf("invalid Pod key")
	}

	podName := keys[2]
	nameSpace := keys[1]

	options := metav1.GetOptions{}
	pod, err := w.kubeClient.CoreV1().Pods(nameSpace).Get(podName, options)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		w.DeletePod(podName, nameSpace)
	}

	return w.AddPod(pod)
}

func (w *PodWatcher) processPodEvent() bool {
	obj, quit := w.queue.Get()
	if quit {
		return false
	}
	// We call Done here so the workqueue knows we have finished processing this item. We also
	// must remember to call Forget if we do not want this work item being re-queued. For
	// example, we do not call Forget if a transient error occurs, instead the item is put back
	// on the workqueue and attempted again after a back-off period.
	defer w.queue.Done(obj)

	// We expect strings (Node name) to come off the workqueue.
	if key, ok := obj.(string); !ok {
		// As the item in the workqueue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen: enqueuePod only enqueues strings.
		w.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := w.handlePodEvent(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		w.queue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		w.queue.AddRateLimited(key)
		klog.Errorf("Error syncing Pod %s, requeuing. Error: %v", key, err)
	}
	return true
}

func (w *PodWatcher) worker() {
	for w.processPodEvent() {
	}
}

func (w *PodWatcher) Run(stopCh <-chan struct{}) {
	klog.Info("Starting Pod watcher")
	defer func() {
		w.queue.ShutDown()
		klog.Info("Shutting down CNI server")
	}()

	w.cniNetworkConfig = w.generateNetworkConfiguration()

	go w.watch()

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(w.worker, time.Second, stopCh)
	}
	<-stopCh
}

func NewPodWatcher(kubeClient clientset.Interface,
	ifaceStore interfacestore.InterfaceStore,
	nodeConfig *config.NodeConfig) *PodWatcher {
	watcher := &PodWatcher{
		kubeClient: kubeClient,
		ifaceStore: ifaceStore,
		nodeConfig: nodeConfig,
		podLock: newContainerAccessArbitrator(),
		queue:      workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "pods"),
	}
	return watcher
}
