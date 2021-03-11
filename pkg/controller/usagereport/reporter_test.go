package usagereport

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	goruntime "runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/component-base/featuregate"

	"antrea.io/antrea/pkg/clusteridentity"
	idtesting "antrea.io/antrea/pkg/clusteridentity/testing"
	nptesting "antrea.io/antrea/pkg/controller/networkpolicy/testing"
	"antrea.io/antrea/pkg/controller/usagereport/api"
	"antrea.io/antrea/pkg/features"
)

const (
	informerDefaultResync time.Duration = 30 * time.Second

	testReportInterval = 100 * time.Millisecond

	testReportInitialDelay = 0 * time.Millisecond

	antreaConfigMapName = "antrea-config"

	defaultNumNamespaces                   = 3
	defaultNumPods                         = 10
	defaultNumTiers                        = 0
	defaultNumNetworkPolicies              = 100
	defaultNumAntreaNetworkPolicies        = 0
	defaultNumAntreaClusterNetworkPolicies = 0
)

var (
	clusterUUID     = uuid.New()
	clusterIdentity = clusteridentity.ClusterIdentity{UUID: clusterUUID}
	creationTime    = time.Now()

	antreaConfigMap = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: defaultAntreaNamespace, Name: antreaConfigMapName},
		Data: map[string]string{
			"antrea-agent.conf":      "", // use all defaults
			"antrea-controller.conf": "",
		},
	}

	nodeSystemInfo = corev1.NodeSystemInfo{
		KernelVersion:           "4.15.0-72-generic",
		OSImage:                 "Ubuntu 18.04.3 LTS",
		ContainerRuntimeVersion: "docker://20.10.0",
		KubeletVersion:          "v1.20.0",
		KubeProxyVersion:        "v1.20.0",
		OperatingSystem:         "linux",
		Architecture:            "amd64",
	}

	node1 = &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node1"},
		Spec:       corev1.NodeSpec{},
		Status: corev1.NodeStatus{
			NodeInfo: nodeSystemInfo,
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: "192.168.1.1",
				},
			},
		},
	}
)

type testData struct {
	*testing.T
	ts                             *httptest.Server
	usageReports                   []*api.UsageReport
	stopCh                         chan struct{}
	ctrl                           *gomock.Controller
	mockClusterIdentityProvider    *idtesting.MockClusterIdentityProvider
	mockNetworkPolicyUsageReporter *nptesting.MockNetworkPolicyUsageReporter
	reporter                       *Reporter
	wg                             sync.WaitGroup
}

func setUp(t *testing.T, objects ...runtime.Object) *testData {
	client := fake.NewSimpleClientset(objects...)
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	nodeInformer := informerFactory.Core().V1().Nodes()
	podInformer := informerFactory.Core().V1().Pods()
	namespaceInformer := informerFactory.Core().V1().Namespaces()

	data := testData{
		T:      t,
		stopCh: make(chan struct{}),
	}

	data.ctrl = gomock.NewController(t)
	data.mockClusterIdentityProvider = idtesting.NewMockClusterIdentityProvider(data.ctrl)
	data.mockNetworkPolicyUsageReporter = nptesting.NewMockNetworkPolicyUsageReporter(data.ctrl)

	data.mockClusterIdentityProvider.EXPECT().Get().Return(clusterIdentity, creationTime, nil).Times(1)

	data.mockNetworkPolicyUsageReporter.EXPECT().GetNumTiers().Return(defaultNumTiers, nil).AnyTimes()
	data.mockNetworkPolicyUsageReporter.EXPECT().GetNumNetworkPolicies().Return(defaultNumNetworkPolicies, nil).AnyTimes()
	data.mockNetworkPolicyUsageReporter.EXPECT().GetNumAntreaNetworkPolicies().Return(defaultNumAntreaNetworkPolicies, nil).AnyTimes()
	data.mockNetworkPolicyUsageReporter.EXPECT().GetNumAntreaClusterNetworkPolicies().Return(defaultNumAntreaClusterNetworkPolicies, nil).AnyTimes()

	data.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		assert.NoError(t, err, "Error when reading HTTP request body")
		var report api.UsageReport
		assert.NoError(t, json.Unmarshal(b, &report), "Error when unmarshalling usage report")
		t.Logf("Received test usage report for cluster %s (%d bytes)", report.ClusterUUID, len(b))
		data.usageReports = append(data.usageReports, &report)
		w.WriteHeader(http.StatusCreated)
	}))

	setTestURL := func(config *ReporterConfig) { config.ServerURL = data.ts.URL }
	setTestReportInterval := func(config *ReporterConfig) { config.ReportInterval = testReportInterval }
	setTestReportInitialDelay := func(config *ReporterConfig) { config.ReportInitialDelay = testReportInitialDelay }
	setAntreaNamespace := func(config *ReporterConfig) { config.AntreaNamespace = defaultAntreaNamespace }
	setAntreaConfigMapName := func(config *ReporterConfig) { config.AntreaConfigMapName = antreaConfigMapName }

	data.reporter = NewReporter(
		client, nodeInformer, podInformer, namespaceInformer,
		data.mockClusterIdentityProvider, data.mockNetworkPolicyUsageReporter,
		setTestURL, setTestReportInterval, setTestReportInitialDelay, setAntreaNamespace, setAntreaConfigMapName,
	)

	informerFactory.Start(data.stopCh)

	return &data
}

func (data *testData) runFor(d time.Duration) {
	data.wg.Add(1)
	go func() {
		defer data.wg.Done()
		data.reporter.Run(data.stopCh)
	}()
	time.Sleep(d)
	close(data.stopCh)
	data.wg.Wait()
}

func (data *testData) tearDown() {
	data.ts.Close()
	data.ctrl.Finish()
}

func (data *testData) checkUsageReports(minCount int, maxCount int, numNodes int) {
	require.GreaterOrEqual(data, len(data.usageReports), minCount, "Not enough usage reports received")
	require.LessOrEqual(data, len(data.usageReports), maxCount, "Too many usage reports received")

	for _, report := range data.usageReports[:minCount] {
		assert.Equal(data, clusterUUID.String(), report.ClusterUUID)

		// comparing timestamps directly does not work because of different location pointers
		assert.True(data, report.AntreaDeploymentTime.Equal(creationTime))

		assert.Equal(data, api.K8sDistributionUnknown, report.ClusterInfo.K8sDistribution)
		assert.Equal(data, []api.IPFamily{api.IPFamilyIPv4}, report.ClusterInfo.IPFamilies)

		assert.Len(data, report.ClusterInfo.Nodes, numNodes)
		assert.EqualValues(data, numNodes, *report.ClusterInfo.NumNodes)

		controllerRuntimeInfo := &report.ClusterInfo.ControllerRuntimeInfo
		assert.EqualValues(data, goruntime.NumCPU(), controllerRuntimeInfo.NumCPU)
		assert.Greater(data, controllerRuntimeInfo.NumGoroutine, int32(0))
		assert.Less(data, controllerRuntimeInfo.MemoryStats.HeapAlloc, controllerRuntimeInfo.MemoryStats.Sys)
		assert.Less(data, controllerRuntimeInfo.MemoryStats.Frees, controllerRuntimeInfo.MemoryStats.Mallocs)

		assert.EqualValues(data, defaultNumNamespaces, *report.ClusterInfo.NumNamespaces)
		assert.EqualValues(data, defaultNumPods, *report.ClusterInfo.NumPods)
		assert.EqualValues(data, defaultNumNetworkPolicies, *report.ClusterInfo.NetworkPolicies.NumNetworkPolicies)
		assert.EqualValues(data, defaultNumAntreaNetworkPolicies, *report.ClusterInfo.NetworkPolicies.NumAntreaNetworkPolicies)
		for _, node := range report.ClusterInfo.Nodes {
			// TODO: check the entire struct?
			assert.Equal(data, nodeSystemInfo.KernelVersion, node.KernelVersion)
			assert.True(data, node.HasIPv4Address)
			assert.False(data, node.HasIPv6Address)
		}

		assert.Equal(data, agentConfigDefaults.EnablePrometheusMetrics, report.AgentConfig.EnablePrometheusMetrics)
		assert.Equal(data, controllerConfigDefaults.EnablePrometheusMetrics, report.ControllerConfig.EnablePrometheusMetrics)

		defaultAntreaFeatureGates := features.DefaultAntreaFeatureGates
		assert.Len(data, report.AgentConfig.FeatureGates, len(defaultAntreaFeatureGates))
		for _, featureGate := range report.AgentConfig.FeatureGates {
			assert.Equal(data, features.DefaultFeatureGate.Enabled(featuregate.Feature(featureGate.Name)), featureGate.Enabled)
		}
		assert.Len(data, report.ControllerConfig.FeatureGates, len(defaultAntreaFeatureGates))
		for _, featureGate := range report.ControllerConfig.FeatureGates {
			assert.Equal(data, features.DefaultFeatureGate.Enabled(featuregate.Feature(featureGate.Name)), featureGate.Enabled)
		}
	}
}

func TestUsageReporting(t *testing.T) {
	objects := []runtime.Object{node1, antreaConfigMap}
	for i := 0; i < defaultNumPods; i++ {
		objects = append(objects, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("pod-%d", i)}})
	}
	for i := 0; i < defaultNumNamespaces; i++ {
		objects = append(objects, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("namespace-%d", i)}})
	}
	data := setUp(t, objects...)
	defer data.tearDown()

	data.runFor(time.Second)
	// we should receive about 10 usage reports (one every 100ms for 1s)
	data.checkUsageReports(2, 20, 1)
}

func TestUsageReportingDebugEnv(t *testing.T) {
	client := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	nodeInformer := informerFactory.Core().V1().Nodes()
	podInformer := informerFactory.Core().V1().Pods()
	namespaceInformer := informerFactory.Core().V1().Namespaces()

	t.Run("default", func(t *testing.T) {
		r := NewReporter(client, nodeInformer, podInformer, namespaceInformer, nil, nil)
		assert.Equal(t, productionServerURL, r.ServerURL)
		assert.Equal(t, defaultReportInterval, r.ReportInterval)
		assert.Equal(t, defaultReportInitialDelay, r.ReportInitialDelay)
	})

	t.Run("debug", func(t *testing.T) {
		env := map[string]string{
			"ANTREA_TELEMETRY_STAGING":              "1",
			"ANTREA_TELEMETRY_REPORT_INTERVAL":      "6h",
			"ANTREA_TELEMETRY_REPORT_INITIAL_DELAY": "1h",
		}
		for k, v := range env {
			os.Setenv(k, v)
			defer os.Unsetenv(k)
		}
		r := NewReporter(client, nodeInformer, podInformer, namespaceInformer, nil, nil)
		assert.Equal(t, stagingServerURL, r.ServerURL)
		assert.Equal(t, 6*time.Hour, r.ReportInterval)
		assert.Equal(t, 1*time.Hour, r.ReportInitialDelay)
	})
}
