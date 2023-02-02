package main

import (
	crdclientset "antrea.io/antrea/pkg/client/clientset/versioned"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"os"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"
	componentbaseconfig "k8s.io/component-base/config"
)

type Options struct {
	// The path of configuration file.
	configFile string
	// The configuration object
	config *ClientConfig
	round  int
	number int
}

type ClientConfig struct {
	// clientConnection specifies the kubeconfig file and client connection settings for the agent
	// to communicate with the apiserver.
	ClientConnection componentbaseconfig.ClientConnectionConfiguration `yaml:"clientConnection"`
	// AntreaClientConnection specifies the kubeconfig file and client connection settings for the
	// agent to communicate with the Antrea Controller apiserver.
	AntreaClientConnection componentbaseconfig.ClientConnectionConfiguration `yaml:"antreaClientConnection"`
}

func (o *Options) loadConfigFromFile() error {
	data, err := os.ReadFile(o.configFile)
	if err != nil {
		return err
	}

	return yaml.UnmarshalStrict(data, &o.config)
}

func (o *Options) complete(args []string) error {
	if len(o.configFile) > 0 {
		if err := o.loadConfigFromFile(); err != nil {
			return err
		}
	}
	return nil
}

// addFlags adds flags to fs and binds them to options.
func (o *Options) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.configFile, "config", o.configFile, "The path to the configuration file")
	fs.IntVar(&o.round, "round", o.round, "The total rounds to run test")
	fs.IntVar(&o.number, "number", o.number, "The number of resources created per round")
}

func (o *Options) createK8sClients() (clientset.Interface, crdclientset.Interface, error) {
	config := o.config.ClientConnection
	kubeConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: config.Kubeconfig},
		&clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, nil, err
	}

	kubeConfig.AcceptContentTypes = config.AcceptContentTypes
	kubeConfig.ContentType = config.ContentType
	kubeConfig.QPS = 1000
	kubeConfig.Burst = 1000

	kubeClient, err := clientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, err
	}
	crdClient, err := crdclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, err
	}
	return kubeClient, crdClient, nil
}
