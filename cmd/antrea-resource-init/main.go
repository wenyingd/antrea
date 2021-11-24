// Copyright 2020 Antrea Authors
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

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	k8sconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/yaml"
)

var commandName = path.Base(os.Args[0])

func run(yamlResource string) error {
	if yamlResource == "" {
		return errors.New("missing yaml file path")
	}
	klog.Infof("Loading yaml file: %s", yamlResource)
	yamlData, err := os.ReadFile(yamlResource)
	if err != nil {
		return err
	}
	apiConfig := k8sconfig.GetConfigOrDie()
	klog.Infof("Using K8s API server: %s", apiConfig.Host)
	client, err := k8sclient.New(apiConfig, k8sclient.Options{})
	if err != nil {
		return err
	}
	// 60 seconds should be enough for creating a few K8s resources
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	klog.Infof("Creating resources")
	err = forEachObjectInYAML(ctx, client, yamlData, "", applyOneYaml)
	return err
}

func newCommand() *cobra.Command {
	var yamlResource string

	cmd := &cobra.Command{
		Use:   commandName,
		Short: commandName + " is utility for Antrea to create initial Kubernetes resources, only needed for TKG Service",
		Long:  commandName + " is utility for Antrea to create initial Kubernetes resources, only needed for TKG Service",
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(yamlResource); err != nil {
				klog.Fatalf("Error running %s: %v", commandName, err)
			}
			klog.Infof("Done")
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&yamlResource, "file", "f", "", "The path to the yaml source")
	return cmd
}

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	cmd := newCommand()
	err := cmd.Execute()
	if err != nil {
		logs.FlushLogs()
		os.Exit(1)
	}
}

func applyOneYaml(ctx context.Context, client k8sclient.Client, obj *unstructured.Unstructured) error {
	klog.Infof("Creating %s \"%s\" in Namespace \"%s\"", obj.GroupVersionKind(), obj.GetName(), obj.GetNamespace())
	owner := k8sclient.FieldOwner(commandName)
	opt := &k8sclient.PatchOptions{
		Force: new(bool),
	}
	*opt.Force = true
	if obj.GetKind() == "APIService" {
		// APIService doesn't support server-side apply, so need special care.
		return applyAPIServiceYaml(ctx, client, obj)
	}
	if obj.GetKind() == "ConfigMap" {
		*opt.Force = false
	}
	// Server-side apply
	if err := client.Patch(ctx, obj, k8sclient.Apply, owner, opt); err != nil {
		if obj.GetKind() == "ConfigMap" {
			if apierrors.HasStatusCause(err, metav1.CauseTypeFieldManagerConflict) {
				klog.Infof(
					"Got conflict when patching object %s %s/%s: %s. User may change the data manually. Trying to remove .data field from init resource definition and patch again.",
					obj.GroupVersionKind(),
					obj.GetNamespace(),
					obj.GetName(),
					err,
				)
				delete(obj.Object, "data")
				if err1 := client.Patch(ctx, obj, k8sclient.Apply, owner, opt); err1 != nil {
					err = err1
				} else {
					return nil
				}
			}
		}
		return fmt.Errorf("failed to patch object %s %s/%s: %w", obj.GroupVersionKind(), obj.GetNamespace(), obj.GetName(), err)
	}
	return nil
}

func applyAPIServiceYaml(ctx context.Context, client k8sclient.Client, obj *unstructured.Unstructured) error {
	owner := k8sclient.FieldOwner(commandName)
	err := client.Create(ctx, obj, owner)
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create object %s %q: %w", obj.GroupVersionKind(), obj.GetName(), err)
	}
	klog.Infof("Patching existing object %s \"%s\"", obj.GroupVersionKind(), obj.GetName())
	patch, err := obj.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to cover object to json %s %q: %w", obj.GroupVersionKind(), obj.GetName(), err)
	}
	if err = client.Patch(ctx, obj, k8sclient.RawPatch(k8stypes.StrategicMergePatchType, patch), owner); err != nil {
		return fmt.Errorf("failed to patch object %s %q: %w", obj.GroupVersionKind(), obj.GetName(), err)
	}
	return nil
}

type forEachObjectInYAMLActionFunc func(context.Context, k8sclient.Client, *unstructured.Unstructured) error

func forEachObjectInYAML(
	ctx context.Context,
	client k8sclient.Client,
	data []byte,
	namespace string,
	actionFn forEachObjectInYAMLActionFunc) error {

	chanObj, chanErr := decodeYAML(data)
	for {
		select {
		case obj := <-chanObj:
			if obj == nil {
				return nil
			}
			if namespace != "" {
				obj.SetNamespace(namespace)
			}
			if err := actionFn(ctx, client, obj); err != nil {
				return err
			}
		case err := <-chanErr:
			if err == nil {
				return nil
			}
			return fmt.Errorf("failed to decode yaml: %w", err)
		}
	}
}

// decodeYAML unmarshals a YAML document or multidoc YAML as unstructured
// objects, placing each decoded object into a channel.
func decodeYAML(data []byte) (<-chan *unstructured.Unstructured, <-chan error) {

	var (
		chanErr        = make(chan error)
		chanObj        = make(chan *unstructured.Unstructured)
		multidocReader = utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	)

	go func() {
		defer close(chanErr)
		defer close(chanObj)

		// Iterate over the data until Read returns io.EOF. Every successful
		// read returns a complete YAML document.
		for {
			buf, err := multidocReader.Read()
			if err != nil {
				if err == io.EOF {
					return
				}
				chanErr <- fmt.Errorf("failed to read yaml: %w", err)
				return
			}

			// Do not use this YAML doc if it is unkind.
			var typeMeta runtime.TypeMeta
			if err := yaml.Unmarshal(buf, &typeMeta); err != nil {
				continue
			}
			if typeMeta.Kind == "" {
				continue
			}

			// Define the unstructured object into which the YAML document will be
			// unmarshaled.
			obj := &unstructured.Unstructured{
				Object: map[string]interface{}{},
			}

			// Unmarshal the YAML document into the unstructured object.
			if err := yaml.Unmarshal(buf, &obj.Object); err != nil {
				chanErr <- fmt.Errorf("failed to unmarshal yaml data: %w", err)
				return
			}

			// Place the unstructured object into the channel.
			chanObj <- obj
		}
	}()

	return chanObj, chanErr
}
