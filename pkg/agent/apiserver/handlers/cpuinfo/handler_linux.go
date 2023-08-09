//go:build linux
// +build linux

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

package cpuinfo

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/google/cadvisor/machine"
	"github.com/google/cadvisor/utils/sysfs"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	systemv1beta1 "antrea.io/antrea/pkg/apis/system/v1beta1"
)

const (
	cpuInfoFile = "/proc/cpuinfo"
)

func parseCPUInfoFromSys() (*systemv1beta1.NodeCPUInfo, error) {
	inHostNamespace := false
	if _, err := os.Stat("/host/proc"); os.IsNotExist(err) {
		inHostNamespace = true
	}

	rootFs := "/"
	if !inHostNamespace {
		rootFs = "/host"
	}

	cpuinfo, err := os.ReadFile(filepath.Join(rootFs, cpuInfoFile))
	if err != nil {
		return nil, err
	}

	sysFs := sysfs.NewRealSysFs()
	topology, logicalCPUs, err := machine.GetTopology(sysFs)
	if err != nil {
		return nil, err
	}
	klog.V(4).InfoS("Got CPU topology", "topology", topology, "numCores", logicalCPUs)

	cpuVendorID := machine.GetCPUVendorID(cpuinfo)
	numPhysicalCores := machine.GetPhysicalCores(cpuinfo)
	numSockets := machine.GetSockets(cpuinfo)

	cpuInfo := &systemv1beta1.NodeCPUInfo{
		ObjectMeta: metav1.ObjectMeta{
			CreationTimestamp: metav1.Now(),
		},
		CPUVendorID: cpuVendorID,
		CPUs:        logicalCPUs,
		Cores:       numPhysicalCores,
		Sockets:     numSockets,
		Nodes:       len(topology),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
	}
	return cpuInfo, nil
}
