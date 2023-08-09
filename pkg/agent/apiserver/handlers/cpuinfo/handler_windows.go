//go:build windows
// +build windows

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
	"runtime"
	"syscall"
	"unsafe"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	systemv1beta1 "antrea.io/antrea/pkg/apis/system/v1beta1"
)

var mod = syscall.NewLazyDLL("kernel32.dll")
var getProcInfo = mod.NewProc("GetLogicalProcessorInformation")

func parseCPUInfoFromSys() (*systemv1beta1.NodeCPUInfo, error) {
	cpuInfo := systemv1beta1.NodeCPUInfo{
		ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.Now()},
	}
	physicalCores, cores, lprocs, nodes, _ := getLogicalProcessorInformation()
	klog.V(4).InfoS("Got LogicalProcessorInformation", "Cores", physicalCores, "CPUs", cores, "lprocs", lprocs, "Nodes", nodes)
	cpuInfo.CPUs = cores
	cpuInfo.Cores = physicalCores
	cpuInfo.Nodes = nodes
	cpuInfo.OS = runtime.GOOS
	cpuInfo.Arch = runtime.GOARCH
	return &cpuInfo, nil
}

// The SYSTEM_LOGICAL_PROCESSOR_INFORMATION struct in Windows.
//
//	typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION {
//	 ULONG_PTR                      ProcessorMask;
//	 LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
//	 union {
//	   struct {
//	     BYTE Flags;
//	   } ProcessorCore;
//	   struct {
//	     DWORD NodeNumber;
//	   } NumaNode;
//	   CACHE_DESCRIPTOR Cache;
//	   ULONGLONG        Reserved[2];
//	 } DUMMYUNIONNAME;
//	} SYSTEM_LOGICAL_PROCESSOR_INFORMATION, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION;
type systemLogicalProcessorInformation struct {
	processorMask uintptr
	relationship  int
	//	 union {
	//	   struct {
	//	     BYTE Flags;
	//	   } ProcessorCore;
	//	   struct {
	//	     DWORD NodeNumber;
	//	   } NumaNode;
	//	   CACHE_DESCRIPTOR Cache;
	//	   ULONGLONG        Reserved[2];
	//	 } DUMMYUNIONNAME;
	dataUnion [16]byte
}

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-system_logical_processor_information
func getLogicalProcessorInformation() (phys, cores, processors, numaNodeCount int, err error) {
	var buflen uint32 = 0
	err = syscall.Errno(0)
	status, _, err := getProcInfo.Call(uintptr(0), uintptr(unsafe.Pointer(&buflen)))
	if status == 0 {
		if err != syscall.Errno(122) { // ERROR_INSUFFICIENT_BUFFER
			return
		}
	} else {
		return 0, 0, 0, 0, syscall.Errno(1)
	}
	buf := make([]byte, buflen)
	status, _, err = getProcInfo.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&buflen)))
	if status == 0 {
		return
	}

	countBits := func(num uint64) (count int) {
		count = 0
		for num > 0 {
			if (num & 0x1) == 1 {
				count++
			}
			num >>= 1
		}
		return
	}

	for i := 0; uint32(i) < buflen; i += getSystemLogicalProcessorInformationSize() {
		info := byteArrayToProcessorStruct(buf[i : i+getSystemLogicalProcessorInformationSize()])
		switch info.relationship {
		case 1: // RelationNumaNode
			numaNodeCount++
		case 0: // RelationProcessorCore
			cores++
			processors += countBits(uint64(info.processorMask))
		case 3: // RelationProcessorPackage
			phys++
		}
	}
	return
}
