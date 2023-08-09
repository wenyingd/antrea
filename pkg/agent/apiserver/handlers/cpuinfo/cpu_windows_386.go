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

import "encoding/binary"

const systemLocalProcessorInformationSize = 24

func getSystemLogicalProcessorInformationSize() int {
	return systemLocalProcessorInformationSize
}

func byteArrayToProcessorStruct(data []byte) (info systemLogicalProcessorInformation) {
	info.processorMask = uintptr(binary.LittleEndian.Uint32(data))
	info.relationship = int(binary.LittleEndian.Uint32(data[4:]))
	copy(info.dataUnion[0:16], data[8:24])
	return
}
