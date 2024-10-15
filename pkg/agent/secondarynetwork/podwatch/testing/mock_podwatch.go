// Copyright 2024 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Code generated by MockGen. DO NOT EDIT.
// Source: antrea.io/antrea/pkg/agent/secondarynetwork/podwatch (interfaces: InterfaceConfigurator,IPAMAllocator)
//
// Generated by this command:
//
//	mockgen -copyright_file hack/boilerplate/license_header.raw.txt -destination pkg/agent/secondarynetwork/podwatch/testing/mock_podwatch.go -package testing antrea.io/antrea/pkg/agent/secondarynetwork/podwatch InterfaceConfigurator,IPAMAllocator
//

// Package testing is a generated GoMock package.
package testing

import (
	reflect "reflect"

	ipam "antrea.io/antrea/pkg/agent/cniserver/ipam"
	types "antrea.io/antrea/pkg/agent/cniserver/types"
	interfacestore "antrea.io/antrea/pkg/agent/interfacestore"
	v1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	gomock "go.uber.org/mock/gomock"
)

// MockInterfaceConfigurator is a mock of InterfaceConfigurator interface.
type MockInterfaceConfigurator struct {
	ctrl     *gomock.Controller
	recorder *MockInterfaceConfiguratorMockRecorder
}

// MockInterfaceConfiguratorMockRecorder is the mock recorder for MockInterfaceConfigurator.
type MockInterfaceConfiguratorMockRecorder struct {
	mock *MockInterfaceConfigurator
}

// NewMockInterfaceConfigurator creates a new mock instance.
func NewMockInterfaceConfigurator(ctrl *gomock.Controller) *MockInterfaceConfigurator {
	mock := &MockInterfaceConfigurator{ctrl: ctrl}
	mock.recorder = &MockInterfaceConfiguratorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockInterfaceConfigurator) EXPECT() *MockInterfaceConfiguratorMockRecorder {
	return m.recorder
}

// ConfigureSriovSecondaryInterface mocks base method.
func (m *MockInterfaceConfigurator) ConfigureSriovSecondaryInterface(arg0, arg1, arg2, arg3, arg4 string, arg5 int, arg6 string, arg7 *types100.Result) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConfigureSriovSecondaryInterface", arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
	ret0, _ := ret[0].(error)
	return ret0
}

// ConfigureSriovSecondaryInterface indicates an expected call of ConfigureSriovSecondaryInterface.
func (mr *MockInterfaceConfiguratorMockRecorder) ConfigureSriovSecondaryInterface(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConfigureSriovSecondaryInterface", reflect.TypeOf((*MockInterfaceConfigurator)(nil).ConfigureSriovSecondaryInterface), arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7)
}

// ConfigureVLANSecondaryInterface mocks base method.
func (m *MockInterfaceConfigurator) ConfigureVLANSecondaryInterface(arg0, arg1, arg2, arg3, arg4 string, arg5 int, arg6 *ipam.IPAMResult) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConfigureVLANSecondaryInterface", arg0, arg1, arg2, arg3, arg4, arg5, arg6)
	ret0, _ := ret[0].(error)
	return ret0
}

// ConfigureVLANSecondaryInterface indicates an expected call of ConfigureVLANSecondaryInterface.
func (mr *MockInterfaceConfiguratorMockRecorder) ConfigureVLANSecondaryInterface(arg0, arg1, arg2, arg3, arg4, arg5, arg6 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConfigureVLANSecondaryInterface", reflect.TypeOf((*MockInterfaceConfigurator)(nil).ConfigureVLANSecondaryInterface), arg0, arg1, arg2, arg3, arg4, arg5, arg6)
}

// DeleteSriovSecondaryInterface mocks base method.
func (m *MockInterfaceConfigurator) DeleteSriovSecondaryInterface(arg0 *interfacestore.InterfaceConfig) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteSriovSecondaryInterface", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteSriovSecondaryInterface indicates an expected call of DeleteSriovSecondaryInterface.
func (mr *MockInterfaceConfiguratorMockRecorder) DeleteSriovSecondaryInterface(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteSriovSecondaryInterface", reflect.TypeOf((*MockInterfaceConfigurator)(nil).DeleteSriovSecondaryInterface), arg0)
}

// DeleteVLANSecondaryInterface mocks base method.
func (m *MockInterfaceConfigurator) DeleteVLANSecondaryInterface(arg0 *interfacestore.InterfaceConfig) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteVLANSecondaryInterface", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteVLANSecondaryInterface indicates an expected call of DeleteVLANSecondaryInterface.
func (mr *MockInterfaceConfiguratorMockRecorder) DeleteVLANSecondaryInterface(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteVLANSecondaryInterface", reflect.TypeOf((*MockInterfaceConfigurator)(nil).DeleteVLANSecondaryInterface), arg0)
}

// MockIPAMAllocator is a mock of IPAMAllocator interface.
type MockIPAMAllocator struct {
	ctrl     *gomock.Controller
	recorder *MockIPAMAllocatorMockRecorder
}

// MockIPAMAllocatorMockRecorder is the mock recorder for MockIPAMAllocator.
type MockIPAMAllocatorMockRecorder struct {
	mock *MockIPAMAllocator
}

// NewMockIPAMAllocator creates a new mock instance.
func NewMockIPAMAllocator(ctrl *gomock.Controller) *MockIPAMAllocator {
	mock := &MockIPAMAllocator{ctrl: ctrl}
	mock.recorder = &MockIPAMAllocatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIPAMAllocator) EXPECT() *MockIPAMAllocatorMockRecorder {
	return m.recorder
}

// SecondaryNetworkAllocate mocks base method.
func (m *MockIPAMAllocator) SecondaryNetworkAllocate(arg0 *v1beta1.PodOwner, arg1 *types.NetworkConfig) (*ipam.IPAMResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SecondaryNetworkAllocate", arg0, arg1)
	ret0, _ := ret[0].(*ipam.IPAMResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SecondaryNetworkAllocate indicates an expected call of SecondaryNetworkAllocate.
func (mr *MockIPAMAllocatorMockRecorder) SecondaryNetworkAllocate(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SecondaryNetworkAllocate", reflect.TypeOf((*MockIPAMAllocator)(nil).SecondaryNetworkAllocate), arg0, arg1)
}

// SecondaryNetworkRelease mocks base method.
func (m *MockIPAMAllocator) SecondaryNetworkRelease(arg0 *v1beta1.PodOwner) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SecondaryNetworkRelease", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SecondaryNetworkRelease indicates an expected call of SecondaryNetworkRelease.
func (mr *MockIPAMAllocatorMockRecorder) SecondaryNetworkRelease(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SecondaryNetworkRelease", reflect.TypeOf((*MockIPAMAllocator)(nil).SecondaryNetworkRelease), arg0)
}
