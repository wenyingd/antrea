// Copyright 2021 Antrea Authors
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
// Source: antrea.io/antrea/pkg/agent/nodeportlocal/portcache (interfaces: LocalPortOpener)

// Package testing is a generated GoMock package.
package testing

import (
	portcache "antrea.io/antrea/pkg/agent/nodeportlocal/portcache"
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// MockLocalPortOpener is a mock of LocalPortOpener interface
type MockLocalPortOpener struct {
	ctrl     *gomock.Controller
	recorder *MockLocalPortOpenerMockRecorder
}

// MockLocalPortOpenerMockRecorder is the mock recorder for MockLocalPortOpener
type MockLocalPortOpenerMockRecorder struct {
	mock *MockLocalPortOpener
}

// NewMockLocalPortOpener creates a new mock instance
func NewMockLocalPortOpener(ctrl *gomock.Controller) *MockLocalPortOpener {
	mock := &MockLocalPortOpener{ctrl: ctrl}
	mock.recorder = &MockLocalPortOpenerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockLocalPortOpener) EXPECT() *MockLocalPortOpenerMockRecorder {
	return m.recorder
}

// OpenLocalPort mocks base method
func (m *MockLocalPortOpener) OpenLocalPort(arg0 int) (portcache.Closeable, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenLocalPort", arg0)
	ret0, _ := ret[0].(portcache.Closeable)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// OpenLocalPort indicates an expected call of OpenLocalPort
func (mr *MockLocalPortOpenerMockRecorder) OpenLocalPort(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenLocalPort", reflect.TypeOf((*MockLocalPortOpener)(nil).OpenLocalPort), arg0)
}
