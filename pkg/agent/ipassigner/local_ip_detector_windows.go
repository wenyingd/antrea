// Copyright 2021 Antrea Authors
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

package ipassigner

import (
	"sync"
)

// Not implemented yet. The feature gate verification will protect this from being run.
type localIPDetector struct {
	mutex       sync.RWMutex
	ipAssigner  IPAssigner
	cacheSynced bool
}

func (d *localIPDetector) IsLocalIP(ip string) bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.ipAssigner.AssignedIPs().Has(ip)
}

func (d *localIPDetector) Run(stopCh <-chan struct{}) {
	return
}

func (d *localIPDetector) AddEventHandler(handler LocalIPEventHandler) {
	return
}

func (d *localIPDetector) HasSynced() bool {
	return true
}

func NewLocalIPDetector(assigner IPAssigner) *localIPDetector {
	return &localIPDetector{ipAssigner: assigner}
}
