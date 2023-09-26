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

type dummyInterfaceType *struct{}

// getARPIgnoreForInterface returns 0 on Windows because the ARP query is responded via OpenFlow entries statically,
// and no need to run an userspace responder.
func getARPIgnoreForInterface(iface string) (int, error) {
	return 1, nil
}

// ensureDummyDevice creates the dummy device if it doesn't exist.
func ensureDummyDevice(deviceName string) (dummyInterfaceType, error) {
	return nil, nil
}

func (a *ipAssigner) addIPOnDummy(parsedIP net.IP) error {
	return nil
}

func (a *ipAssigner) deleteIPFromDummy(parsedIP net.IP) error {
	return nil
}

func (a *ipAssigner) syncIPsOnDummy(ips sets.Set[string]) error {
	return nil
}
