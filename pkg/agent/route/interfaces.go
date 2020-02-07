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

package route

import (
	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
)

// HostRoute is a struct to describe the routing configuration on the host.
type HostRoute interface {
	delete() error
	add() error
}

// Client is route client.
type Client struct {
	nodeConfig *types.NodeConfig
	encapMode  config.TrafficEncapModeType
}

// NewClient returns a route client
func NewClient() *Client {
	return &Client{}
}

func (c *Client) DeletePeerCIDRRoute(routes []HostRoute) error {
	for _, rt := range routes {
		if err := rt.delete(); err != nil {
			return err
		}
	}
	return nil
}
