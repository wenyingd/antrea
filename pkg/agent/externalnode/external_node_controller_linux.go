// Copyright 2022 Antrea Authors
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

package externalnode

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/util"
)

var (
	linkByName             = netlink.LinkByName
	linkSetMTU             = netlink.LinkSetMTU
	linkSetUp              = netlink.LinkSetUp
	removeLinkIPs          = util.RemoveLinkIPs
	removeLinkRoutes       = util.RemoveLinkRoutes
	configureLinkAddresses = util.ConfigureLinkAddresses
	configureLinkRoutes    = util.ConfigureLinkRoutes
)

func (c *ExternalNodeController) moveIFConfigurations(adapterConfig *config.AdapterNetConfig, src string, dst string) error {
	dstLink, err := linkByName(dst)
	if err != nil {
		return fmt.Errorf("failed to find link for destination %s, err %v", dst, err)
	}
	if src != "" {
		srcLink, err := linkByName(src)
		if err != nil {
			return fmt.Errorf("failed to find link for source %s, err %v", src, err)
		}
		if err := linkSetMTU(dstLink, adapterConfig.MTU); err != nil {
			return err
		}
		if err := linkSetUp(dstLink); err != nil {
			return err
		}
		if err := removeLinkIPs(srcLink); err != nil {
			return err
		}
		if err := removeLinkRoutes(srcLink); err != nil {
			return err
		}
	}
	dstIndex := dstLink.Attrs().Index
	// Configure the source interface's IPs on the destination interface.
	if err := configureLinkAddresses(dstIndex, adapterConfig.IPs); err != nil {
		return err
	}
	// Configure the source interface's routes on the destination interface.
	if err := configureLinkRoutes(dstLink, adapterConfig.Routes); err != nil {
		return err
	}
	return nil
}

func (c *ExternalNodeController) removeExternalNodeConfig() error {
	return nil
}

func (c *uplinkMonitor) start() error {
	if c.isStart() {
		return nil
	}

	c.done = make(chan struct{})
	linkUpdateCh := make(chan netlink.LinkUpdate)
	if err := netlink.LinkSubscribe(linkUpdateCh, c.done); err != nil {
		return fmt.Errorf("failed to subscribe for link events: %v", err)
	}

	go func() {
		for true {
			select {
			case update := <-linkUpdateCh:
				c.mutex.Lock()
				name, found := c.uplinks[update.Attrs().Index]
				c.mutex.Unlock()
				if !found || name != update.Attrs().Name {
					continue
				}
				// check if the event is for link down
				if update.IfInfomsg.Flags&unix.IFF_UP == 0 {
					klog.InfoS("uplink is down, set it up")
					netlink.LinkSetUp(update.Link)
				}
			case <-c.stopCh:
				klog.InfoS("ExternalNodeController has stopped")
				close(c.done)
				return
			case <-c.done:
				klog.InfoS("ExternalNode monitor is completed, stop")
				return
			}
		}
	}()
	c.started = true
	return nil
}

func (c *uplinkMonitor) stop() {
	close(c.done)
	c.started = false
}
