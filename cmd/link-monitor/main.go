package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

type uplinkContext struct {
	linkUpdateCh chan netlink.LinkUpdate
	linkContext  context.Context
	cancelFunc   context.CancelFunc
	uplinkIndex  int
	uplinkName   string
	ctrlContext  context.Context
}

func newUplinkContext(ctrlContext context.Context, uplink *net.Interface) *uplinkContext {
	linkUpdateCh := make(chan netlink.LinkUpdate)
	linkContext, cancelFunc := context.WithCancel(context.Background())
	return &uplinkContext{
		linkUpdateCh: linkUpdateCh,
		linkContext:  linkContext,
		cancelFunc:   cancelFunc,
		uplinkIndex:  uplink.Index,
		uplinkName:   uplink.Name,
		ctrlContext:  ctrlContext,
	}
}

func (c *uplinkContext) start() error {
	if err := netlink.LinkSubscribe(c.linkUpdateCh, c.linkContext.Done()); err != nil {
		return fmt.Errorf("failed to subscribe for link events with uplink %s: %v", c.uplinkName, err)
	}

	go func() {
		for true {
			select {
			case update := <-c.linkUpdateCh:
				if update.Attrs().Index != c.uplinkIndex || update.Attrs().Name != c.uplinkName {
					continue
				}
				klog.Infof("Received update: %+v", update.IfInfomsg)
				if update.IfInfomsg.Flags&unix.IFF_UP == 0 {
					klog.InfoS("uplink is down, set it up")
					netlink.LinkSetUp(update.Link)
				}
			case <-c.ctrlContext.Done():
				klog.InfoS("ExternalNodeController task has completed, stop")
				c.linkContext.Done()
				return
			case <-c.linkContext.Done():
				klog.InfoS("uplink task is completed, stop")
				return
			}
		}
	}()
	return nil
}

func (c *uplinkContext) stop() {
	c.cancelFunc()
}

func main() {
	name := "dummy0"
	ctx := context.Background()
	iface, _ := net.InterfaceByName(name)
	uplinkCtx := newUplinkContext(ctx, iface)
	if err := uplinkCtx.start(); err != nil {
		klog.ErrorS(err, "Failed to start subscription")
		os.Exit(1)
	}
	link, _ := netlink.LinkByIndex(iface.Index)
	defer func() {
		uplinkCtx.stop()
		netlink.LinkSetUp(link)
	}()

	if err := netlink.LinkSetDown(link); err != nil {
		klog.ErrorS(err, "Failed to start subscription")
	}

	time.Sleep(time.Second * 10)
}
