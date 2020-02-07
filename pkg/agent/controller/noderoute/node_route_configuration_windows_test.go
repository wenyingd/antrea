package noderoute

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"

	"github.com/rakelkar/gonetsh/netroute"
	"github.com/stretchr/testify/require"
)

func TestRouteOperation(t *testing.T) {
	// Leverage loopback interface for testing.
	gwLink := getGatewayIndex("Loopback Pseudo-Interface 1")
	gwIP := net.ParseIP("192.168.2.1")
	_, dest, _ := net.ParseCIDR("192.168.2.0/24")
	route := &hostRoute{
		destination: dest,
		linkIndex:   gwLink,
		gateway:     gwIP,
	}
	nodeName := "node2"
	err := addRoute(nodeName, route)
	require.Nil(t, err)
	nr := netroute.New()
	routes, err := nr.GetNetRoutes(gwLink, dest)
	require.Nil(t, err)
	assert.Equal(t, 1, len(routes))
	rstRoute := routes[0]
	assert.Equal(t, route.gateway.String(), rstRoute.GatewayAddress.String())
	err = deleteRoute(nodeName, route)
	require.Nil(t, err)
	routes2, err := nr.GetNetRoutes(gwLink, dest)
	require.Nil(t, err)
	assert.Equal(t, 0, len(routes2))
}
