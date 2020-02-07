package route

import (
	"net"
	"testing"

	"github.com/rakelkar/gonetsh/netroute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/antrea/pkg/agent/util"
)

func TestRouteOperation(t *testing.T) {
	// Leverage loopback interface for testing.
	gwLink := util.GetNetLinkIndex("Loopback Pseudo-Interface 1")
	gwIP := net.ParseIP("192.168.2.1")
	_, dest, _ := net.ParseCIDR("192.168.2.0/24")
	route := &hRoute{
		route:&netroute.Route{
			LinkIndex:         gwLink,
			DestinationSubnet: dest,
			GatewayAddress:    gwIP,
		},
	}
	err := route.add()
	require.Nil(t, err)
	nr := netroute.New()
	routes, err := nr.GetNetRoutes(gwLink, dest)
	require.Nil(t, err)
	assert.Equal(t, 1, len(routes))
	rstRoute := routes[0]
	require.Nil(t, err)
	assert.Equal(t, route.route.GatewayAddress.String(), rstRoute.GatewayAddress.String())
	err = route.delete()
	routes2, err := nr.GetNetRoutes(gwLink, dest)
	require.Nil(t, err)
	assert.Equal(t, 0, len(routes2))
}
