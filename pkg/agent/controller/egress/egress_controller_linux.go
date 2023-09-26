package egress

import "fmt"

func (c *EgressController) addSNATRule(ipState *egressIPState) error {
	if err := c.routeClient.AddSNATRule(ipState.egressIP, ipState.mark); err != nil {
		return fmt.Errorf("error installing SNAT rule for IP %s: %v", ipState.egressIP, err)
	}
	return nil
}
