package debug

import (
	"antrea.io/antrea/pkg/agent/util"
)

func enableIPForwarding() error {
	name := "br-int"
	if err := util.EnableIPForwarding(name); err != nil {
		return fmt.Errorf("unable to enable net adapter with name %s: %v", name, err)
	}
	return nil
}
func main() {
	if err := enableIPForwarding(); err != nil {
		klog.ErrorS(err)
	}
}
