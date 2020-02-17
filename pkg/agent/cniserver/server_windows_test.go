// +build windows

package cniserver

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/Microsoft/go-winio"
	"github.com/vmware-tanzu/antrea/pkg/cni"
	"testing"
)

func TestCNIServerConnection(t *testing.T) {
	stopCh := make(chan struct{})
	randBytes := make([]byte, 16)
	rand.Read(randBytes)

	cniServerAddress := cni.AntreaCNISocketAddr + hex.EncodeToString(randBytes)
	cniServer := CNIServer{cniSocket: cniServerAddress}

	go cniServer.Run(stopCh)
	stopCh <- struct{}{}
	conn, err := winio.DialPipe(cniServerAddress, nil)
	if err != nil {
		//t.Fatal(err)
		t.Error(err)
	}
	defer conn.Close()
}
