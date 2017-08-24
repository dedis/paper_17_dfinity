package protocol

import (
	"testing"

	"gopkg.in/dedis/onet.v1"
)

func TestService(t *testing.T) {
	n := 5
	local := onet.NewTCPTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	hosts, roster, _ := local.GenTree(n, false)
	defer local.CloseAll()

	privs, pubs := GenerateBatchKeys(n)

	rootService := hosts[0].GetService(ServiceName).(*Service)
	rootService.BroadcastPBCContext(roster, pubs, privs)

	//require.Nil(t, rootService.RunDKG())
}
