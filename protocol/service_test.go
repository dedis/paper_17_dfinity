package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"

	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

func TestService(t *testing.T) {
	n := 3
	threshold := n/2 + 1
	local := onet.NewTCPTest()
	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	hosts, roster, _ := local.GenTree(n, false)
	defer local.CloseAll()
	for _, h := range hosts {
		log.LLvl1("Host: ", h.ServerIdentity.Address)
	}

	privs, pubs := GenerateBatchKeys(n)

	rootService := hosts[0].GetService(ServiceName).(*Service)
	rootService.BroadcastPBCContext(roster, pubs, privs, threshold)

	require.Nil(t, rootService.RunDKG())
}
