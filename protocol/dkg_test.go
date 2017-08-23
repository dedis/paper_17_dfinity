package protocol

import (
	"sync"
	"testing"
	"time"

	"github.com/dedis/paper_17_dfinity/pedersen/dkg"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func TestMain(m *testing.M) {
	log.TestOutput(true, 5)
	log.MainTest(m)
}

func TestDkgProtocol(test *testing.T) {
	//pairing := pbc.NewPairingFp382_2()
	network.Suite = pairing.G2()
	//network.Suite = edwards.NewAES128SHA256Ed25519(false)
	//network.Suite = nist.NewAES128SHA256P256()

	for _, nbrHosts := range []int{5} {

		log.Lvl2("Running dkg with", nbrHosts, "hosts")
		t := nbrHosts/2 + 1

		// function that will be called when protocol is finished by the root
		done := make(chan bool)
		var wg sync.WaitGroup
		wg.Add(nbrHosts)
		cb := func(d *dkg.DistKeyShare) {
			wg.Done()
		}
		local := onet.NewLocalTest()
		hosts, _, tree := local.GenBigTree(nbrHosts, nbrHosts, nbrHosts, true)
		for _, host := range hosts {
			// registration of the custom factory
			host.ProtocolRegister(DKGProtoName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
				return NewProtocol(n, t, cb)
			})

		}

		// Start the protocol
		p, err := local.CreateProtocol(DKGProtoName, tree)
		if err != nil {
			test.Fatal("Couldn't create new node:", err)
		}
		go func() {
			wg.Wait()
			done <- true
		}()

		go p.Start()

		select {
		case <-done:
		case <-time.After(time.Duration(nbrHosts) * time.Second):
			test.Fatal("could not get a DKS after two seconds")
		}
		local.CloseAll()
	}
}
