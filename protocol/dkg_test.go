package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/dedis/paper_17_dfinity/pedersen/dkg"
	"gopkg.in/dedis/crypto.v0/abstract"
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

	for _, nbrHosts := range []int{10} {
		log.Lvl2("Running dkg with", nbrHosts, "hosts")
		t := nbrHosts/2 + 1
		if t == nbrHosts {
			panic("aie")
		}

		// function that will be called when protocol is finished by the root
		done := make(chan bool)
		var wg sync.WaitGroup
		wg.Add(nbrHosts)
		dkss := make([]*dkg.DistKeyShare, nbrHosts)
		var dksLock sync.Mutex
		cb := func(d *dkg.DistKeyShare) {
			s := sha256.Sum256([]byte(d.Poly.Commit().String()))
			fmt.Println("got dks index ", d.Share.I, " over ", nbrHosts, "hosts. public->", hex.EncodeToString(s[:]))
			dksLock.Lock()
			dkss[d.PriShare().I] = d
			dksLock.Unlock()
			wg.Done()
		}
		local := onet.NewLocalTest()
		hosts, _, tree := local.GenBigTree(nbrHosts, nbrHosts, nbrHosts, true)
		privates := make([]abstract.Scalar, nbrHosts)
		publics := make([]abstract.Point, nbrHosts)
		for _, host := range hosts {
			// registration of the custom factory
			host.ProtocolRegister(DKGProtoName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
				privates[n.Index()] = n.Private()
				publics[n.Index()] = n.Public()
				return NewDKGProtocol(n, t, cb)
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

		/*// try to sign with it*/
		//dsss := make([]*dss.DSS, nbrHosts)
		//for i, dks := range dkss {
		//NewDSS(network.Suite, hosts[i],publics,)
		/*}*/
		local.CloseAll()
	}
}
