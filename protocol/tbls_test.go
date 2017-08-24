package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/dedis/paper_17_dfinity/bls"
	"github.com/dedis/paper_17_dfinity/pedersen/dkg"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func TestTBLS(test *testing.T) {
	//	pairing := pbc.NewPairingFp382_2()
	network.Suite = pairing.G2()
	//network.Suite = edwards.NewAES128SHA256Ed25519(false)
	//network.Suite = nist.NewAES128SHA256P256()

	for _, nbrHosts := range []int{3} {

		log.Lvl2("Running dkg with", nbrHosts, "hosts")
		t := nbrHosts/2 + 1

		// function that will be called when protocol is finished by the root
		dkssCh := make(chan *dkg.DistKeyShare, 1)
		dkss := make([]*dkg.DistKeyShare, nbrHosts)
		cb := func(d *dkg.DistKeyShare) {
			s := ToHex(d.Poly.Commit())
			priv := ToHex(d.PriShare().V)
			fmt.Printf("dks[%d] / %d hosts: public -> %s, private -> %s\n", d.Share.I, nbrHosts, s, priv)
			dkssCh <- d
		}
		local := onet.NewLocalTest()
		hosts, _, tree := local.GenBigTree(nbrHosts, nbrHosts, nbrHosts, true)
		for _, host := range hosts {
			// registration of the custom factory
			host.ProtocolRegister(DKGProtoName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
				return NewDKGProtocol(n, t, cb)
			})

		}

		// Start the protocol
		p, err := local.CreateProtocol(DKGProtoName, tree)
		if err != nil {
			test.Fatal("Couldn't create new node:", err)
		}

		go p.Start()
		receivedDKS := 0
		for {
			d := <-dkssCh
			dkss[d.PriShare().I] = d
			receivedDKS++
			if receivedDKS == nbrHosts {
				break
			}
			require.NotNil(test, d.Share)
		}

		fmt.Println("Dist Key Shares DONE ")
		for i := range rand.Perm(len(dkss)) {
			fmt.Printf("#1 Check DKS[%d] -> %s\n", dkss[i].Share.I, ToHex(dkss[i].Share.V))
			require.NotNil(test, dkss[i], "dks index %d nil", i)
		}

		fmt.Println(" --------- local test ---------- ")
		// local test
		msg := []byte("Hello World")
		sigs := make([]*bls.ThresholdSig, nbrHosts)
		for i, d := range dkss {
			sigs[i] = bls.ThresholdSign(pairing, d, msg)
			fmt.Printf("TBLS sig[%d] -> (%d) %s\n", i, sigs[i].Index, sigs[i].Sig.String())
		}
		poly := dkss[0].Polynomial()
		sig, err := bls.AggregateSignatures(pairing, poly, msg, sigs, nbrHosts, t)
		require.Nil(test, err)
		require.Nil(test, bls.Verify(pairing, poly.Commit(), msg, sig))

		fmt.Println(" ---------- network test -----------")
		for i := range rand.Perm(len(dkss)) {
			fmt.Printf("#1 Check DKS[%d] -> %s\n", dkss[i].Share.I, ToHex(dkss[i].Share.V))
			require.NotNil(test, dkss[i], "dks index %d nil", i)
		}

		// network test
		network.Suite = pairing.G1()
		for i, host := range hosts[1:] {
			dks := dkss[i+1]
			host.ProtocolRegister(TBLSProtoName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
				fmt.Printf("Protocol TBLS[%d] -> priv share %s\n", n.Index(), ToHex(dks.Share.V))
				return NewTBLSProtocol(n, dks)
			})
		}

		sigDone := make(chan []byte)
		sigCb := func(sig []byte) {
			sigDone <- sig
		}
		hosts[0].ProtocolRegister(TBLSProtoName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
			return NewTBLSRootProtocol(n, pairing, dkss[0], sigCb, msg)
		})

		// Start the protocol
		p, err = local.CreateProtocol(TBLSProtoName, tree)
		if err != nil {
			test.Fatal("Couldn't create new node:", err)
		}

		go p.Start()

		select {
		case sig := <-sigDone:
			require.NoError(test, bls.Verify(pairing, dkss[0].Polynomial().Commit(), msg, sig))
		case <-time.After(5 * time.Second):
			test.Fatal("hello")
		}

		local.CloseAll()
	}
}

type ToStr interface {
	String() string
}

func ToHex(s ToStr) string {
	b := sha256.Sum256([]byte(s.String()))
	return hex.EncodeToString(b[:])
}
