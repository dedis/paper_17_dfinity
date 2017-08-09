package bls

import (
	"testing"

	"github.com/dedis/paper_17_dfinity/pbc"
	"github.com/dedis/paper_17_dfinity/pedersen/dkg"
	"github.com/dedis/paper_17_dfinity/pedersen/vss"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
)

var pairing = pbc.NewPairingFp254BNb()
var suite = pairing.G2()

var nbParticipants = 7

var partPubs []abstract.Point
var partSec []abstract.Scalar

var dkgs []*dkg.DistKeyGenerator

func init() {
	partPubs = make([]abstract.Point, nbParticipants)
	partSec = make([]abstract.Scalar, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		sec, pub := genPair()
		partPubs[i] = pub
		partSec[i] = sec
	}
	dkgs = dkgGen()
}

func TestThresholdBLS(t *testing.T) {
	fullExchange(t)
	dkg := dkgs[0]
	dks, err := dkg.DistKeyShare()
	require.Nil(t, err)

	msg := []byte("Hello World")
	tsig, err := ThresholdSign(pairing, dks, msg)
	require.Nil(t, err)

	require.Nil(t, ThresholdVerify(pairing, dks.Polynomial(), msg, tsig))
}

func dkgGen() []*dkg.DistKeyGenerator {
	dkgs := make([]*dkg.DistKeyGenerator, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		dkg, err := dkg.NewDistKeyGenerator(suite, partSec[i], partPubs, random.Stream, nbParticipants/2+1)
		if err != nil {
			panic(err)
		}
		dkgs[i] = dkg
	}
	return dkgs
}

func fullExchange(t *testing.T) {
	dkgs = dkgGen()
	// full secret sharing exchange
	// 1. broadcast deals
	resps := make([]*dkg.Response, 0, nbParticipants*nbParticipants)
	for _, dkg := range dkgs {
		deals, err := dkg.Deals()
		require.Nil(t, err)
		for i, d := range deals {
			resp, err := dkgs[i].ProcessDeal(d)
			require.Nil(t, err)
			require.Equal(t, vss.StatusApproval, resp.Response.Status)
			resps = append(resps, resp)
		}
	}
	// 2. Broadcast responses
	for _, resp := range resps {
		for i, dkg := range dkgs {
			// ignore all messages from ourself
			if resp.Response.Index == uint32(i) {
				continue
			}
			j, err := dkg.ProcessResponse(resp)
			require.Nil(t, err)
			require.Nil(t, j)
		}
	}

}
func genPair() (abstract.Scalar, abstract.Point) {
	sc := suite.Scalar().Pick(random.Stream)
	return sc, suite.Point().Mul(nil, sc)
}
