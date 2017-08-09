package bls

import (
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/proof"
	"gopkg.in/dedis/crypto.v0/share"
)

type DistKeyShare interface {
	PriShare() *share.PriShare
	Polynomial() *share.PubPoly
}

type ThresholdSig struct {
	Index  int
	Sig    abstract.Point
	Paired abstract.Point
	Proof  *proof.DLEQProof
}

// ThresholdSign generates the regular BLS signature and also computes a
// discrete log equality proof to show that the signature have been correctly
// generated from the private share generated during a DKG.
func ThresholdSign(s PairingSuite, d DistKeyShare, msg []byte) (*ThresholdSig, error) {
	// signs
	HM := hashed(s, msg)
	xHM := HM.Mul(HM, d.PriShare().V)

	eHM := s.GT().PointGT().Pairing(HM, s.G2().Point().Base())
	eXHM := s.GT().PointGT().Pairing(xHM, s.G2().Point().Base())

	// then proves
	base, _ := d.Polynomial().Info()
	eBase := s.GT().PointGT().Pairing(s.G1().Point().Base(), base)

	p, _, _, err := proof.NewDLEQProof(s.GT(), eBase, eHM, d.PriShare().V)
	if err != nil {
		return nil, err
	}

	return &ThresholdSig{
		Index:  d.PriShare().I,
		Sig:    xHM,
		Paired: eXHM,
		Proof:  p,
	}, nil
}

// ThresholdVerify verifies that the threshold signature is have been correctly
// generated from the private share generated during a DKG.
func ThresholdVerify(s PairingSuite, public *share.PubPoly, msg []byte, sig *ThresholdSig) error {
	HM := hashed(s, msg)
	eHM := s.GT().PointGT().Pairing(HM, s.G2().Point().Base())

	base, _ := public.Info()
	eBase := s.GT().PointGT().Pairing(s.G1().Point().Base(), base)

	xG := public.Eval(sig.Index).V
	eXG := s.GT().PointGT().Pairing(s.G1().Point().Base(), xG)
	return sig.Proof.Verify(s.GT(), eBase, eHM, eXG, sig.Paired)
}

func AggregateSignatures(s PairingSuite, sigs []*ThresholdSig, t int) ([]byte, error) {
	return nil, nil
}
