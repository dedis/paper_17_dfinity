package protocol

import (
	"fmt"

	"github.com/dedis/paper_17_dfinity/bls"
	"github.com/dedis/paper_17_dfinity/pbc"
	"github.com/dedis/paper_17_dfinity/pedersen/dkg"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

const TBLSProtoName = "TBLS"

func init() {
	network.RegisterMessage(bls.ThresholdSig{})
	network.RegisterMessage(TBLSRequest{})
}

type TBLSRequest struct {
	Message []byte
}

type OnRequest struct {
	*onet.TreeNode
	TBLSRequest
}

type OnSignature struct {
	*onet.TreeNode
	bls.ThresholdSig
}

type TBLSProto struct {
	*onet.TreeNodeInstance
	p    *pbc.Pairing
	dks  *dkg.DistKeyShare
	sigs []*bls.ThresholdSig
	cb   func(sig []byte)
	msg  []byte
	done bool
}

func NewTBLSProtocol(tni *onet.TreeNodeInstance, p *pbc.Pairing, dks *dkg.DistKeyShare) (onet.ProtocolInstance, error) {
	t := &TBLSProto{
		TreeNodeInstance: tni,
		p:                p,
		dks:              dks,
	}
	t.RegisterHandlers(t.OnRequest, t.OnSignature)
	return t, nil
}

func NewTBLSRootProtocol(tni *onet.TreeNodeInstance, p *pbc.Pairing, dks *dkg.DistKeyShare, cb func(sig []byte), msg []byte) (onet.ProtocolInstance, error) {
	pi, _ := NewTBLSProtocol(tni, p, dks)
	proto := pi.(*TBLSProto)
	proto.cb = cb
	proto.msg = msg
	return proto, nil
}

func (t *TBLSProto) Start() error {
	return t.Broadcast(&TBLSRequest{t.msg})
}

func (t *TBLSProto) OnRequest(or OnRequest) error {
	msg := or.TBLSRequest.Message
	ts := bls.ThresholdSign(t.p, t.dks, msg)

	return t.SendToParent(ts)
}

func (t *TBLSProto) OnSignature(os OnSignature) error {
	if t.done {
		return nil
	}
	if !bls.ThresholdVerify(t.p, t.dks.Polynomial(), t.msg, &os.ThresholdSig) {
		fmt.Println(os.TreeNode.ServerIdentity.Address, " gave invalid signature")
	}
	t.sigs = append(t.sigs, &os.ThresholdSig)
	n := len(t.Roster().List)
	threshold := t.dks.Polynomial().Threshold()
	if len(t.sigs) >= threshold {
		sig, err := bls.AggregateSignatures(t.p, t.dks.Polynomial(), t.msg, t.sigs, n, threshold)
		if err != nil {
			panic(err)
		}

		t.done = true
		t.cb(sig)
	}
	return nil
}
