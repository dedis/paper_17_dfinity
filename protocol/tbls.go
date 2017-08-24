package protocol

import (
	"fmt"
	"sync"

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
	dks  *dkg.DistKeyShare
	sigs []*bls.ThresholdSig
	cb   func(sig []byte)
	msg  []byte
	done bool
	sync.Mutex
}

func NewTBLSProtocol(tni *onet.TreeNodeInstance, dks *dkg.DistKeyShare) (onet.ProtocolInstance, error) {
	t := &TBLSProto{
		TreeNodeInstance: tni,
		dks:              dks,
	}
	t.RegisterHandlers(t.OnRequest, t.OnSignature)
	return t, nil
}

func NewTBLSRootProtocol(tni *onet.TreeNodeInstance, p *pbc.Pairing, dks *dkg.DistKeyShare, cb func(sig []byte), msg []byte) (onet.ProtocolInstance, error) {
	pi, _ := NewTBLSProtocol(tni, dks)
	proto := pi.(*TBLSProto)
	proto.cb = cb
	proto.msg = msg
	return proto, nil
}

func (t *TBLSProto) Start() error {
	ts := bls.ThresholdSign(pairing, t.dks, t.msg)
	if !bls.ThresholdVerify(pairing, t.dks.Polynomial(), t.msg, ts) {
		panic("aaaa")
	}

	t.sigs = append(t.sigs, ts)
	return t.Broadcast(&TBLSRequest{t.msg})
}

func (t *TBLSProto) OnRequest(or OnRequest) error {
	msg := or.TBLSRequest.Message
	ts := bls.ThresholdSign(pairing, t.dks, msg)

	return t.SendToParent(ts)
}

func (t *TBLSProto) OnSignature(os OnSignature) error {
	t.Lock()
	defer t.Unlock()
	if t.done {
		return nil
	}
	fmt.Println(t.Info(), "OnSignature")
	if !bls.ThresholdVerify(pairing, t.dks.Polynomial(), t.msg, &os.ThresholdSig) {
		panic(fmt.Errorf("%s: gave invalid signature", os.TreeNode.ServerIdentity.Address))
	}
	t.sigs = append(t.sigs, &os.ThresholdSig)
	n := len(t.Roster().List)
	threshold := t.dks.Polynomial().Threshold()
	if len(t.sigs) > threshold {
		sig, err := bls.AggregateSignatures(pairing, t.dks.Polynomial(), t.msg, t.sigs, n, threshold)
		if err != nil {
			panic(err)
		}

		t.done = true
		t.cb(sig)
	}
	return nil
}
