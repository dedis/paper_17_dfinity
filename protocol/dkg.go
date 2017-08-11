package protocol

import (
	"sync"

	"github.com/dedis/onet/log"
	"github.com/dedis/paper_17_dfinity/pedersen/dkg"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

const DKGProtoName = "DKG"

func init() {
	network.RegisterMessage(dkg.Deal{})
	network.RegisterMessage(dkg.Response{})
	network.RegisterMessage(dkg.Justification{})
}

type DkgProto struct {
	*onet.TreeNodeInstance
	dkg       *dkg.DistKeyGenerator
	dks       *dkg.DistKeyShare
	dkgDoneCb func(*dkg.DistKeyShare)
	list      []*onet.TreeNode // to avoid recomputing it
	sentDeal  bool
	sync.Mutex
	done bool
}

type DealMsg struct {
	*onet.TreeNode
	dkg.Deal
}

type ResponseMsg struct {
	*onet.TreeNode
	dkg.Response
}

type JustificationMsg struct {
	*onet.TreeNode
	dkg.Justification
}

func newProtoWrong(node *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	panic("DkgProto should not be instantiated this way, but by a Service")
}

func NewProtocol(node *onet.TreeNodeInstance, t int, cb func(*dkg.DistKeyShare)) (*DkgProto, error) {
	var participants = make([]abstract.Point, len(node.Roster().List))
	list := node.Tree().List()
	for i, e := range list {
		participants[i] = e.ServerIdentity.Public
	}
	dkg, err := dkg.NewDistKeyGenerator(node.Suite(), node.Private(), participants, random.Stream, t)
	if err != nil {
		return nil, err
	}

	dp := &DkgProto{
		TreeNodeInstance: node,
		dkg:              dkg,
		dkgDoneCb:        cb,
		list:             list,
	}

	err = dp.RegisterHandlers(dp.OnDeal, dp.OnResponse, dp.OnJustification)
	return dp, err
}

func (d *DkgProto) Start() error {
	return d.sendDeals()
}

func (d *DkgProto) OnDeal(dm DealMsg) error {
	d.Lock()
	defer d.Unlock()
	if !d.sentDeal {
		d.sentDeal = true
		if err := d.sendDeals(); err != nil {
			return err
		}
	}
	resp, err := d.dkg.ProcessDeal(&dm.Deal)
	if err != nil {
		return err
	}
	return d.Broadcast(resp)
}

func (d *DkgProto) OnResponse(rm ResponseMsg) error {
	d.Lock()
	defer d.checkCertified()
	defer d.Unlock()
	j, err := d.dkg.ProcessResponse(&rm.Response)
	if err != nil {
		return err
	}

	if j != nil {
		return d.Broadcast(j)
	}

	return nil
}

func (d *DkgProto) OnJustification(jm JustificationMsg) error {
	if err := d.dkg.ProcessJustification(&jm.Justification); err != nil {
		return err
	}

	return nil
}

func (d *DkgProto) sendDeals() error {
	deals, err := d.dkg.Deals()
	if err != nil {
		return err
	}
	for i, l := range d.list {
		deal, ok := deals[i]
		if !ok {
			continue
		}
		if err := d.SendTo(l, deal); err != nil {
			log.Lvl3(d.Info(), err)
		}
	}
	return nil
}

func (d *DkgProto) checkCertified() {
	d.Lock()
	defer d.Unlock()
	if d.done {
		return
	}
	if !d.dkg.Certified() {
		return
	}
	dks, err := d.dkg.DistKeyShare()
	if err != nil {
		log.Lvl2(d.ServerIdentity().String(), err)
		return
	}
	d.dks = dks
	d.dkgDoneCb(dks)
	d.done = true
}
