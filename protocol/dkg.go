package protocol

import (
	"fmt"
	"strings"
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
	dkg               *dkg.DistKeyGenerator
	dks               *dkg.DistKeyShare
	index             int
	dkgDoneCb         func(*dkg.DistKeyShare)
	list              []*onet.TreeNode // to avoid recomputing it
	responsesReceived int
	tempResponses     map[uint32][]*dkg.Response // responses received without any deal first
	sentDeal          bool
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

func NewDKGProtocolFromService(node *onet.TreeNodeInstance, c *PBCContext, cb func(*dkg.DistKeyShare)) (*DkgProto, error) {
	dkgen, err := dkg.NewDistKeyGenerator(pairing.G2(), c.Private, c.Roster, random.Stream, c.Threshold)
	if err != nil {
		return nil, err
	}
	dp := &DkgProto{
		TreeNodeInstance: node,
		index:            c.Index,
		dkg:              dkgen,
		dkgDoneCb:        cb,
		list:             node.Tree().List(),
		tempResponses:    make(map[uint32][]*dkg.Response),
	}
	err = dp.RegisterHandlers(dp.OnDeal, dp.OnResponse, dp.OnJustification)
	return dp, err

}

func NewDKGProtocol(node *onet.TreeNodeInstance, t int, cb func(*dkg.DistKeyShare)) (*DkgProto, error) {
	var participants = make([]abstract.Point, len(node.Roster().List))
	list := node.Tree().List()
	var index int = -1
	for i, e := range list {
		participants[i] = e.ServerIdentity.Public
		if node.Public().Equal(participants[i]) {
			index = i
			if node.Index() != index {
				panic("aie")
			}
		}
	}
	dkgen, err := dkg.NewDistKeyGenerator(node.Suite(), node.Private(), participants, random.Stream, t)
	if err != nil {
		return nil, err
	}

	dp := &DkgProto{
		TreeNodeInstance: node,
		index:            index,
		dkg:              dkgen,
		dkgDoneCb:        cb,
		list:             list,
		tempResponses:    make(map[uint32][]*dkg.Response),
	}

	err = dp.RegisterHandlers(dp.OnDeal, dp.OnResponse, dp.OnJustification)
	return dp, err
}

func (d *DkgProto) Start() error {
	d.Lock()
	defer d.Unlock()
	d.sentDeal = true
	return d.sendDeals()
}

func (d *DkgProto) OnDeal(dm DealMsg) error {
	log.LLvl2(d.Name(), " received deal from ", dm.TreeNode.Name())
	d.Lock()
	if !d.sentDeal {
		d.sentDeal = true
		if err := d.sendDeals(); err != nil {
			d.Unlock()
			return err
		}
	}
	resp, err := d.dkg.ProcessDeal(&dm.Deal)

	if err != nil {
		d.Unlock()
		return err
	}

	if err := d.Broadcast(resp); err != nil {
		d.Unlock()
		return err
	}

	d.Unlock()
	d.processAllTempResponses(dm.Deal.Index)
	return nil
}

func (d *DkgProto) processAllTempResponses(dealIndex uint32) {
	d.Lock()
	resps, ok := d.tempResponses[dealIndex]
	if !ok {
		d.Unlock()
		return
	}
	d.Unlock()

	for _, r := range resps {
		d.OnResponse(ResponseMsg{TreeNode: nil, Response: *r})
	}
}

func (d *DkgProto) OnResponse(rm ResponseMsg) error {
	d.Lock()
	defer d.checkCertified()
	defer d.Unlock()
	d.responsesReceived++
	j, err := d.dkg.ProcessResponse(&rm.Response)
	if err != nil {
		if strings.Contains(err.Error(), "corresponding deal") {
			// no deal received for it yet, save it for later
			d.tempResponses[rm.Response.Index] = append(d.tempResponses[rm.Response.Index], &rm.Response)
			return nil
		}
		fmt.Println("no deal received but response for ", rm.TreeNode.RosterIndex)
		return err
	}

	if j != nil {
		return d.Broadcast(j)
	}

	return nil
}

func (d *DkgProto) OnJustification(jm JustificationMsg) error {
	log.Fatal("justification ? everything should be fine...")
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
		log.LLvl2(d.Name(), "sending deal (", i, ") to ", l.Name(), ":", deal)
		if err := d.SendTo(l, deal); err != nil {
			log.Lvl3(d.Info(), err)
		}
	}
	log.LLvl2(d.Name(), "finished sending deals")
	return nil
}

func (d *DkgProto) checkCertified() {
	d.Lock()
	defer d.Unlock()
	if d.done {
		return
	}
	if !d.dkg.Certified() {
		//fmt.Printf("%d (#%d responses received). certified() ? --> NO\n", d.index, d.responsesReceived)
		return
	}
	//fmt.Printf("%d (#%d responses received). certified() ? --> YES\n", d.index, d.responsesReceived)
	dks, err := d.dkg.DistKeyShare()
	if err != nil {
		log.Lvl2(d.ServerIdentity().String(), err)
		return
	}
	d.dks = dks
	d.dkgDoneCb(dks)
	d.done = true
}
