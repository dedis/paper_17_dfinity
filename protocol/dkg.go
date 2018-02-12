package protocol

import (
	"strconv"
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
	tmpResponses      map[uint32][]*dkg.Response
	responsesReceived int
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
		tmpResponses:     make(map[uint32][]*dkg.Response),
	}
	return dp, dp.RegisterHandlers(dp.OnDeal, dp.OnResponse, dp.OnJustification)
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
		tmpResponses:     make(map[uint32][]*dkg.Response),
	}
	return dp, dp.RegisterHandlers(dp.OnDeal, dp.OnResponse, dp.OnJustification)
}

func (d *DkgProto) Start() error {
	d.Lock()
	defer d.Unlock()
	d.sentDeal = true
	return d.sendDeals()
}

func (d *DkgProto) id() string {
	return d.Name() + " ( " + strconv.Itoa(d.index) + " / " + strconv.Itoa(len(d.list)) + " ) "
}

/*func (d *DkgProto) Dispatch() error {*/
//n := len(d.list)
//for i := 0; i < n-1; i++ {
////log.Lvl1(d.id(), " <- d.onDealCh (", i, ") ...")
//dm := <-d.onDealCh
//if err := d.OnDeal(dm); err != nil {
//log.Error(err)
//}
//log.Lvl1(d.id(), " <- d.onDealCh (", i, ") RECEIVED from ", dm.Deal.Index, ": Missing ", n-i-1, " deals!")
////log.Lvl1(d.id(), " <- d.onDealCh (", i, ") PROCESSED")
//}

//log.Lvl1(d.id(), " ---- DISPATCH DEAL DONE --- ")
//for i := 0; i < n*(n-1); i++ {
//rm := <-d.onResponseCh
//if err := d.OnResponse(rm); err != nil {
//log.Error(err)
//}
//}
//log.Lvl1(d.id(), " ---- DISPATCH RESPONSES DONE --- ")
//if !d.dkg.Certified() {
//log.Error(d.Name(), "is finished but not DKG !!")
//}
//return nil
/*}*/

func (d *DkgProto) OnDeal(dm DealMsg) error {
	log.Lvl2(d.Name(), " received deal from ", dm.TreeNode.Name())
	d.Lock()
	if !d.sentDeal {
		d.sentDeal = true
		if err := d.sendDeals(); err != nil {
			d.Unlock()
			return err
		}
	}

	resp, err := d.dkg.ProcessDeal(&dm.Deal)
	defer d.processTmpResponses(&dm.Deal)
	if err != nil {
		d.Unlock()
		return err
	}

	if err := d.Broadcast(resp); err != nil {
		d.Unlock()
		return err
	}

	d.Unlock()
	return nil
}

func (d *DkgProto) processTmpResponses(deal *dkg.Deal) {
	d.Lock()
	defer d.checkCertified()
	defer d.Unlock()
	resps, ok := d.tmpResponses[deal.Index]
	if !ok {
		return
	}
	log.Lvl2(d.id(), "processing ", len(resps), " TEMP responses for dealer", deal.Index)
	delete(d.tmpResponses, deal.Index)
	for _, r := range resps {
		_, err := d.dkg.ProcessResponse(r)
		if err != nil {
			log.Error(d.id(), ": err process temp response: ", err)
		}
	}
}

func (d *DkgProto) OnResponse(rm ResponseMsg) error {
	d.Lock()
	defer d.checkCertified()
	defer d.Unlock()
	d.responsesReceived++

	j, err := d.dkg.ProcessResponse(&rm.Response)
	if err != nil {
		if strings.Contains(err.Error(), "got no corresponding deal") {
			d.tmpResponses[rm.Response.Index] = append(d.tmpResponses[rm.Response.Index], &rm.Response)
			log.Lvl2(d.id(), "storing future response for unknown deal ", rm.Response.Index)
			return nil
		}
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
	nbSent := 0
	for i, l := range d.list {
		deal, ok := deals[i]
		if !ok {
			//log.Lvl1(d.id(), " -> not sending deal to ", i)
			continue
		}
		//log.LLvl2(d.Name(), "sending deal (", i, ") to ", l.Name(), ":", deal)
		if err := d.SendTo(l, deal); err != nil {
			log.Error(d.Info(), err)
		}
		nbSent++
	}
	log.Lvl1(d.id(), "finished sending ", nbSent, " deals")
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

type pair struct {
	Dealer   uint32
	Verifier uint32
}
