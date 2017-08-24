package protocol

import (
	"errors"
	"time"

	"github.com/dedis/onet/log"
	"github.com/dedis/paper_17_dfinity/pbc"
	"github.com/dedis/paper_17_dfinity/pedersen/dkg"
	"github.com/dedis/protobuf"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

const ServiceName = "PBCService"

func init() {
	onet.RegisterNewService(ServiceName, NewService)
}

type Service struct {
	c          *onet.Context
	Context    *PBCContext
	construct  protobuf.Constructors
	pairing    *pbc.Pairing
	ackd       int
	notify     chan bool
	dks        *dkg.DistKeyShare // latest dkg share produced
	onetRoster *onet.Roster      // classic roster to launch the DKG/TBLS protocol
}

func NewService(c *onet.Context) onet.Service {
	s := &Service{
		c:         c,
		construct: make(protobuf.Constructors),
		notify:    make(chan bool),
		Context:   new(PBCContext),
	}
	c.RegisterProcessor(s, pbcrawType)
	c.RegisterProcessor(s, pbcAck)
	return s
}

// RunDKG will launch the DKG protocol with the context & roster set up before with
// BroadcastPBContext.
func (s *Service) RunDKG() error {
	n := len(s.onetRoster.List)
	tree := s.onetRoster.GenerateNaryTreeWithRoot(n-1, s.c.ServerIdentity())
	tni := s.c.NewTreeNodeInstance(tree, tree.Root, DKGProtoName)

	done := make(chan *dkg.DistKeyShare)
	callback := func(d *dkg.DistKeyShare) {
		s.dkgDone(d)
		done <- d
	}

	proto, err := NewDKGProtocolFromService(tni, s.Context, callback)
	if err != nil {
		return err
	}
	if err := s.c.RegisterProtocolInstance(proto); err != nil {
		return err
	}
	go proto.Start()

	select {
	case _ = <-done:
		log.Lvl1("Root Service DKG DONE !")
		return nil
	case <-time.After(10 * time.Minute):
		return errors.New("service root timeout on DKG")
	}
}

// Broadcast each individual private / public keys and wait for everyone to
// answer back
// r is the list of usual server identities
// curve is which curve of pbc are we using
// roster is the list of public keys
// private sis the list of private keys
func (s *Service) BroadcastPBCContext(r *onet.Roster, Roster []abstract.Point, privates []abstract.Scalar, threshold int) {
	// XXX constant pairing
	//s.pairing = pbc.NewPairing(curve)
	s.onetRoster = r
	s.pairing = pairing
	own := s.c.ServerIdentity()
	for i, si := range r.List {
		c := &PBCContext{
			Index:     i,
			Roster:    Roster,
			Private:   privates[i],
			Threshold: threshold,
		}

		if own.Equal(si) {
			s.setupContext(c)
			continue
		}
		/*for i, r := range Roster {*/
		//fmt.Println(" Serializing Point ", i)
		//fmt.Println(r.String())
		//buff, _ := r.MarshalBinary()
		//fmt.Printf("%x\n", buff)
		/*}*/
		buff, err := protobuf.Encode(c)
		if err != nil {
			panic(err)
		}
		log.Lvl1("DKG Service sending to ", i, "/", len(r.List))
		if err := s.c.SendRaw(si, &PBCRaw{Context: buff}); err != nil {
			log.Lvl1(err)
			panic(err)
		}
	}

	// wait for acks
	<-s.notify
}

func (s *Service) Process(p *network.Envelope) {
	switch inner := p.Msg.(type) {
	case *PBCRaw:
		msg := inner
		// XXX constant pairing
		//s.pairing = pbc.NewPairing(msg.Curve)
		s.pairing = pairing
		g2 := s.pairing.G2()
		context := new(PBCContext)
		if err := decode(msg.Context, context, g2); err != nil {
			panic(err)
		}
		s.setupContext(context)
		s.c.SendRaw(p.ServerIdentity, &PBCContextACK{s.Context.Index})
	case *PBCContextACK:
		s.ackd++
		if s.ackd == len(s.Context.Roster)-1 {
			s.notify <- true
		}
	default:
		panic("receiving unknown message")
	}
}

func (s *Service) dkgDone(d *dkg.DistKeyShare) {
	s.dks = d
}

func (s *Service) setupContext(c *PBCContext) {
	s.Context = c
	s.c.ProtocolRegister(DKGProtoName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		log.Fatal("ahahah")
		return NewDKGProtocolFromService(n, s.Context, s.dkgDone)
	})
}

func (s *Service) NewProtocol(node *onet.TreeNodeInstance, c *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.LLvl2(s.c.String(), " -> NewProtocol DKG")
	return NewDKGProtocolFromService(node, s.Context, s.dkgDone)
}
func (s *Service) ProcessClientRequest(handler string, msg []byte) (reply []byte, err onet.ClientError) {
	panic("not implemented")
}
