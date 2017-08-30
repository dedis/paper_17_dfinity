package protocol

import (
	"errors"
	"sync"
	"time"

	"github.com/dedis/onet/log"
	"github.com/dedis/paper_17_dfinity/bls"
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
	c            *onet.Context
	Context      *PBCContext
	construct    protobuf.Constructors
	pairing      *pbc.Pairing
	ackd         int
	notify       chan bool
	dks          *dkg.DistKeyShare // latest dkg share produced
	onetRoster   *onet.Roster      // classic roster to launch the DKG/TBLS protocol
	dksCond      *sync.Cond
	dkgConfirmed int
	dkgWg        *sync.WaitGroup
}

func NewService(c *onet.Context) onet.Service {
	s := &Service{
		c:         c,
		construct: make(protobuf.Constructors),
		notify:    make(chan bool),
		Context:   new(PBCContext),
		dksCond:   sync.NewCond(&sync.Mutex{}),
		dkgWg:     new(sync.WaitGroup),
	}
	c.RegisterProcessor(s, pbcrawType)
	c.RegisterProcessor(s, pbcAck)
	c.RegisterProcessor(s, dkgConfirmationType)
	c.RegisterProcessor(s, dkgAckType)
	return s
}

// RunDKG will launch the DKG protocol with the context & roster set up before with
// BroadcastPBContext.
func (s *Service) RunDKG() error {
	s.dks = nil
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
	go proto.Dispatch()
	log.Lvl1("Root Service DKG.Start()")

	select {
	case _ = <-done:
		log.Lvl1("Root Service DKG DONE !")
		return nil
	case <-time.After(10 * time.Minute):
		return errors.New("service root timeout on DKG")
	}
}

// RunTBLS runs the TBLS protocol with the latest DKG information given. It
// returns the signature and an error if any.
func (s *Service) RunTBLS(msg []byte) ([]byte, error) {
	if s.dks == nil {
		return nil, errors.New("NO DKG run before TBLS !!")
	}
	n := len(s.onetRoster.List)
	// XXX optimize the tree as field
	tree := s.onetRoster.GenerateNaryTreeWithRoot(n-1, s.c.ServerIdentity())
	tni := s.c.NewTreeNodeInstance(tree, tree.Root, TBLSProtoName)

	done := make(chan []byte)
	callback := func(sig []byte) {
		done <- sig
	}

	proto, err := NewTBLSRootProtocol(tni, s.dks, callback, msg)
	if err != nil {
		return nil, err
	}
	if err := s.c.RegisterProtocolInstance(proto); err != nil {
		return nil, err
	}
	go proto.Start()

	select {
	case sig := <-done:
		log.Lvl1("Root Service TBLS DONE !")
		return sig, bls.Verify(pairing, s.dks.Polynomial().Commit(), msg, sig)
	case <-time.After(10 * time.Minute):
		return nil, errors.New("service root timeout on DKG")
	}
}

// WaitDKGFinished asks all nodes if their DKG protocol has returned their DKS
// MUST ONLY BE CALLED ONCE (because I'm lazy and sync.WaitGroup is super
// useful)
func (s *Service) WaitDKGFinished() error {
	for _, si := range s.onetRoster.List {
		s.dkgWg.Add(1)
		if err := s.c.SendRaw(si, &DKGConfirmation{}); err != nil {
			return err
		}
	}

	done := make(chan bool)
	go func() {
		s.dkgWg.Wait()
		done <- true
	}()

	select {
	case <-done:
		s.dkgWg = new(sync.WaitGroup)
		return nil
	case <-time.After(10 * time.Minute):
		return errors.New("TIMEOUT on waiting ACK DKG")
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
	case *DKGConfirmation:
		s.waitDKGConfirmation()
		s.c.SendRaw(p.ServerIdentity, &DKGAck{})
	case *DKGAck:
		s.dkgWg.Done()
	default:
		panic("receiving unknown message")
	}
}

func (s *Service) dkgDone(d *dkg.DistKeyShare) {
	s.dksCond.L.Lock()
	defer s.dksCond.L.Unlock()
	s.dks = d
	s.dksCond.Broadcast()
}

func (s *Service) waitDKGConfirmation() {
	s.dksCond.L.Lock()
	for s.dks == nil {
		s.dksCond.Wait()
	}
	s.dksCond.L.Unlock()
}

func (s *Service) setupContext(c *PBCContext) {
	s.Context = c
	s.c.ProtocolRegister(DKGProtoName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		log.Fatal("ahahah")
		return nil, nil
	})
	s.c.ProtocolRegister(TBLSProtoName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		log.Fatal("ahahah")
		return nil, nil
	})
}

func (s *Service) NewProtocol(node *onet.TreeNodeInstance, c *onet.GenericConfig) (onet.ProtocolInstance, error) {
	switch node.ProtocolName() {
	case DKGProtoName:
		s.dks = nil
		log.LLvl2(s.c.String(), " -> NewProtocol DKG")
		return NewDKGProtocolFromService(node, s.Context, s.dkgDone)
	case TBLSProtoName:
		log.LLvl2(s.c.String(), " -> NewProtocol TBLS")
		return NewTBLSProtocol(node, s.dks)
	default:
		return nil, errors.New("UNDEFINED protocol")
	}
}
func (s *Service) ProcessClientRequest(handler string, msg []byte) (reply []byte, err onet.ClientError) {
	panic("not implemented")
}
