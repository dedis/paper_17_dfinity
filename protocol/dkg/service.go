package dkg

import (
	"fmt"

	"github.com/dedis/onet/log"
	"github.com/dedis/paper_17_dfinity/pbc"
	"github.com/dedis/protobuf"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

const ServiceName = "DkgService"

func init() {
	onet.RegisterNewService(ServiceName, NewService)
}

type Service struct {
	c         *onet.Context
	Context   *PBCContext
	construct protobuf.Constructors
	pairing   *pbc.Pairing
	ackd      int
	notify    chan bool
}

func NewService(c *onet.Context) onet.Service {
	s := &Service{
		c:         c,
		construct: make(protobuf.Constructors),
		notify:    make(chan bool),
	}
	c.RegisterProcessor(s, pbcrawType)
	c.RegisterProcessor(s, pbcAck)
	return s
}

func (s *Service) NewProtocol(*onet.TreeNodeInstance, *onet.GenericConfig) (onet.ProtocolInstance, error) {
	panic("not implemented")
}

// Broadcast each individual private / public keys and wait for everyone to
// answer back
// r is the list of usual server identities
// curve is which curve of pbc are we using
// roster is the list of public keys
// private sis the list of private keys
func (s *Service) BroadcastPBCContext(r *onet.Roster, curve int, Roster []abstract.Point, privates []abstract.Scalar) {
	s.pairing = pbc.NewPairing(curve)
	own := s.c.ServerIdentity()
	for i, si := range r.List {
		c := &PBCContext{
			Index:   i,
			Roster:  Roster,
			Private: privates[i],
		}

		if own.Equal(si) {
			s.Context = c
			continue
		}
		for i, r := range Roster {
			fmt.Println(" Serializing Point ", i)
			fmt.Println(r.String())
			buff, _ := r.MarshalBinary()
			fmt.Printf("%x\n", buff)
		}
		buff, err := protobuf.Encode(c)
		if err != nil {
			panic(err)
		}
		log.Lvl1("DKG Service sending to ", i, "/", len(r.List))
		if err := s.c.SendRaw(si, &PBCRaw{Curve: curve, Context: buff}); err != nil {
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
		s.pairing = pbc.NewPairing(msg.Curve)
		g2 := s.pairing.G2()
		if err := decode(msg.Context, s.Context, g2); err != nil {
			panic(err)
		}
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

func (s *Service) ProcessClientRequest(handler string, msg []byte) (reply []byte, err onet.ClientError) {
	panic("not implemented")
}

// message proxy part
