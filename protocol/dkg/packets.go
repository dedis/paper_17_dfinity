package dkg

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/dedis/paper_17_dfinity/pbc"
	"github.com/dedis/paper_17_dfinity/pedersen/dkg"
	"github.com/dedis/protobuf"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

func init() {
	pbcrawType = network.RegisterMessage(&PBCRaw{})
	pbcAck = network.RegisterMessage(&PBCContextACK{})
	pbcPacketType = network.RegisterMessage(&PBCProtocol{})
}

// packets related to the service setting up the right curve and constructor for
// using pairing based crypto
type PBCContext struct {
	Index   int
	Roster  []abstract.Point
	Private abstract.Scalar
}

type PBCRaw struct {
	Curve   int
	Context []byte
}

type PBCContextACK struct {
	Index int
}

var pbcrawType network.MessageTypeID
var pbcAck network.MessageTypeID

// packets related to the message proxy so it can marshal and unmarshal with
// pairing based crypto
const (
	TypeDKG int = iota
	TypeTBLS
)

type PBCProtocol struct {
	Type int

	Buff []byte

	Om *onet.OverlayMsg
}

var pbcPacketType network.MessageTypeID

type DKGPacket struct {
	Deal          *dkg.Deal
	Response      *dkg.Response
	Justification *dkg.Justification
}

type DKGProxy struct {
	p *pbc.Pairing
}

func (p *DKGProxy) Wrap(msg interface{}, info *onet.OverlayMsg) (interface{}, error) {
	dkgPacket := &DKGPacket{}
	switch inner := msg.(type) {
	case *dkg.Deal:
		dkgPacket.Deal = inner
	case *dkg.Response:
		dkgPacket.Response = inner
	case *dkg.Justification:
		dkgPacket.Justification = inner
	default:
		panic("not implementing anything else for the moment")
	}

	buff, err := protobuf.Encode(dkgPacket)
	if err != nil {
		return nil, err
	}
	return &PBCProtocol{
		Type: TypeDKG,
		Buff: buff,
		Om:   info,
	}, nil
}

func (p *DKGProxy) Unwrap(msg interface{}) (interface{}, *onet.OverlayMsg, error) {
	pbcPacket, ok := msg.(*PBCProtocol)
	if !ok {
		return nil, nil, errors.New("dkgproxy: received non pbcprotocol packet")
	}
	packet, err := unwrap(p.p, msg)
	if err != nil {
		return nil, nil, err
	}
	dkgPacket, ok := packet.(*DKGPacket)
	if !ok {
		return nil, nil, errors.New("dkgproxy: received non dkg packet")
	}
	switch {
	case dkgPacket.Deal != nil:
		return dkgPacket.Deal, pbcPacket.Om, nil
	case dkgPacket.Response != nil:
		return dkgPacket.Response, pbcPacket.Om, nil
	case dkgPacket.Justification != nil:
		return dkgPacket.Justification, pbcPacket.Om, nil
	}
	return nil, nil, errors.New("dkgproxy: unknown error")
}

func (p *DKGProxy) PacketType() network.MessageTypeID {
	return pbcPacketType
}

func (p *DKGProxy) Name() string {
	return ProtoName
}

func unwrap(p *pbc.Pairing, msg interface{}) (interface{}, error) {
	pbc := msg.(*PBCProtocol)
	var packet interface{}
	var suite abstract.Suite
	switch pbc.Type {
	case TypeDKG:
		packet = &DKGPacket{}
		suite = p.G2()
	case TypeTBLS:
		//
	}

	return packet, decode(pbc.Buff, packet, suite)
}

func decode(buff []byte, packet interface{}, suite abstract.Suite) error {
	cons := make(protobuf.Constructors)
	var pt abstract.Point
	var sc abstract.Scalar
	cons[reflect.TypeOf(&pt).Elem()] = func() interface{} { return suite.Point() }
	cons[reflect.TypeOf(&sc).Elem()] = func() interface{} { return suite.Scalar() }
	fmt.Println(cons)
	return protobuf.DecodeWithConstructors(buff, packet, cons)

}
