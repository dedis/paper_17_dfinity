package protocol

import (
	"errors"
	"reflect"

	"github.com/dedis/paper_17_dfinity/bls"
	"github.com/dedis/paper_17_dfinity/pedersen/dkg"
	"github.com/dedis/protobuf"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

func init() {
	pbcrawType = network.RegisterMessage(&PBCRaw{})
	pbcAck = network.RegisterMessage(&PBCContextACK{})
	dkgPacketType = network.RegisterMessage(&DKGPacket{})
	tblsPacketType = network.RegisterMessage(&TBLSPacket{})

	onet.RegisterMessageProxy(func() onet.MessageProxy {
		return new(DKGProxy)
	})
	onet.RegisterMessageProxy(func() onet.MessageProxy {
		return new(TBLSProxy)
	})
}

// packets related to the service setting up the right curve and constructor for
// using pairing based crypto
type PBCContext struct {
	Index     int
	Roster    []abstract.Point
	Private   abstract.Scalar
	Threshold int
}

type PBCRaw struct {
	Context []byte
}

type PBCContextACK struct {
	Index int
}

var pbcrawType network.MessageTypeID
var pbcAck network.MessageTypeID

const (
	DKGDeal = iota
	DKGResponse
	DKGJust
	DKGOm
)

var dkgPacketType network.MessageTypeID

type DKGPacket struct {
	Type int

	Buff []byte

	Om *onet.OverlayMsg
}

type DKGProxy struct{}

func (p *DKGProxy) Wrap(msg interface{}, info *onet.OverlayMsg) (interface{}, error) {
	dkgPacket := &DKGPacket{Om: info}
	var err error
	if msg != nil {
		dkgPacket.Buff, err = protobuf.Encode(msg)
		if err != nil {
			return nil, err
		}
	}
	//log.LLvl2("DKGProxy -> Wrap() ", msg)
	switch msg.(type) {
	case *dkg.Deal:
		dkgPacket.Type = DKGDeal
	case *dkg.Response:
		dkgPacket.Type = DKGResponse
	case *dkg.Justification:
		dkgPacket.Type = DKGJust
	default:
		dkgPacket.Type = DKGOm
		dkgPacket.Buff = make([]byte, 0)
	}
	return dkgPacket, nil
}

func (p *DKGProxy) Unwrap(msg interface{}) (interface{}, *onet.OverlayMsg, error) {
	dkgPacket, ok := msg.(*DKGPacket)
	if !ok {
		return nil, nil, errors.New("dkgproxy: received non dkg packet")
	}
	var ret interface{}
	switch dkgPacket.Type {
	case DKGDeal:
		ret = &dkg.Deal{}
	case DKGResponse:
		ret = &dkg.Response{}
	case DKGJust:
		ret = &dkg.Justification{}
	case DKGOm:
		//log.LLvl2("DKGProxy -> Unwrap() OverlayMessage")
		return nil, dkgPacket.Om, nil
	}
	if err := decode(dkgPacket.Buff, ret, pairing.G2()); err != nil {
		return nil, nil, err
	}

	return ret, dkgPacket.Om, nil
}

func (p *DKGProxy) PacketType() network.MessageTypeID {
	return dkgPacketType
}

func (p *DKGProxy) Name() string {
	return DKGProtoName
}

const (
	TBLSRequestType = iota
	TBLSSigType
	TBLSOm
)

var tblsPacketType network.MessageTypeID

type TBLSPacket struct {
	Type int
	Buff []byte
	Om   *onet.OverlayMsg
}

type TBLSProxy struct{}

func (p *TBLSProxy) Wrap(msg interface{}, info *onet.OverlayMsg) (interface{}, error) {
	bPacket := &TBLSPacket{Om: info}
	if msg != nil {
		var err error
		bPacket.Buff, err = protobuf.Encode(msg)
		if err != nil {
			return nil, err
		}
	}
	switch msg.(type) {
	case *TBLSRequest:
		bPacket.Type = TBLSRequestType
	case *bls.ThresholdSig:
		bPacket.Type = TBLSSigType
	default:
		bPacket.Type = TBLSOm
		bPacket.Buff = make([]byte, 0)
	}
	return bPacket, nil
}

func (p *TBLSProxy) Unwrap(msg interface{}) (interface{}, *onet.OverlayMsg, error) {
	bPacket, ok := msg.(*TBLSPacket)
	if !ok {
		return nil, nil, errors.New("tbls proxy received non tbls packet")
	}
	var ret interface{}
	switch bPacket.Type {
	case TBLSRequestType:
		ret = &TBLSRequest{}
	case TBLSSigType:
		ret = &bls.ThresholdSig{}
	case TBLSOm:
		return nil, bPacket.Om, nil
	}

	if err := decode(bPacket.Buff, ret, pairing.G1()); err != nil {
		return nil, nil, err
	}
	return ret, bPacket.Om, nil

}

func (p *TBLSProxy) Name() string {
	return TBLSProtoName
}

func (p *TBLSProxy) PacketType() network.MessageTypeID {
	return tblsPacketType
}

func decode(buff []byte, packet interface{}, suite abstract.Suite) error {
	cons := make(protobuf.Constructors)
	var pt abstract.Point
	var sc abstract.Scalar
	cons[reflect.TypeOf(&pt).Elem()] = func() interface{} { return suite.Point() }
	cons[reflect.TypeOf(&sc).Elem()] = func() interface{} { return suite.Scalar() }
	return protobuf.DecodeWithConstructors(buff, packet, cons)

}
