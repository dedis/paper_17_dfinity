package protocol

import (
	"reflect"
	"testing"

	"github.com/dedis/protobuf"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
)

func TestMarshalling(t *testing.T) {
	//p := pbc.NewPairingFp382_2()
	g2 := pairing.G2()
	msg := &PBCContext{
		Index:   0,
		Private: g2.NewKey(random.Stream),
	}
	msg.Roster = []abstract.Point{g2.Point().Mul(nil, msg.Private)}
	buff, err := protobuf.Encode(msg)
	require.Nil(t, err)
	decoded := &PBCContext{}
	require.Nil(t, decode(buff, decoded, g2))
	reflect.DeepEqual(decoded, msg)

	//p = pbc.NewPairingFp254BNb()
	g2 = pairing.G2()
	msg = &PBCContext{
		Index:   0,
		Private: g2.NewKey(random.Stream),
	}
	msg.Roster = []abstract.Point{g2.Point().Mul(nil, msg.Private)}
	buff, err = protobuf.Encode(msg)
	require.Nil(t, err)
	decoded = &PBCContext{}
	require.Nil(t, decode(buff, decoded, g2))
	reflect.DeepEqual(decoded, msg)

}

/*func TestMarshallingPoint(t *testing.T) {*/
//buff := "7f22c088c2ff348d390bd0975d32e678f1cd0d8b23cc13cd9a6ce50e8dbe4808d5cdd1f12daf039af99edc80a6f62b9e9475dff452cb987e57d2a7026bf0258d"
//decoded, err := hex.DecodeString(buff)
//require.Nil(t, err)

//go TryDecode(t, decoded)
//TryDecode(t, decoded)
//}

//func TryDecode(t *testing.T, decoded []byte) {
//for i := 0; i < 10; i++ {
//p := pbc.NewPairingFp254BNb()
//g2 := p.G2()
//point := g2.Point()
//require.Nil(t, point.UnmarshalBinary(decoded))
//point.MarshalBinary()
//}

/*}*/
