package protocol

import (
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
)

func GenerateBatchKeys(n int) ([]abstract.Scalar, []abstract.Point) {
	g2 := pairing.G2()

	privs := make([]abstract.Scalar, n)
	pubs := make([]abstract.Point, n)

	for i := 0; i < n; i++ {
		privs[i] = g2.Scalar().Pick(random.Stream)
		pubs[i] = g2.Point().Mul(nil, privs[i])
	}
	return privs, pubs
}
