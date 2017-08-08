package dkg

import (
	"github.com/dedis/onet"
	"gopkg.in/dedis/kyber.v1/share/pedersen/dkg"
)

const ServiceName = "DKG"

func init() {

}

type Suite dkg.Suite

type DkgService struct {
	*onet.ServiceProcessor
	suite Suite
}
