package protocol

import (
	"github.com/BurntSushi/toml"
	"github.com/dedis/onet/log"
	"github.com/dedis/paper_17_dfinity/pbc"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/onet.v1"
)

const SimulationName = "PedersenDKG"

func init() {
	onet.SimulationRegister(SimulationName, NewSimulation)
}

type Simulation struct {
	onet.SimulationBFTree
	Threshold  int    // if 0, then threshold = n / 2 + 1
	PBCurve    string // see pbc.Curve()
	PBCRoster  []abstract.Point
	PBCPrivate []abstract.Scalar
}

func NewSimulation(config string) (onet.Simulation, error) {
	s := &Simulation{PBCurve: "Fp254Nb"}
	_, err := toml.Decode(config, s)
	// panics if something's wrong
	pbc.Curve(s.PBCurve)
	return s, err
}

// create the pairing based public keys here
func (s *Simulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sim := new(onet.SimulationConfig)
	s.CreateRoster(sim, hosts, 2000)
	n := len(sim.Roster.List)
	sim.Tree = sim.Roster.GenerateNaryTree(n - 1)
	return sim, nil
}

func (s *Simulation) Pairing() *pbc.Pairing {
	curve := pbc.Curve(s.PBCurve)
	return pbc.NewPairing(curve)
}

func (s *Simulation) Run(c *onet.SimulationConfig) error {
	n := len(c.Roster.List)
	roster := make([]abstract.Point, n)
	privates := make([]abstract.Scalar, n)
	pairing := s.Pairing()
	suite := pairing.G2()

	for i := 0; i < n; i++ {
		kp := config.NewKeyPair(suite)
		roster[i] = kp.Public
		privates[i] = kp.Secret
	}
	s.PBCRoster = roster
	s.PBCPrivate = privates
	log.Lvl1("DKG Simulation will dispatch private / public")
	service := c.GetService(ServiceName).(*Service)
	service.BroadcastPBCContext(c.Roster, pbc.Curve(s.PBCurve), roster, privates)
	return nil
}
