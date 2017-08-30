package protocol

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/dedis/onet/log"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/simul/monitor"
)

const SimulationName = "dfinity"

func init() {
	onet.SimulationRegister(SimulationName, NewSimulation)
}

type Simulation struct {
	onet.SimulationBFTree
	Threshold  int // if 0, then threshold = n / 2 + 1
	PBCRoster  []abstract.Point
	PBCPrivate []abstract.Scalar
}

func NewSimulation(config string) (onet.Simulation, error) {
	s := &Simulation{}
	_, err := toml.Decode(config, s)
	// panics if something's wrong
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

func (s *Simulation) Run(c *onet.SimulationConfig) error {
	fmt.Println("SIMULATION: RUN()")
	n := len(c.Roster.List)
	privs, pubs := GenerateBatchKeys(n)
	s.PBCRoster = pubs
	s.PBCPrivate = privs
	log.Lvl1("DKG Simulation will dispatch private / public")
	service := c.GetService(ServiceName).(*Service)
	service.BroadcastPBCContext(c.Roster, pubs, privs, s.Threshold)

	for i := 0; i < s.Rounds; i++ {
		log.Lvl1("DKG(", i, ") Context broadcasted. Run protocol now...")
		dkgSetup := monitor.NewTimeMeasure("dkg_setup")
		dkgWait := monitor.NewTimeMeasure("dkg_wait")
		if err := service.RunDKG(); err != nil {
			log.Fatal(err)
		}
		dkgSetup.Record()
		log.Lvl1("DKG(", i, ") Protocol DONE ! waiting all dkg done...")
		if err := service.WaitDKGFinished(); err != nil {
			log.Fatal(err)
		}
		dkgWait.Record()
		tbls := monitor.NewTimeMeasure("tbls")
		log.Lvl1("DKG (", i, ") ALL DONE !")
		log.Lvl1("Start TBLS (", i, ") !")

		msg := []byte("let's dfinityze the world")
		_, err := service.RunTBLS(msg)
		tbls.Record()
		if err != nil {
			log.Fatal(err)
		}
		log.Lvl1("TBLS (", i, ") DONE")
	}
	return nil
}
