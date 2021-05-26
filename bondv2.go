package financial

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type bondCircuit struct {
	Isin         frontend.Variable `gnark:",public"`
	Ticker       frontend.Variable `gnark:",public"`
	Yield        frontend.Variable `gnark:",public"`
	Bondhash     frontend.Variable `gnark:",public"`
	Size         frontend.Variable `gnark:",private"`
	Party        frontend.Variable `gnark:",private"`
	Counterparty frontend.Variable `gnark:",private"`
}

func (circuit *bondCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	mimc, _ := mimc.NewMiMC("seed", curveID)

	//fmt.Printf("%v\n", mimc)
	cs.Println("", mimc)
	cs.Println("curveid", curveID)
	cs.Println("c hsah", circuit)

	cs.AssertIsEqual(circuit.Bondhash, mimc.Hash(cs, circuit.Isin, circuit.Ticker, circuit.Yield,
		circuit.Size, circuit.Party, circuit.Counterparty))

	return nil
}
