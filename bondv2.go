package financial

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Yield could be private because if a big bank is trading it has a better yield
// Depending in user cases and scenarios the Party and Counterparty should remain always private
// Other attributes could be private or public depending on Party and Counterparty decisions.
type bondCircuit struct {
	Isin         frontend.Variable `gnark:",public"`
	Ticker       frontend.Variable `gnark:",public"`
	Yield        frontend.Variable `gnark:",public"`
	Bondhash     frontend.Variable `gnark:",public"`
	Size         frontend.Variable `gnark:",public"`
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
