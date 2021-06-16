package financial

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// Yield could be private because if a big bank is trading it has a better yield
// Depending in user cases and scenarios the Party and Counterparty should remain always private
// Other attributes could be private or public depending on Party and Counterparty decisions.
// Time to create is around 8s (notebook) but it isn't an issue for Bonds.
type bondCircuitv3 struct {
	/**Isin                  frontend.Variable `gnark:",public"`
	Ticker                frontend.Variable `gnark:",public"`
	Yield                 frontend.Variable `gnark:",public"`*/
	Size     frontend.Variable `gnark:",public"`
	Bondhash frontend.Variable `gnark:",public"`  //msg hash
	Party    frontend.Variable `gnark:",private"` /*
		Counterparty          frontend.Variable `gnark:",private"`*/
	PublicKeyParty        PublicKey `gnark:",private"`
	PublicKeyCounterparty PublicKey `gnark:",private"`
	SignatureParty        Signature `gnark:",private"`
	SignatureCounterparty Signature `gnark:",private"`
}

func (circuit *bondCircuitv3) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	// hash function
	//mimc, _ := mimc.NewMiMC("seed", curveID)

	/*bondHash := mimc.Hash(cs, circuit.Isin, circuit.Ticker, circuit.Yield,
	circuit.Size, circuit.Party, circuit.Counterparty)*/

	//cs.AssertIsEqual(circuit.Bondhash, bondHash)

	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	fmt.Println(circuit.Party)
	// verify the signature for Party and Counterparty
	circuit.PublicKeyParty.Curve = params
	circuit.PublicKeyCounterparty.Curve = params

	eddsa.Verify(cs, circuit.SignatureParty, circuit.Bondhash, circuit.PublicKeyParty)
	eddsa.Verify(cs, circuit.SignatureCounterparty, circuit.Bondhash, circuit.PublicKeyCounterparty)

	return nil
}
