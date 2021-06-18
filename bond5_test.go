package financial

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func TestBondv5(t *testing.T) {

	var circuit bondCircuitv5

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)

	fmt.Print((err))

	// Seting up
	var witness bondCircuitv5
	witness.AcceptedQuote.Assign(93)
	witness.QuoteFromA.Assign(97)
	witness.QuoteFromB.Assign(93)
	witness.QuoteFromC.Assign(94)
	witness.WinnerQuote.Assign(93)
	witness.Quote1.Assign(94)
	witness.Quote2.Assign(97)

	pk, vk, err := groth16.Setup(r1cs)
	//fmt.Print(pk)
	//fmt.Print(vk)

	// Generate Proof
	proof, err := groth16.Prove(r1cs, pk, &witness)

	fmt.Println(proof)
	if err != nil {
		t.Fatal(err)
	}

	//Check with a correct value and it returns NIL
	var witnessCorrectValue bondCircuitv5
	witnessCorrectValue.AcceptedQuote.Assign(95)

	err = groth16.Verify(proof, vk, &witnessCorrectValue)
	if err != nil {
		fmt.Print(err)
	}

	/*var witnessWrongValue bondCircuitv5
	witnessWrongValue.AcceptedQuote.Assign(90)

	err = groth16.Verify(proof, vk, &witnessWrongValue)
	if err != nil {
		fmt.Print("Error - ")
		fmt.Print(err)
	}*/
}
