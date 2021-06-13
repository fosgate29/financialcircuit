package financial

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type bondCircuitv5 struct {
	AcceptedQuote frontend.Variable `gnark:",public"`  // 92.60
	QuoteFromA    frontend.Variable `gnark:",private"` // 92.92
	QuoteFromB    frontend.Variable `gnark:",private"` // 92.60 winner - least one
	QuoteFromC    frontend.Variable `gnark:",private"` // 92.80
}

func (circuit *bondCircuitv5) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	/*
		If x3 is computed, circuit works.
		If it doesn't have this computation, it fails with this error code:
		runtime error: index out of range [0] with length 0

		x3 := cs.Mul(circuit.AcceptedQuote, circuit.AcceptedQuote, circuit.AcceptedQuote)
		fmt.Print(x3)
	*/

	cs.AssertIsEqual(circuit.AcceptedQuote, circuit.QuoteFromB)

	/*if(QuoteFromA < QuoteFromB){
		if(QuoteFromA < QuoteC){
			Result = QuoteFromA
		}
		else{
			Result = QuoteFromC
		}
	}
	else if(QuoteFromB < QuoteFromC){
		Result = QuoteFromB
	}
	else{
		Result = QuoteFromC
	} */

	return nil
}
