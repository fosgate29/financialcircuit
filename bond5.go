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

	cs.AssertIsEqual(circuit.AcceptedQuote, circuit.QuoteFromB)
	/*if(QuoQuoteFromAteA < QuoteFromB){
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
