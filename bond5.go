package financial

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// PublicKey stores an eddsa public key (to be used in gnark circuit)
type PublicKey = eddsa.PublicKey
type Signature = eddsa.Signature

type bondCircuitv5 struct {
	//Bid 92.63
	AcceptedQuote frontend.Variable `gnark:",public"` // 92.64
	/*PublicKeyA    PublicKey         `gnark:",public"`
	PublicKeyB    PublicKey         `gnark:",public"`
	PublicKeyC    PublicKey         `gnark:",public"`
	SignatureA    Signature         `gnark:",private"`
	SignatureB    Signature         `gnark:",private"`
	SignatureC    Signature         `gnark:",private"`*/
	QuoteFromA  frontend.Variable `gnark:",private"` // 92.63
	QuoteFromB  frontend.Variable `gnark:",private"` // 92.70 winner - least one
	QuoteFromC  frontend.Variable `gnark:",private"` // 92.80*/
	WinnerQuote frontend.Variable `gnark:",private"` // 92.63
	Quote1      frontend.Variable `gnark:",private"` // 92.70 winner - least one
	Quote2      frontend.Variable `gnark:",private"` // 92.80*/
}

func (circuit *bondCircuitv5) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	//Make sure Winner Quote is the smallest one
	cs.AssertIsLessOrEqual(circuit.WinnerQuote, circuit.Quote1)
	cs.AssertIsLessOrEqual(circuit.WinnerQuote, circuit.Quote2)
	cs.AssertIsEqual(circuit.WinnerQuote, circuit.AcceptedQuote)

	//If winner quote is from A, B or C, one of the subtraction is going to return zero
	subA := cs.Sub(circuit.QuoteFromA, circuit.WinnerQuote)
	subB := cs.Sub(circuit.QuoteFromB, circuit.WinnerQuote)
	subC := cs.Sub(circuit.QuoteFromC, circuit.WinnerQuote)

	outputA := cs.IsZero(subA, curveID) // 1 - iszero - true
	outputB := cs.IsZero(subB, curveID) // 0 false
	outputC := cs.IsZero(subC, curveID) // 0 false

	// outputA || outputB || outputC == 1
	result_temp := cs.Or(outputA, outputB)
	result := cs.Or(result_temp, outputC)

	one := cs.Constant(1)
	cs.AssertIsEqual(result, one) //

	/*
		Proof a,b and C sent value using signture and pub key
	*/

	/*
		If x3 is computed, circuit works.
		If it doesn't have this computation, it fails with this error code:
		runtime error: index out of range [0] with length 0

		x3 := cs.Mul(circuit.AcceptedQuote, circuit.AcceptedQuote, circuit.AcceptedQuote)
		fmt.Print(x3)
	*/
	/*a := CheckIsLessOrEqual(cs, circuit.QuoteFromA, circuit.QuoteFromB)

	fmt.Print(a)

	if a == nil {
		a = CheckIsLessOrEqual(cs, circuit.QuoteFromA, circuit.QuoteFromC)
		fmt.Print(a)
		if a == nil {
			cs.AssertIsEqual(circuit.AcceptedQuote, circuit.QuoteFromA)
		}
	}

	if a != nil {
		a = CheckIsLessOrEqual(cs, circuit.QuoteFromB, circuit.QuoteFromC)
		fmt.Print(a)
		if a == nil {
			cs.AssertIsEqual(circuit.AcceptedQuote, circuit.QuoteFromB)
		}

		if a != nil {
			cs.AssertIsEqual(circuit.AcceptedQuote, circuit.QuoteFromC)
		}
	}*/

	//fmt.Print(a)
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
	}

	cs.AssertIsEqual(cs.AcceptedQuote, Result)
	*/

	return nil
}
