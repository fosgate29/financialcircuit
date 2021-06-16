package financial

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// Yield could be private because if a big bank is trading it has a better yield
// Depending in user cases and scenarios the Party and Counterparty should remain always private
// Other attributes could be private or public depending on Party and Counterparty decisions.
// Time to create is around 8s (notebook) but it isn't an issue for Bonds.
type bondCircuitv4 struct {
	//IsinHash      frontend.Variable `gnark:",public"`  // isin hash
	//BidQuote      frontend.Variable `gnark:",public"`  // 92.63
	AcceptedQuote frontend.Variable `gnark:",public"`  // 92.60
	QuoteFromA    frontend.Variable `gnark:",private"` // 92.92 A
	QuoteFromB    frontend.Variable `gnark:",private"` // 92.60  winner
	QuoteFromC    frontend.Variable `gnark:",private"` // 92.80
}

func (circuit *bondCircuitv4) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	/*zero := cs.Constant(0)
	sub := cs.Sub(circuit.Winner, circuit.WinnerB) // -0.03
	cs.AssertIsEqual(sub, 0)
	fmt.Print(zero)
	fmt.Print(sub)*/

	/*
		correctSub := cs.Sub(circuit.Quote, circuit.Winner) // -0.03

		zero := cs.Constant(5)
		fmt.Print(zero)
		cs.AssertIsLessOrEqual(zero, correctSub)

		cs.AssertIsEqual(circuit.Winner, circuit.Quote)

		y := cs.Sub(circuit.A, circuit.Quote) // 0.32
		z := cs.Sub(circuit.B, circuit.Quote) // -0.03
		w := cs.Sub(circuit.C, circuit.Quote) // 0.17

		fmt.Print(y)
		fmt.Print(z)
		fmt.Print(w)

		cs.AssertIsLessOrEqual(x, x)

		/*a := cs.Constant(90)
		b := cs.Constant(100)
		output := cs.Select("a" == "b", circuit.A, circuit.B)

		fmt.Print(output)

		/*if(QuoteA < QuoteB){
			if(QuoteA < QuoteC){
				Result = QuoteA
			}
			else{
				Result = QuoteC
			}
		}
		else if(QuoteB < QuoteC){
			Result = QuoteB
		}
		else{
			Result = QuoteC
		}

		AssertEqual(Winner, Result)


		/*x3 := cs.Mul(circuit.Quote, circuit.Quote, circuit.Quote)
		cs.AssertIsEqual(circuit.Winner, cs.Add(x3, circuit.Quote, 5))

		cs.AssertIsEqual(4, 4)
		cs.Println(4)*/
	return nil
}
