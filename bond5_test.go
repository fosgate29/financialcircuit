package financial

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func TestBondv5(t *testing.T) {

	var circuit bondCircuitv5

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	pk, vk, err := groth16.Setup(r1cs)

	fmt.Print((err))

	//setup signature parameters
	signature.Register(signature.EDDSA_BN254, eddsabn254.GenerateKeyInterfaces)

	// Create a private/pub key to sign
	hFunc := hash.MIMC_BN254.New("seed")
	src := rand.NewSource(0)
	rA := rand.New(src)
	rB := rand.New(src)
	rC := rand.New(src)

	privKeyA, err := signature.EDDSA_BN254.New(rA)
	pubKeyA := privKeyA.Public()

	privKeyB, err := signature.EDDSA_BN254.New(rB)
	pubKeyB := privKeyB.Public()

	privKeyC, err := signature.EDDSA_BN254.New(rC)
	pubKeyC := privKeyC.Public()

	/* Private and Public Key for A,B and C created */

	//Set values for quotes from A,B and C
	var quoteA big.Int
	quoteA.SetString("92", 10)
	QuoteFromA := quoteA.Bytes()

	var quoteB big.Int
	quoteB.SetString("94", 10)
	QuoteFromB := quoteB.Bytes()

	var quoteC big.Int
	quoteC.SetString("95", 10)
	QuoteFromC := quoteC.Bytes()

	signatureA, err := privKeyA.Sign(QuoteFromA[:], hFunc)
	signatureB, err := privKeyB.Sign(QuoteFromB[:], hFunc)
	signatureC, err := privKeyC.Sign(QuoteFromC[:], hFunc)

	id := ecc.BN254

	// Seting up
	var witness bondCircuitv5
	witness.AcceptedQuote.Assign(92)
	witness.WinnerQuote.Assign(92)
	witness.Quote1.Assign(94)
	witness.Quote2.Assign(95)

	witness.QuoteFromA.Assign(QuoteFromA)
	witness.QuoteFromB.Assign(QuoteFromB)
	witness.QuoteFromC.Assign(QuoteFromC)

	//A
	pubkeyAx, pubkeyAy := parsePoint(id, pubKeyA.Bytes())
	var pbAx, pbAy big.Int
	pbAx.SetBytes(pubkeyAx)
	pbAy.SetBytes(pubkeyAy)
	witness.PublicKeyA.A.X.Assign(pubkeyAx)
	witness.PublicKeyA.A.Y.Assign(pubkeyAy)

	sigRx, sigRy, sigS1, sigS2 := parseSignature(id, signatureA)
	witness.SignatureA.R.X.Assign(sigRx)
	witness.SignatureA.R.Y.Assign(sigRy)
	witness.SignatureA.S1.Assign(sigS1)
	witness.SignatureA.S2.Assign(sigS2)

	//B
	pubkeyBAx, pubkeyBAy := parsePoint(id, pubKeyB.Bytes())
	var pbBAx, pbBAy big.Int
	pbBAx.SetBytes(pubkeyBAx)
	pbBAy.SetBytes(pubkeyBAy)
	witness.PublicKeyB.A.X.Assign(pubkeyBAx)
	witness.PublicKeyB.A.Y.Assign(pubkeyBAy)

	sigBRx, sigBRy, sigBS1, sigBS2 := parseSignature(id, signatureB)
	witness.SignatureB.R.X.Assign(sigBRx)
	witness.SignatureB.R.Y.Assign(sigBRy)
	witness.SignatureB.S1.Assign(sigBS1)
	witness.SignatureB.S2.Assign(sigBS2)

	//C
	pubkeyCAx, pubkeyCAy := parsePoint(id, pubKeyC.Bytes())
	var pbCAx, pbCAy big.Int
	pbCAx.SetBytes(pubkeyCAx)
	pbCAy.SetBytes(pubkeyCAy)
	witness.PublicKeyC.A.X.Assign(pubkeyCAx)
	witness.PublicKeyC.A.Y.Assign(pubkeyCAy)

	sigCRx, sigCRy, sigCS1, sigCS2 := parseSignature(id, signatureC)
	witness.SignatureC.R.X.Assign(sigCRx)
	witness.SignatureC.R.Y.Assign(sigCRy)
	witness.SignatureC.S1.Assign(sigCS1)
	witness.SignatureC.S2.Assign(sigCS2)

	// Generate Proof
	proof, err := groth16.Prove(r1cs, pk, &witness)

	fmt.Println(proof)
	if err != nil {
		t.Fatal(err)
	}

	if vk == nil {

	}
	//Check with a correct value and it returns NIL
	var witnessCorrectValue bondCircuitv5
	witnessCorrectValue.AcceptedQuote.Assign(92)

	witnessCorrectValue.PublicKeyA.A.X.Assign(pubkeyAx)
	witnessCorrectValue.PublicKeyA.A.Y.Assign(pubkeyAy)

	witnessCorrectValue.PublicKeyB.A.X.Assign(pubkeyBAx)
	witnessCorrectValue.PublicKeyB.A.Y.Assign(pubkeyBAy)

	witnessCorrectValue.PublicKeyC.A.X.Assign(pubkeyCAx)
	witnessCorrectValue.PublicKeyC.A.Y.Assign(pubkeyCAy)

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
