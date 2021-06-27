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

	/**
	*  First step: Compile and Setup circuit.
	 */
	var circuit bondCircuitv5
	// compiles our circuit into a R1CS
	fmt.Println("Compiling Bond circuit")
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	fmt.Println("Setting up circuit - it will take some time")
	pk, vk, err := groth16.Setup(r1cs)
	fmt.Println("pk and vk created. Now starting testing")
	if err != nil {
		t.Fatal(err)
	}

	/*
	* Populate test cases
	 */
	var testCases = createTestCases()

	for i := 0; i < 3; i++ {
		fmt.Println("Test ", i)
		testCase := testCases[i]
		/*
		* Hash and Signatures
		 */
		hashFunc := hash.MIMC_BN254
		goMimc := hashFunc.New("seed")
		signature.Register(signature.EDDSA_BN254, eddsabn254.GenerateKeyInterfaces)

		// Create a private/pub key to sign
		hFunc := goMimc //hash.MIMC_BN254.New("seed")
		src1 := rand.NewSource(1)
		src2 := rand.NewSource(2)
		src3 := rand.NewSource(3)
		rA := rand.New(src1)
		rB := rand.New(src2)
		rC := rand.New(src3)

		privKeyA, err := signature.EDDSA_BN254.New(rA)
		pubKeyA := privKeyA.Public()

		privKeyB, err := signature.EDDSA_BN254.New(rB)
		pubKeyB := privKeyB.Public()

		privKeyC, err := signature.EDDSA_BN254.New(rC)
		pubKeyC := privKeyC.Public()

		/* Private and Public Key for A,B and C created */

		//Set values for quotes from A,B and C
		QuoteFromA := testCase.quoteA
		QuoteFromB := testCase.quoteB
		QuoteFromC := testCase.quoteC

		signatureA, err := privKeyA.Sign(QuoteFromA[:], hFunc)
		signatureB, err := privKeyB.Sign(QuoteFromB[:], hFunc)
		signatureC, err := privKeyC.Sign(QuoteFromC[:], hFunc)

		id := ecc.BN254

		// Seting up
		var witness bondCircuitv5

		var IsinHash = testCase.isinTickerHash
		witness.AcceptedQuote.Assign(testCase.winner)
		witness.Isin.Assign(testCase.isinTickerHash)

		goMimc.Reset()
		goMimc.Write([]byte(IsinHash))
		goMimc.Write([]byte(testCase.quoteA))
		var IsinQuoteAHashed = goMimc.Sum(nil)
		IsinQuoteSignedA, err := privKeyA.Sign(IsinQuoteAHashed[:], hFunc)

		goMimc.Reset()
		goMimc.Write([]byte(IsinHash))
		goMimc.Write([]byte(testCase.quoteB))
		var IsinQuoteBHashed = goMimc.Sum(nil)
		IsinQuoteSignedB, err := privKeyB.Sign(IsinQuoteBHashed[:], hFunc)

		goMimc.Reset()
		goMimc.Write([]byte(IsinHash))
		goMimc.Write([]byte(testCase.quoteC))
		var IsinQuoteCHashed = goMimc.Sum(nil)
		IsinQuoteSignedC, err := privKeyC.Sign(IsinQuoteCHashed[:], hFunc)

		sigRxt, sigRyt, sigS1t, sigS2t := parseSignature(id, IsinQuoteSignedA)
		witness.IsinQuoteSignedA.R.X.Assign(sigRxt)
		witness.IsinQuoteSignedA.R.Y.Assign(sigRyt)
		witness.IsinQuoteSignedA.S1.Assign(sigS1t)
		witness.IsinQuoteSignedA.S2.Assign(sigS2t)

		sigRxt, sigRyt, sigS1t, sigS2t = parseSignature(id, IsinQuoteSignedB)
		witness.IsinQuoteSignedB.R.X.Assign(sigRxt)
		witness.IsinQuoteSignedB.R.Y.Assign(sigRyt)
		witness.IsinQuoteSignedB.S1.Assign(sigS1t)
		witness.IsinQuoteSignedB.S2.Assign(sigS2t)

		sigRxt, sigRyt, sigS1t, sigS2t = parseSignature(id, IsinQuoteSignedC)
		witness.IsinQuoteSignedC.R.X.Assign(sigRxt)
		witness.IsinQuoteSignedC.R.Y.Assign(sigRyt)
		witness.IsinQuoteSignedC.S1.Assign(sigS1t)
		witness.IsinQuoteSignedC.S2.Assign(sigS2t)

		AcceptedQuoteSigned, err := privKeyA.Sign(testCase.winner[:], hFunc)

		sigRx, sigRy, sigS1, sigS2 := parseSignature(id, AcceptedQuoteSigned)
		witness.AcceptedQuoteSigned.R.X.Assign(sigRx)
		witness.AcceptedQuoteSigned.R.Y.Assign(sigRy)
		witness.AcceptedQuoteSigned.S1.Assign(sigS1)
		witness.AcceptedQuoteSigned.S2.Assign(sigS2)

		witness.WinnerQuote.Assign(testCase.winner)
		witness.Quote1.Assign(testCase.quoteB)
		witness.Quote2.Assign(testCase.quoteC)

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

		witness.WinnerQuotePubKey.A.X.Assign(pubkeyAx)
		witness.WinnerQuotePubKey.A.Y.Assign(pubkeyAy)

		sigRx, sigRy, sigS1, sigS2 = parseSignature(id, signatureA)
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

		//fmt.Println(proof)
		if err != nil {
			fmt.Println("Test ", i, " failed.")
		}

		if err == nil {

			//Check with a correct value and it returns NIL
			var witnessCorrectValue bondCircuitv5

			witnessCorrectValue.AcceptedQuote.Assign(testCase.winner)

			IsinHash = testCase.isinTickerHash
			witnessCorrectValue.Isin.Assign(IsinHash)

			AcceptedQuoteSigned, err = privKeyA.Sign(testCase.winner[:], hFunc)
			sigRx, sigRy, sigS1, sigS2 = parseSignature(id, AcceptedQuoteSigned)
			witnessCorrectValue.AcceptedQuoteSigned.R.X.Assign(sigRx)
			witnessCorrectValue.AcceptedQuoteSigned.R.Y.Assign(sigRy)
			witnessCorrectValue.AcceptedQuoteSigned.S1.Assign(sigS1)
			witnessCorrectValue.AcceptedQuoteSigned.S2.Assign(sigS2)

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
		}
	}
}
