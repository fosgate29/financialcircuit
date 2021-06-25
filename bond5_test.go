package financial

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"strconv"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

type Bond struct {
	Isin string
}

// func setQuotesValue(valueA int, valueACents int, valueB int, valueBCents int, valueC int, valueCCents int, valueAccepted int, valueAcceptedCents int, winnerValue int, winnerValueCents int, quote1Value int, quote1ValueCents int, quote2Value int, quote2ValueCents int) [14]int {
// 	toRet := [14]int{valueA, valueACents, valueB, valueBCents, valueC, valueCCents, winnerValue, winnerValueCents, valueAccepted, valueAcceptedCents, quote1Value, quote1ValueCents, quote2Value, quote2ValueCents}
// 	return toRet
// }

func setQuotesValue(valueADollars int, valueACents int, valueBDollars int, valueBCents int, valueCDollars int, valueCCents int, valueAcceptedDollars int, valueAcceptedCents int, winnerValueDollars int, winnerValueCents int, quote1ValueDollars int, quote1ValueCents int, quote2ValueDollars int, quote2ValueCents int) [7]int {
	toRet := [7]int{}
	toRet[0] = (valueADollars * 100) + valueACents
	toRet[1] = (valueBDollars * 100) + valueBCents
	toRet[2] = (valueCDollars * 100) + valueCCents
	toRet[3] = (valueAcceptedDollars * 100) + valueAcceptedCents
	toRet[4] = (winnerValueDollars * 100) + winnerValueCents
	toRet[5] = (quote1ValueDollars * 100) + quote1ValueCents
	toRet[6] = (quote2ValueDollars * 100) + quote2ValueCents

	return toRet
}

// func setQuotesValue(valueA float32, valueB float32, valueC float32, valueAccepted float32, winnetValue float32, quote1Value float32, quote2Value float32) [7]float32 {
// 	toRet := [7]float32{valueA, valueB, valueC, valueAccepted, winnetValue, quote1Value, quote2Value}
// 	return toRet
// }

// func parseFloat(value float32) string {
// 	s := fmt.Sprintf("%f", value)
// 	return s
// }

func TestBondv5(t *testing.T) {

	//Isin hash
	var bond Bond
	bond.Isin = "CA29250NAT24"
	reqBodyBytes := new(bytes.Buffer)
	json.NewEncoder(reqBodyBytes).Encode(bond)
	h := sha256.New()
	h.Write([]byte(reqBodyBytes.Bytes()))
	var IsinHash = h.Sum([]byte{})

	fmt.Print(IsinHash)

	var circuit bondCircuitv5

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	pk, vk, err := groth16.Setup(r1cs)

	if err != nil {
		t.Fatal(err)
	}

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

	// set values for all quotes
	// it should be 93.2
	values := setQuotesValue(92, 0, 93, 0, 94, 0, 92, 0, 92, 0, 93, 0, 94, 0)
	fmt.Println(values)

	/* Private and Public Key for A,B and C created */

	//Set values for quotes from A,B and C
	var quoteA big.Int

	quoteA.SetString(strconv.Itoa(values[0]), 10)
	h = sha256.New()
	h.Write([]byte(IsinHash))
	h.Write([]byte(quoteA.Bytes()))
	var QuoteFromAHashed = h.Sum([]byte{})

	//fmt.Print(QuoteFromAHashed)
	QuoteFromA := quoteA.Bytes()
	QuoteFromAHashed = QuoteFromA

	var quoteB big.Int
	quoteB.SetString(strconv.Itoa(values[1]), 10)
	h = sha256.New()
	h.Write([]byte(IsinHash))
	h.Write([]byte(quoteB.Bytes()))
	var QuoteFromBHashed = h.Sum([]byte{})
	//fmt.Print(QuoteFromBHashed)
	QuoteFromB := quoteB.Bytes()
	QuoteFromBHashed = QuoteFromB

	var quoteC big.Int
	quoteC.SetString(strconv.Itoa(values[2]), 10)
	h = sha256.New()
	h.Write([]byte(IsinHash))
	h.Write([]byte(quoteC.Bytes()))
	var QuoteFromCHashed = h.Sum([]byte{})
	//fmt.Print(QuoteFromCHashed)
	QuoteFromC := quoteC.Bytes()
	QuoteFromCHashed = QuoteFromC

	signatureA, err := privKeyA.Sign(QuoteFromAHashed[:], hFunc)
	signatureB, err := privKeyB.Sign(QuoteFromBHashed[:], hFunc)
	signatureC, err := privKeyC.Sign(QuoteFromCHashed[:], hFunc)

	id := ecc.BN254

	// Seting up
	var witness bondCircuitv5

	witness.AcceptedQuote.Assign(values[3])

	//witness.AcceptedQuote.Assign(signatureA)
	sigRx, sigRy, sigS1, sigS2 := parseSignature(id, signatureA)
	witness.AcceptedQuoteSignature.R.X.Assign(sigRx)
	witness.AcceptedQuoteSignature.R.Y.Assign(sigRy)
	witness.AcceptedQuoteSignature.S1.Assign(sigS1)
	witness.AcceptedQuoteSignature.S2.Assign(sigS2)

	witness.IsinHash.Assign(IsinHash)
	witness.WinnerQuote.Assign(values[4])
	witness.Quote1.Assign(values[5])
	witness.Quote2.Assign(values[6])

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

	witness.WinnerPublicKey.A.X.Assign(pubkeyAx)
	witness.WinnerPublicKey.A.Y.Assign(pubkeyAy)

	// Generate Proof
	proof, err := groth16.Prove(r1cs, pk, &witness)

	//fmt.Println(proof)
	if err != nil {
		t.Fatal(err)
	}

	if vk == nil {

	}
	//Check with a correct value and it returns NIL
	var witnessCorrectValue bondCircuitv5

	witnessCorrectValue.AcceptedQuote.Assign(92 * 100)
	witnessCorrectValue.IsinHash.Assign(IsinHash)

	acceptedQuoteSignature, err := privKeyA.Sign(QuoteFromAHashed[:], hFunc)
	sigRx, sigRy, sigS1, sigS2 = parseSignature(id, acceptedQuoteSignature)
	witnessCorrectValue.AcceptedQuoteSignature.R.X.Assign(sigRx)
	witnessCorrectValue.AcceptedQuoteSignature.R.Y.Assign(sigRy)
	witnessCorrectValue.AcceptedQuoteSignature.S1.Assign(sigS1)
	witnessCorrectValue.AcceptedQuoteSignature.S2.Assign(sigS2)

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
