package financial

import (
	"bytes"
	"encoding/json"
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

	"github.com/shopspring/decimal"
)

type Bond struct {
	Isin   string
	Size   string
	Ticker string
}

func setQuotesValue(bond Bond, quoteA string, quoteB string, quoteC string) [3][]byte {
	quote0, err := decimal.NewFromString(quoteA)
	quote1, err := decimal.NewFromString(quoteB)
	quote2, err := decimal.NewFromString(quoteC)
	if err != nil {
		panic(err)
	}

	one100 := decimal.NewFromInt(100)
	bondSize, err := decimal.NewFromString(bond.Size)

	toRet := [3][]byte{}
	// 93.63 / 100 = 0,9363
	quote0 = quote0.Div(one100)
	quote1 = quote1.Div(one100)
	quote2 = quote2.Div(one100)

	//0.9363 * 550000 = 514965
	quote0 = bondSize.Mul(quote0)
	quote1 = bondSize.Mul(quote1)
	quote2 = bondSize.Mul(quote2)

	//convert to cents * 100
	// 514965 * 100 = 51496500
	quote0 = quote0.Mul(one100)
	quote1 = quote1.Mul(one100)
	quote2 = quote2.Mul(one100)

	toRet[0] = quote0.BigInt().Bytes()
	toRet[1] = quote1.BigInt().Bytes()
	toRet[2] = quote2.BigInt().Bytes()

	return toRet
}

func TestBondv5(t *testing.T) {

	//Isin hash
	var bond Bond
	bond.Isin = "CA29250NAT24"
	bond.Size = "550000"
	bond.Ticker = "ENB 5.375 27-Sep-2077"

	reqBodyBytes := new(bytes.Buffer)
	json.NewEncoder(reqBodyBytes).Encode(bond)

	hashFunc := hash.MIMC_BN254

	goMimc := hashFunc.New("seed")
	goMimc.Write([]byte(reqBodyBytes.Bytes()))
	var IsinHash = goMimc.Sum(nil)

	//fmt.Print(IsinHash)

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

	// set values for all quotes
	// quoteA, quoteB, QuoteC, winnerQuote - in this example, winner == quoteA
	values := setQuotesValue(bond, "92.63", "93.4", "94")

	//Set values for quotes from A,B and C
	QuoteFromA := values[0]
	QuoteFromB := values[1]
	QuoteFromC := values[2]

	signatureA, err := privKeyA.Sign(QuoteFromA[:], hFunc)
	signatureB, err := privKeyB.Sign(QuoteFromB[:], hFunc)
	signatureC, err := privKeyC.Sign(QuoteFromC[:], hFunc)

	id := ecc.BN254

	// Seting up
	var witness bondCircuitv5

	witness.AcceptedQuote.Assign(values[0])
	witness.Isin.Assign(IsinHash)

	goMimc.Reset()
	goMimc.Write([]byte(IsinHash))
	goMimc.Write([]byte(values[0]))
	var IsinQuoteAHashed = goMimc.Sum(nil)
	IsinQuoteSignedA, err := privKeyA.Sign(IsinQuoteAHashed[:], hFunc)

	goMimc.Reset()
	goMimc.Write([]byte(IsinHash))
	goMimc.Write([]byte(values[1]))
	var IsinQuoteBHashed = goMimc.Sum(nil)
	IsinQuoteSignedB, err := privKeyB.Sign(IsinQuoteBHashed[:], hFunc)

	goMimc.Reset()
	goMimc.Write([]byte(IsinHash))
	goMimc.Write([]byte(values[2]))
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

	AcceptedQuoteSigned, err := privKeyA.Sign(values[0][:], hFunc)

	sigRx, sigRy, sigS1, sigS2 := parseSignature(id, AcceptedQuoteSigned)
	witness.AcceptedQuoteSigned.R.X.Assign(sigRx)
	witness.AcceptedQuoteSigned.R.Y.Assign(sigRy)
	witness.AcceptedQuoteSigned.S1.Assign(sigS1)
	witness.AcceptedQuoteSigned.S2.Assign(sigS2)

	witness.WinnerQuote.Assign(values[0])
	witness.Quote1.Assign(values[1])
	witness.Quote2.Assign(values[2])

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
		t.Fatal(err)
	}

	if vk == nil {

	}
	//Check with a correct value and it returns NIL
	var witnessCorrectValue bondCircuitv5

	witnessCorrectValue.AcceptedQuote.Assign(values[0])

	bond.Isin = "CA29250NAT24"
	bond.Size = "550000"
	bond.Ticker = "ENB 5.375 27-Sep-2077"
	reqBodyBytes = new(bytes.Buffer)
	json.NewEncoder(reqBodyBytes).Encode(bond)

	goMimc.Reset()
	goMimc.Write([]byte(reqBodyBytes.Bytes()))
	IsinHash = goMimc.Sum(nil)
	witnessCorrectValue.Isin.Assign(IsinHash)

	AcceptedQuoteSigned, err = privKeyA.Sign(values[0][:], hFunc)
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
