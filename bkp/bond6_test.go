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

func TestBondv6(t *testing.T) {

	var circuit bondCircuitv6

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
	rA := rand.New(src1)
	rB := rand.New(src2)

	privKeyA, err := signature.EDDSA_BN254.New(rA)
	pubKeyA := privKeyA.Public()

	privKeyB, err := signature.EDDSA_BN254.New(rB)
	pubKeyB := privKeyB.Public()

	if pubKeyB == nil {
		fmt.Print(pubKeyB)
	}

	//Set values for quotes from A,B and C
	var quoteA big.Int
	quoteA.SetString("92", 10)
	QuoteFromA := quoteA.Bytes()

	//signatureA, err := privKeyA.Sign(QuoteFromA[:], hFunc)
	signatureA, err := privKeyB.Sign(QuoteFromA[:], hFunc)

	id := ecc.BN254

	// Seting up
	var witness bondCircuitv6

	witness.Quote.Assign(92)

	//A
	pubkeyAx, pubkeyAy := parsePoint(id, pubKeyA.Bytes())
	var pbAx, pbAy big.Int
	pbAx.SetBytes(pubkeyAx)
	pbAy.SetBytes(pubkeyAy)
	witness.PublicKey.A.X.Assign(pubkeyAx)
	witness.PublicKey.A.Y.Assign(pubkeyAy)

	sigRx, sigRy, sigS1, sigS2 := parseSignature(id, signatureA)
	witness.Signature.R.X.Assign(sigRx)
	witness.Signature.R.Y.Assign(sigRy)
	witness.Signature.S1.Assign(sigS1)
	witness.Signature.S2.Assign(sigS2)

	pubkeyAxt, pubkeyAyt := parsePoint(id, pubKeyB.Bytes())
	var pbAxt, pbAyt big.Int
	pbAxt.SetBytes(pubkeyAxt)
	pbAyt.SetBytes(pubkeyAyt)
	witness.PublicKeyB.A.X.Assign(pubkeyAxt)
	witness.PublicKeyB.A.Y.Assign(pubkeyAyt)

	// Generate Proof
	proof, err := groth16.Prove(r1cs, pk, &witness)

	//fmt.Println(proof)
	if err != nil {
		t.Fatal(err)
	}

	if vk == nil {

	}
	//Check with a correct value and it returns NIL
	var witnessCorrectValue bondCircuitv6

	witnessCorrectValue.Quote.Assign(92)

	pubkeyAxtt, pubkeyAytt := parsePoint(id, pubKeyA.Bytes())
	var pbAxtt, pbAytt big.Int
	pbAxtt.SetBytes(pubkeyAxtt)
	pbAytt.SetBytes(pubkeyAytt)
	witnessCorrectValue.PublicKey.A.X.Assign(pubkeyAxtt)
	witnessCorrectValue.PublicKey.A.Y.Assign(pubkeyAytt)

	pubkeyAxttt, pubkeyAyttt := parsePoint(id, pubKeyB.Bytes())
	var pbAxttt, pbAyttt big.Int
	pbAxttt.SetBytes(pubkeyAxttt)
	pbAyttt.SetBytes(pubkeyAyttt)
	witnessCorrectValue.PublicKeyB.A.X.Assign(pubkeyAxttt)
	witnessCorrectValue.PublicKeyB.A.Y.Assign(pubkeyAyttt)

	err = groth16.Verify(proof, vk, &witnessCorrectValue)
	if err != nil {
		fmt.Print(err)
	}
}
