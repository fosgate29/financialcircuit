package financial

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"

	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func TestBondv2(t *testing.T) {

	//setup signature parameters
	signature.Register(signature.EDDSA_BN254, eddsabn254.GenerateKeyInterfaces)

	// Create a private/pub key to sign
	hFunc := hash.MIMC_BN254.New("seed")
	src := rand.NewSource(0)
	r := rand.New(src)

	privKeyParty, err := signature.EDDSA_BN254.New(r)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyParty := privKeyParty.Public()

	rCounterparty := rand.New(src)

	privKeyCounterparty, err := signature.EDDSA_BN254.New(rCounterparty)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyCounterparty := privKeyCounterparty.Public()

	//get bond information from a file
	jsonFile, err := os.Open("bond.json")
	if err != nil {
		fmt.Println(err)
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)

	// create Bond var using data from file
	var bonds Bonds
	json.Unmarshal(byteValue, &bonds)
	bondStruct := bonds.Bonds[0]

	//hash Bond struct to sign later
	msgBin := getMessageHash(bondStruct)

	// generate signature
	signatureParty, err := privKeyParty.Sign(msgBin[:], hFunc)
	if err != nil {
		t.Fatal(err)
	}

	signatureCounterparty, err := privKeyCounterparty.Sign(msgBin[:], hFunc)
	if err != nil {
		t.Fatal(err)
	}

	id := ecc.BN254

	// create and compile the circuit for signature verification
	var circuit bondCircuitv3

	r1cs, err := frontend.Compile(id, backend.GROTH16, &circuit) //returns a math equation
	if err != nil {
		t.Fatal(err)
	}

	{
		var witness bondCircuitv3

		//set Bond information in the circuit
		//witness.Isin.Assign(bondStruct.Isin)
		//witness.Ticker.Assign(bondStruct.Ticker)
		//		witness.Yield.Assign(bondStruct.Yield)
		witness.Size.Assign(bondStruct.Size)
		witness.Party.Assign(bondStruct.Party)
		//		witness.Counterparty.Assign(bondStruct.Counterparty)

		//set the hash in the circuit
		witness.Bondhash.Assign(msgBin)

		pubkeyAx, pubkeyAy := parsePoint(id, pubKeyParty.Bytes())
		var pbAx, pbAy big.Int
		pbAx.SetBytes(pubkeyAx)
		pbAy.SetBytes(pubkeyAy)
		witness.PublicKeyParty.A.X.Assign(pubkeyAx)
		witness.PublicKeyParty.A.Y.Assign(pubkeyAy)

		sigRx, sigRy, sigS1, sigS2 := parseSignature(id, signatureParty)
		witness.SignatureParty.R.X.Assign(sigRx)
		witness.SignatureParty.R.Y.Assign(sigRy)
		witness.SignatureParty.S1.Assign(sigS1)
		witness.SignatureParty.S2.Assign(sigS2)

		pubkeyCounterpartyAx, pubkeyCounterpartyAy := parsePoint(id, pubKeyCounterparty.Bytes())
		var pbCounterpartyAx, pbCounterpartyAy big.Int
		pbCounterpartyAx.SetBytes(pubkeyCounterpartyAx)
		pbCounterpartyAy.SetBytes(pubkeyCounterpartyAy)
		witness.PublicKeyCounterparty.A.X.Assign(pubkeyCounterpartyAx)
		witness.PublicKeyCounterparty.A.Y.Assign(pubkeyCounterpartyAy)

		sigCounterpartyRx, sigCounterpartyRy, sigCounterpartyS1, sigCounterpartyS2 := parseSignature(id, signatureCounterparty)
		witness.SignatureCounterparty.R.X.Assign(sigCounterpartyRx)
		witness.SignatureCounterparty.R.Y.Assign(sigCounterpartyRy)
		witness.SignatureCounterparty.S1.Assign(sigCounterpartyS1)
		witness.SignatureCounterparty.S2.Assign(sigCounterpartyS2)

		pk, vk, err := groth16.Setup(r1cs)

		if err != nil {
			t.Fatal(err)
		}

		/*	fmt.Println(witness.Isin)
			fmt.Println(witness.Ticker)
			fmt.Println(witness.Yield)*/
		fmt.Println(witness.Size)
		/*	fmt.Println(witness.Party)
			fmt.Println(witness.Counterparty)*/
		fmt.Println(witness.Bondhash)
		//proof can be sent to the blockchain
		proof, err := groth16.Prove(r1cs, pk, &witness)

		fmt.Println(proof)
		if err != nil {
			t.Fatal(err)
		}

		// verify the proof
		var witnessPublic bondCircuitv3
		/*	witnessPublic.Isin.Assign(bondStruct.Isin)
			witnessPublic.Ticker.Assign(bondStruct.Ticker)
			witnessPublic.Yield.Assign(bondStruct.Yield)
			witnessPublic.Size.Assign(bondStruct.Size)*/

		//smart contract is going to receive proof and witness  (hash message)
		//smart contract already has the vk, which was generate in the setup
		//and doesn't change.
		//for each bond we have one witness (one hash) and one proof. vk is always the same
		err = groth16.Verify(proof, vk, &witnessPublic)
		if err != nil {
			// invalid proof
		}
	}

	// verification with incorrect Message/*
	/*	{
		var witness eddsaCircuit
		witness.Message.Assign("44717650746155748460101257525078853138837311576962212923649547644148297035979")

		pubkeyAx, pubkeyAy := parsePoint(id, pubKey.Bytes())
		witness.PublicKey.A.X.Assign(pubkeyAx)
		witness.PublicKey.A.Y.Assign(pubkeyAy)

		sigRx, sigRy, sigS1, sigS2 := parseSignature(id, signature)
		witness.Signature.R.X.Assign(sigRx)
		witness.Signature.R.Y.Assign(sigRy)
		witness.Signature.S1.Assign(sigS1)
		witness.Signature.S2.Assign(sigS2)

		assert.SolvingFailed(r1cs, &witness)
	}*/

}
