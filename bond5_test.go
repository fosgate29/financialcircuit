package financial

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func TestBondv5(t *testing.T) {

	var circuit bondCircuitv5

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)

	fmt.Print((err))

	groth16.Setup(r1cs)
	//pk, vk, err := groth16.Setup(r1cs)
	//fmt.Print(pk)
	//fmt.Print(vk)
}
