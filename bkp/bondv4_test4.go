/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package financial

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func TestBondv4(t *testing.T) {

	var circuit bondCircuitv4

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)

	//var witness bondCircuitv4

	//witness.Quote.Assign(40)

	fmt.Print((err))

	groth16.Setup(r1cs)
	//pk, vk, err := groth16.Setup(r1cs)
	//fmt.Print(pk)
	//fmt.Print(vk)
}
