package financial

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// this structure declares the public inputs and secrets keys
type bondCircuitv6 struct {
	Signature  Signature         `gnark:",private"`
	PublicKeyB PublicKey         `gnark:",public"`
	PublicKey  PublicKey         `gnark:",public"`
	Quote      frontend.Variable `gnark:",public"`
}

func (circuit *bondCircuitv6) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	circuit.PublicKeyB.Curve = params
	eddsa.Verify(cs, circuit.Signature, circuit.Quote, circuit.PublicKeyB)

	return nil
}
