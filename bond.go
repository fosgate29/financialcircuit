package financial

import (
	"github.com/consensys/gnark-crypto/ecc"
	edwardsbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// PublicKey stores an eddsa public key (to be used in gnark circuit)
type PublicKeyParty = eddsa.PublicKey
type PublicKeyCounterparty = eddsa.PublicKey
type SignatureParty = eddsa.Signature
type SignatureCounterparty = eddsa.Signature

type eddsaCircuit struct {
	PublicKeyParty        PublicKeyParty        `gnark:",private"`
	PublicKeyCounterparty PublicKeyCounterparty `gnark:",private"`
	SignatureParty        SignatureParty        `gnark:",private"`
	SignatureCounterparty SignatureCounterparty `gnark:",private"`
	Message               frontend.Variable     `gnark:",public"` //hash
}

func parseSignature(id ecc.ID, buf []byte) ([]byte, []byte, []byte, []byte) {

	var pointbn254 edwardsbn254.PointAffine

	switch id {
	case ecc.BN254:
		pointbn254.SetBytes(buf[:32])
		a, b := parsePoint(id, buf)
		s1 := buf[32:48] // r is 256 bits, so s = 2^128*s1 + s2
		s2 := buf[48:]
		return a[:], b[:], s1, s2
	default:
		return buf, buf, buf, buf
	}
}

func parsePoint(id ecc.ID, buf []byte) ([]byte, []byte) {
	var pointbn254 edwardsbn254.PointAffine

	switch id {
	case ecc.BN254:
		pointbn254.SetBytes(buf[:32])
		a := pointbn254.X.Bytes()
		b := pointbn254.Y.Bytes()
		return a[:], b[:]
	default:
		return buf, buf
	}
}

func (circuit *eddsaCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	// verify the signature in the cs for Party
	circuit.PublicKeyParty.Curve = params
	eddsa.Verify(cs, circuit.SignatureParty, circuit.Message, circuit.PublicKeyParty)

	// verify the signature in the cs for Counterparty
	circuit.PublicKeyCounterparty.Curve = params
	eddsa.Verify(cs, circuit.SignatureCounterparty, circuit.Message, circuit.PublicKeyCounterparty)

	return nil
}
