package financial

import (
	"github.com/consensys/gnark-crypto/ecc"
	edwardsbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// PublicKey stores an eddsa public key (to be used in gnark circuit)
//required to verify signatures in gnark
type PublicKey = eddsa.PublicKey
type Signature = eddsa.Signature

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

// this structure declares the public inputs and secrets keys
type bondCircuitv5 struct {
	//Accepted Bid 92.63 by the 2 parties prior to creating the circuit
	//Before the circuit is build the initiator knows  the responder whos bid was accepted
	AcceptedQuoteQuery  frontend.Variable `gnark:",public"`  // 92.63
	AcceptedQuoteSigned Signature         `gnark:",public"`  // to prevent spam
	PublicKeyCpt1       PublicKey         `gnark:",public"`  // Public key to check quotes signed - The reason for the public keys is to confirm who participated in providing quotes
	PublicKeyCpt2       PublicKey         `gnark:",public"`  // Public key to check quotes signed
	PublicKeyCpt3       PublicKey         `gnark:",public"`  // Public key to check quotes signed
	Bond                frontend.Variable `gnark:",public"`  // hash of Isin, Ticker and Size
	SignatureCpt1       Signature         `gnark:",private"` // Sign(quote)
	SignatureCpt2       Signature         `gnark:",private"` // Sign(quote)
	SignatureCpt3       Signature         `gnark:",private"` // Sign(quote)
	QuoteFromCpt1       frontend.Variable `gnark:",private"` // Example: 92.63
	QuoteFromCpt2       frontend.Variable `gnark:",private"` // Example: 92.40
	QuoteFromCpt3       frontend.Variable `gnark:",private"` // Example: 93
	AcceptedQuotePubKey PublicKey         `gnark:",private"` // It is going to be PublicKeyCpt1 or PublicKeyCpt2 or PublicKeyC
	AcceptedQuote       frontend.Variable `gnark:",private"` // ig: 92.63
	RejectedQuote1      frontend.Variable `gnark:",private"` // ig: 93 - Rejected quote order doesn't matter
	RejectedQuote2      frontend.Variable `gnark:",private"` // ig: 92.40
	BondQuoteSignedCpt1 Signature         `gnark:",private"` // Sign(Bond hash, quote)
	BondQuoteSignedCpt2 Signature         `gnark:",private"` // Sign(Bond hash, quote)
	BondQuoteSignedCpt3 Signature         `gnark:",private"` // Sign(Bond hash, quote)
}

func (circuit *bondCircuitv5) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	// Make sure Winner Quote is the smallest one or matching the bid
	cs.AssertIsLessOrEqual(circuit.AcceptedQuote, circuit.RejectedQuote1)
	cs.AssertIsLessOrEqual(circuit.AcceptedQuote, circuit.RejectedQuote2)
	cs.AssertIsEqual(circuit.AcceptedQuote, circuit.AcceptedQuoteQuery)

	// If winner quote is from Cpt1, Cpt2 or Cpt3, one of the subtraction is going to return zero
	// The circuit is build with all quotes received from responders
	subA := cs.Sub(circuit.QuoteFromCpt1, circuit.AcceptedQuote)
	subB := cs.Sub(circuit.QuoteFromCpt2, circuit.AcceptedQuote)
	subC := cs.Sub(circuit.QuoteFromCpt3, circuit.AcceptedQuote)

	outputA := cs.IsZero(subA, curveID) // 1 - iszero - true
	outputB := cs.IsZero(subB, curveID) // 0 false
	outputC := cs.IsZero(subC, curveID) // 0 false

	// outputA || outputB || outputC == 1
	result_temp := cs.Or(outputA, outputB)
	result := cs.Or(result_temp, outputC)

	one := cs.Constant(1)
	cs.AssertIsEqual(result, one)

	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}

	circuit.AcceptedQuotePubKey.Curve = params
	eddsa.Verify(cs, circuit.AcceptedQuoteSigned, circuit.AcceptedQuote, circuit.AcceptedQuotePubKey)

	// verify the signature in the cs for A,B,C
	circuit.PublicKeyCpt1.Curve = params
	eddsa.Verify(cs, circuit.SignatureCpt1, circuit.QuoteFromCpt1, circuit.PublicKeyCpt1)

	circuit.PublicKeyCpt2.Curve = params
	eddsa.Verify(cs, circuit.SignatureCpt2, circuit.QuoteFromCpt2, circuit.PublicKeyCpt2)

	circuit.PublicKeyCpt3.Curve = params
	eddsa.Verify(cs, circuit.SignatureCpt3, circuit.QuoteFromCpt3, circuit.PublicKeyCpt3)

	//check Isin + quote
	mimc, _ := mimc.NewMiMC("seed", curveID)
	IsinQuoteFromAHash := mimc.Hash(cs, circuit.Bond, circuit.QuoteFromCpt1)
	IsinQuoteFromBHash := mimc.Hash(cs, circuit.Bond, circuit.QuoteFromCpt2)
	IsinQuoteFromCHash := mimc.Hash(cs, circuit.Bond, circuit.QuoteFromCpt3)

	circuit.PublicKeyCpt1.Curve = params
	eddsa.Verify(cs, circuit.BondQuoteSignedCpt1, IsinQuoteFromAHash, circuit.PublicKeyCpt1)

	circuit.PublicKeyCpt2.Curve = params
	eddsa.Verify(cs, circuit.BondQuoteSignedCpt2, IsinQuoteFromBHash, circuit.PublicKeyCpt2)

	circuit.PublicKeyCpt3.Curve = params
	eddsa.Verify(cs, circuit.BondQuoteSignedCpt3, IsinQuoteFromCHash, circuit.PublicKeyCpt3)

	return nil
}
