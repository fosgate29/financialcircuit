package financial

import (
	"bytes"
	"encoding/json"

	"github.com/consensys/gnark-crypto/hash"
	"github.com/shopspring/decimal"
)

type TestCase struct {
	quoteA         []byte
	quoteB         []byte
	quoteC         []byte
	winner         []byte
	isinTickerHash []byte
}

type Bond struct {
	Isin   string
	Size   string
	Ticker string
}

func createTestCases() [4]TestCase {

	toRet := [4]TestCase{}

	bond := &Bond{
		Isin:   "CA29250NAT24",
		Size:   "550000",
		Ticker: "ENB 5.375 27-Sep-2077",
	}

	// TODO - Quote A is always the winner, see how to change that
	toRet[0] = getQuotesValue(bond, "92.63", "92.63", "95")    //test case 1
	toRet[1] = getQuotesValue(bond, "91.71", "91.71", "91.71") // test case 2
	toRet[2] = getQuotesValue(bond, "0", "0", "0")
	toRet[3] = getQuotesValue(bond, "92.63", "92.63", "92.63")

	return toRet
}

func getQuotesValue(bond *Bond, quoteA string, quoteB string, quoteC string) TestCase {

	quote0, err := decimal.NewFromString(quoteA)
	quote1, err := decimal.NewFromString(quoteB)
	quote2, err := decimal.NewFromString(quoteC)
	if err != nil {
		panic(err)
	}

	one100 := decimal.NewFromInt(100)
	bondSize, err := decimal.NewFromString(bond.Size)

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

	var testCase TestCase
	testCase.quoteA = quote0.BigInt().Bytes()
	testCase.quoteB = quote1.BigInt().Bytes()
	testCase.quoteC = quote2.BigInt().Bytes()
	testCase.winner = quote0.BigInt().Bytes()

	reqBodyBytes := new(bytes.Buffer)
	json.NewEncoder(reqBodyBytes).Encode(bond)

	hashFunc := hash.MIMC_BN254

	goMimc := hashFunc.New("seed")
	goMimc.Write([]byte(reqBodyBytes.Bytes()))
	var IsinHash = goMimc.Sum(nil)
	testCase.isinTickerHash = IsinHash

	return testCase
}
