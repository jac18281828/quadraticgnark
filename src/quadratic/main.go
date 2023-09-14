package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// simple circuit
// a * a mod n == b mod n
type Circuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	A frontend.Variable `gnark:"a"`
	B frontend.Variable `gnark:"b,public"`
	N frontend.Variable `gnark:"n,public"`
}

func Mod(api frontend.API, a, n frontend.Variable) frontend.Variable {
	// q = a / n;
    // r = a - q * n;

	q := api.Div(a, n)
	m := api.Mul(q, n)
	res := api.Sub(a, m)

	return res
}

// Define declares the circuit constraints
// a * a mod n == b mod n
func (circuit *Circuit) Define(api frontend.API) error {
	// a*a
	x2modN := Mod(api, api.Mul(circuit.A, circuit.A), circuit.N)
	bmodN := Mod(api, circuit.B, circuit.N)
	api.AssertIsEqual(x2modN, bmodN)
	return nil
}

func main() {
	var quadraticCircuit Circuit
	r1cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &quadraticCircuit)
	if err != nil {
		return
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		return
	}

	/* // calculator safe test
	a:= new(big.Int)
	a.SetString("1529", 10);
	b:= new(big.Int)
	b.SetString("3878", 10);
	n:= new(big.Int)
	n.SetString("5879", 10);
	*/

	/* // weak encryption 256 bit
	a:= new(big.Int)
	a.SetString("105503353341635251739388807057048439745", 10);
	b:= new(big.Int)
	b.SetString("5906876347610788132374914526238871430", 10);
	n:= new(big.Int)
	n.SetString("142433102793350311139494996326894655391", 10);
	*/

	// strong encryption 1024 bit
	a:= new(big.Int)
	a.SetString("8316257881641021803582905045717248206056718946016883409345574565136922113375339185405930244923042687180817302566013120911495945967850843772303215152494233", 10);
	b:= new(big.Int)
	b.SetString("9872291329696295407337711770023368047044283358907128526510010117886524991212042657797091303026873836609390626022927092784183453775270320719649472866081175", 10);
	n:= new(big.Int)
	n.SetString("11827058731941270008765010504059650034033355481454192607091635073002083084605790970710373730279239889399395303258055587536080559285758863055719494590037407", 10);

	circuitParameters := &Circuit{
		A: a,
		B: b,
		N: n,
	}

	witness, _ := frontend.NewWitness(circuitParameters, ecc.BLS12_381.ScalarField())

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		return
	}

	publicParameters := &Circuit{
		B: b,
		N: n,
	}

	publicWitness, _ := frontend.NewWitness(publicParameters, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("verification failed\n")
		return
	}
	fmt.Printf("verification succeded\n")
}
