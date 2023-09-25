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
}

// Define declares the circuit constraints
// a * a mod n == b mod n
func (circuit *Circuit) Define(api frontend.API) error {
	// a*a
	x2 := api.Mul(circuit.A, circuit.A)
	zero, _ := api.Compiler().ConstantValue(big.NewInt(0))
	// proof is trivial if a or b == 0
	api.AssertIsDifferent(x2, zero)
	api.AssertIsDifferent(circuit.B, zero)
	api.AssertIsEqual(x2, circuit.B)
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

	// 1024 bit
	a:= new(big.Int)
	a.SetString("178800966790051593920192922643770639842463081723895264399569408502030276897777945823935810034454120124866561298438574877728992316804450445738446831105202822097641746286927813123301642751171919521342991098705489892343220069575354287430800044268378927246855795753359644119735174090935499441410174889772507785999", 10);
	b:= new(big.Int)
	b.SetString("31969785725057132989721964005976347223369519615157747397574202476941528103285182961753802822487115018431906149722101536986425750224502585790182684993230886528895930699633017488648506791183045262707458228617634352807485707031843205639973167612436907950992651989350655896583894563950492327853783227024965220272748885336134812401910852803832109858059987749596362074373384168009809607367587838737985335899094141132651196283834287186800918408200363732173437785074615195795693378652781289016475584158237353466715471356191896093211275982315957272025569203342174390022691958263958458298537873960313165462319437651076780428001", 10);

	/*
	// calculator example
	a:= new(big.Int)
	a.SetString("2", 10);
	b:= new(big.Int)
	b.SetString("4", 10);
    */

	circuitParameters := &Circuit{
		A: a,
		B: b,
	}

	witness, _ := frontend.NewWitness(circuitParameters, ecc.BLS12_381.ScalarField())

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		return
	}

	publicParameters := &Circuit{
		B: b,
	}

	publicWitness, _ := frontend.NewWitness(publicParameters, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("verification failed\n")
		return
	}
	fmt.Printf("verification succeded\n")
}
