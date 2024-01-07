package groth16_test

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

type InnerCubicCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

// x**3 + 2*x + 5 == y
func (c *InnerCubicCircuit) Define(api frontend.API) error {
	xCubic := api.Mul(c.X, c.X, c.X)
	api.AssertIsEqual(c.Y, api.Add(xCubic, c.X, 5))
	return nil
}

//
//type OuterHashCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
//	Proof        stdgroth16.Proof[G1El, G2El]
//	VerifyingKey stdgroth16.VerifyingKey[G1El, G2El, GtEl]
//	InnerWitness stdgroth16.Witness[FR]
//}
//
//func (c *OuterHashCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
//	curve, err := algebra.GetCurve[FR, G1El](api)
//	if err != nil {
//		return fmt.Errorf("new curve: %w", err)
//	}
//	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
//	if err != nil {
//		return fmt.Errorf("get pairing: %w", err)
//	}
//	verifier := stdgroth16.NewVerifier(curve, pairing)
//	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
//	return err
//}

func TestInnerCubicCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit InnerCubicCircuit

	//实例化CubicCircuit
	c := InnerCubicCircuit{
		X: 3,
		Y: 35,
	}
	//分析赋值电路实际的witness, witness是用fr.Element表示的电路实际输入，这里为3和5
	witness, err := frontend.NewWitness(&c, ecc.BN254.ScalarField())
	nbSecret := witness.NbSecret()
	nbPublic := witness.NbPublic()
	fmt.Printf("nbWitness:%v, witness:%v\n", nbSecret+nbPublic, witness.Vector()) //打印所有的witness

	instance, err := witness.Public()
	fmt.Printf("nbPublic:%v, publicWitness:%v\n", nbPublic, instance.Vector()) //

	// compile a circuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	fmt.Printf("r1cs, nbPublic(including \"1\"):%v, nbSecret:%v, nbInternal:%v\n", r1cs.GetNbPublicVariables(), r1cs.GetNbSecretVariables(), r1cs.GetNbInternalVariables())
	assert.NoError(err)

	pk, vk, err := groth16.Setup(r1cs)
	assert.NoError(err)

	proof, err := groth16.Prove(r1cs, pk, witness)
	//fmt.Printf("proof:%v\n", proof)
	assert.NoError(err)

	err = groth16.Verify(proof, vk, instance)
	assert.NoError(err)

	numConstraints := r1cs.GetNbConstraints()
	numWitness := r1cs.GetNbSecretVariables()
	numInstance := r1cs.GetNbPublicVariables()
	fmt.Printf("numConstraints:%v, numWitness:%v, numInstance:%v\n", numConstraints, numWitness, numInstance)
}

func getInnerCubicCircuit(field *big.Int, x, y frontend.Variable) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof, error) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &InnerCubicCircuit{})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	fmt.Printf("r1cs, nbPublic(including \"1\"):%v, nbSecret:%v, nbInternal:%v\n", innerCcs.GetNbPublicVariables(), innerCcs.GetNbSecretVariables(), innerCcs.GetNbInternalVariables())
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// inner proof
	innerAssignment := &InnerCubicCircuit{
		X: x,
		Y: y,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	nbSecret := innerWitness.NbSecret()
	nbPublic := innerWitness.NbPublic()
	fmt.Printf("nbWitness:%v, witness:%v\n", nbSecret+nbPublic, innerWitness.Vector()) //打印所有的witness

	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	err = groth16.Verify(innerProof, innerVK, innerPubWitness)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return innerCcs, innerVK, innerPubWitness, innerProof, nil
}

func TestGetInnerCubicCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, _, _, err := getInnerCubicCircuit(ecc.BN254.ScalarField(), 3, 35)
	assert.NoError(err)
}

func TestRecursiveCubicCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	innerCcs, innerVK, innerPubWitness, innerProof, err := getInnerCubicCircuit(ecc.BN254.ScalarField(), 3, 35)
	assert.NoError(err)

	// initialize the witness elements
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	assert.NoError(err)
	circuitPubWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](innerPubWitness)
	fmt.Printf("nbInnerPubWitness:%v, witness:%v\n", len(circuitPubWitness.Public), circuitPubWitness.Public)

	assert.NoError(err)
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

	/*
		// k = innerCircuitPublicVariable(inlcuding "1")
		//InnerWitness的secret数量 = 4*(k-1)
		//Proof的secret数量 = 32
		//VerifyingKey的secret的数量 = 80 + 8*k
		// 当k=2时， outerCircuit secret的数量为 112+16+4 = 132
		// 当k=33时(对应hash的32byte + 1)，outerCircuit secret的数量为 112+12*33-4 = 504
	*/
	outerAssignment := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitPubWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}

	// the witness size depends on the number of public variables. We use the
	// compiled inner circuit to deduce the required size for the outer witness
	// using functions [stdgroth16.PlaceholderWitness] and
	// [stdgroth16.PlaceholderVerifyingKey]
	outerCircuit := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs),
		VerifyingKey: stdgroth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerCcs),
	}
	fmt.Printf("outerCircuit, nbPublic:%v\n", len(outerCircuit.InnerWitness.Public))
	// compile the outer circuit
	outerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outerCircuit)
	fmt.Printf("outerCcs, nbPublic(including \"1\"):%v, nbSecret:%v, nbInternal:%v\n", outerCcs.GetNbPublicVariables(), outerCcs.GetNbSecretVariables(), outerCcs.GetNbInternalVariables())

	// create prover witness from the assignment
	outerWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	fmt.Printf("outerWitness, nbPublic:%v, nbSecret:%v\n", outerWitness.NbPublic(), outerWitness.NbSecret())
	assert.NoError(err)
	// create public witness from the assignment
	outerPublicWitness, err := outerWitness.Public()
	assert.NoError(err)

	// create Groth16 setup. NB! UNSAFE
	outerPk, outerVk, err := groth16.Setup(outerCcs) // UNSAFE! Use MPC
	assert.NoError(err)

	// construct the groth16 proof of verifying Groth16 proof in-circuit
	outerProof, err := groth16.Prove(outerCcs, outerPk, outerWitness)
	assert.NoError(err)

	// verify the Groth16 proof
	err = groth16.Verify(outerProof, outerVk, outerPublicWitness)
	assert.NoError(err)
}
