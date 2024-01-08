package groth16_test

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

type InnerHashCircuit struct {
	Input  []uints.U8
	Output [32]uints.U8 `gnark:",public"`
}

func (c *InnerHashCircuit) Define(api frontend.API) error {
	h, err := sha2.New(api)
	if err != nil {
		return fmt.Errorf("new sha2: %w", err)
	}
	h.Write(c.Input[:])
	res := h.Sum()
	if len(res) != len(c.Output) {
		return fmt.Errorf("wrong digest size")
	}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return fmt.Errorf("new uints api: %w", err)
	}
	for i := range res {
		uapi.ByteAssertEq(res[i], c.Output[i])
	}
	return nil
}

func getInnerCircuit(field *big.Int, input []uints.U8, output [32]uints.U8) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof, error) {
	//make the compiler happy
	circuit := InnerHashCircuit{
		Input: make([]uints.U8, len(input)),
	}

	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	innerPK, innerVK, err := groth16.Setup(innerCcs)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// inner proof
	innerAssignment := &InnerHashCircuit{
		Input:  input,
		Output: output,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		return nil, nil, nil, nil, err
	}
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

func TestRecursiveHashCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	msg := []byte("hello, world")
	input := uints.NewU8Array(msg)
	digest := sha256.Sum256(msg)

	var output [32]uints.U8
	for i := range digest {
		output[i] = uints.NewU8(digest[i])
	}

	innerCcs, innerVK, innerPubWitness, innerProof, err := getInnerCircuit(ecc.BN254.ScalarField(), input, output)
	assert.NoError(err)
	// initialize the witness elements
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	assert.NoError(err)
	circuitPubWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](innerPubWitness)
	fmt.Printf("nbInnerPubWitness:%v, witness:%v\n", len(circuitPubWitness.Public), circuitPubWitness.Public)

	assert.NoError(err)
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	assert.NoError(err)

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
	fmt.Printf("outerWitness:%v\n", outerWitness.Vector())
	//assert.EqualValues(outerCcs.GetNbPublicVariables()-1, outerWitness.NbPublic())
	//assert.EqualValues(outerCcs.GetNbSecretVariables(), outerWitness.NbSecret())

	assert.NoError(err)
	// create public witness from the assignment
	outerPublicWitness, err := outerWitness.Public()
	assert.NoError(err)

	// create Groth16 setup. NB! UNSAFE
	outerPk, outerVk, err := groth16.Setup(outerCcs) // UNSAFE! Use MPC
	assert.NoError(err)

	/*
	  recursive_hash_test.go:306:
	        	Error Trace:	/Users/luokeep/Code/github.com/readygo67/gnark/std/recursion/groth16/recursive_hash_test.go:306
	        	Error:      	Received unexpected error:
	        	            	invalid witness size, got 512, expected 504
	        	Test:       	TestRecursiveHashCircuit
	*/
	// construct the groth16 proof of verifying Groth16 proof in-circuit
	outerProof, err := groth16.Prove(outerCcs, outerPk, outerWitness)
	assert.NoError(err)

	// verify the Groth16 proof
	err = groth16.Verify(outerProof, outerVk, outerPublicWitness)
	assert.NoError(err)

}
