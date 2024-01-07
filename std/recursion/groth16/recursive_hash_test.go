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

func TestInnerHashCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	msg := []byte("hello, world")
	input := uints.NewU8Array(msg)
	digest := sha256.Sum256(msg)

	var output [32]uints.U8
	for i := range digest {
		output[i] = uints.NewU8(digest[i])
	}

	//实例化CubicCircuit
	c := InnerHashCircuit{
		Input:  input,
		Output: output,
	}

	witness, err := frontend.NewWitness(&c, ecc.BN254.ScalarField())
	instance, err := witness.Public()

	//make the compiler happy
	circuit := InnerHashCircuit{
		Input: make([]uints.U8, len(input)),
	}

	// compile a circuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
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

func TestGetInnerCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	msg := []byte("hello, world")
	input := uints.NewU8Array(msg)
	digest := sha256.Sum256(msg)

	var output [32]uints.U8
	for i := range digest {
		output[i] = uints.NewU8(digest[i])
	}

	_, _, _, _, err := getInnerCircuit(ecc.BN254.ScalarField(), input, output)
	assert.NoError(err)
}

func TestHashBN254InBN254(t *testing.T) {
	assert := test.NewAssert(t)
	msg := []byte("hello, world")
	input := uints.NewU8Array(msg)
	digest := sha256.Sum256(msg)

	var output [32]uints.U8
	for i := range digest {
		output[i] = uints.NewU8(digest[i])
	}

	innerCcs, innerVK, innerWitness, innerProof, err := getInnerCircuit(ecc.BN254.ScalarField(), input, output)
	assert.NoError(err)

	// initialize the witness elements
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	if err != nil {
		panic(err)
	}
	circuitWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](innerWitness)
	if err != nil {
		panic(err)
	}
	circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof)
	if err != nil {
		panic(err)
	}

	outerAssignment := &OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		InnerWitness: circuitWitness,
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

	// compile the outer circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outerCircuit)
	if err != nil {
		panic("compile failed: " + err.Error())
	}

	// create Groth16 setup. NB! UNSAFE
	pk, vk, err := groth16.Setup(ccs) // UNSAFE! Use MPC
	if err != nil {
		panic("setup failed: " + err.Error())
	}

	// create prover witness from the assignment
	secretWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		panic("secret witness failed: " + err.Error())
	}

	// create public witness from the assignment
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic("public witness failed: " + err.Error())
	}

	// construct the groth16 proof of verifying Groth16 proof in-circuit
	outerProof, err := groth16.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic("proving failed: " + err.Error())
	}

	// verify the Groth16 proof
	err = groth16.Verify(outerProof, vk, publicWitness)
	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
}

//@@@@@Keep sync with backend/witness/witness.go

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

	numConstraints := innerCcs.GetNbConstraints()
	numWitness := innerCcs.GetNbSecretVariables()
	numInstance := innerCcs.GetNbPublicVariables()
	fmt.Printf("inner Circuit numConstraints:%v, numWitness:%v, numInstance:%v\n", numConstraints, numWitness, numInstance)

	// initialize the witness elements
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVK)
	assert.NoError(err)
	circuitPubWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](innerPubWitness)
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

	// compile the outer circuit
	outerCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outerCircuit)

	// create Groth16 setup. NB! UNSAFE
	outerPk, outerVk, err := groth16.Setup(outerCcs) // UNSAFE! Use MPC
	assert.NoError(err)

	// create prover witness from the assignment
	outerWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	// create public witness from the assignment
	outerPublicWitness, err := outerWitness.Public()
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

	numConstraints = outerCcs.GetNbConstraints()
	numWitness = outerCcs.GetNbSecretVariables()
	numInstance = outerCcs.GetNbPublicVariables()
	fmt.Printf("outer Circuit numConstraints:%v, numWitness:%v, numInstance:%v\n", numConstraints, numWitness, numInstance)
}
