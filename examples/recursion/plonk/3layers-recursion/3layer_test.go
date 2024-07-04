package _layers_recursion

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"math/big"
	"testing"
	"time"
)

// InnerCircuitNative is the definition of the inner circuit we want to
// recursively verify inside an outer circuit. The circuit proves the knowledge
// of a factorisation of a semiprime.
type InnerCircuitNative struct {
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
}

// x**3 + x + 5 == y
func (c *InnerCircuitNative) Define(api frontend.API) error {
	x3 := api.Mul(c.X, c.X, c.X)
	api.AssertIsEqual(c.Y, api.Add(x3, c.X, 5))
	return nil
}

func computeInnerProof(field, outer *big.Int) (constraint.ConstraintSystem, native_plonk.VerifyingKey, witness.Witness, native_plonk.Proof) {
	innerCcs, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitNative{})
	if err != nil {
		panic(err)
	}
	// NB! UNSAFE! Use MPC.
	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)
	if err != nil {
		panic(err)
	}

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	// inner proof
	innerAssignment := &InnerCircuitNative{
		X: 3,
		Y: 35,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		panic(err)
	}
	innerProof, err := native_plonk.Prove(innerCcs, innerPK, innerWitness, plonk.GetNativeProverOptions(outer, field))
	if err != nil {
		panic(err)
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		panic(err)
	}
	err = native_plonk.Verify(innerProof, innerVK, innerPubWitness, plonk.GetNativeVerifierOptions(outer, field))
	if err != nil {
		panic(err)
	}
	return innerCcs, innerVK, innerPubWitness, innerProof
}

type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        plonk.Proof[FR, G1El, G2El]
	VerifyingKey plonk.VerifyingKey[FR, G1El, G2El] `gnark:"-"` // constant verification key
	InnerWitness plonk.Witness[FR]                  `gnark:",public"`
}

func (c *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	return err
}

func TestCubicRecursion_Simulated_BLS12377_BW6761_BLS12377(t *testing.T) {
	assert := test.NewAssert(t)
	innerField := ecc.BLS12_377.ScalarField()
	outer1Field := ecc.BW6_761.ScalarField()
	outer2Field := ecc.BLS12_377.ScalarField()
	innerCcs, innerVK, innerWitness, innerProof := computeInnerProof(innerField, outer1Field)
	fmt.Printf("inner Ccs nbConstraints:%v, nbSecretWitness:%v, nbPublicInstance:%v\n", innerCcs.GetNbConstraints(), innerCcs.GetNbSecretVariables(), innerCcs.GetNbPublicVariables())
	// initialize the witness elements
	circuit1Vk, err := plonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	assert.NoError(err)
	circuit1Witness, err := plonk.ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuit1Proof, err := plonk.ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outer1Circuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: plonk.PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		Proof:        plonk.PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
		VerifyingKey: circuit1Vk,
	}
	outer1Assignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuit1Witness,
		Proof:        circuit1Proof,
	}

	// compile the outer circuit
	fmt.Printf("compile outer1 start...\n")
	compileOuter1Start := time.Now()
	outer1CCS, err := frontend.Compile(outer1Field, scs.NewBuilder, outer1Circuit)
	if err != nil {
		panic("compile failed: " + err.Error())
	}
	compileOuter1Duration := time.Since(compileOuter1Start)
	fmt.Printf("compile outer1 duration:%v\n", compileOuter1Duration)
	fmt.Printf("outer1 Ccs nbConstraints:%v, nbSecretWitness:%v, nbPublicInstance:%v\n", outer1CCS.GetNbConstraints(), outer1CCS.GetNbSecretVariables(), outer1CCS.GetNbPublicVariables())

	// NB! UNSAFE! Use MPC.
	fmt.Printf("generate start srs for outer1 circuit...\n")
	generateOuter1SRSStart := time.Now()
	outer1SRS, outer1SRSLagrange, err := unsafekzg.NewSRS(outer1CCS)
	assert.NoError(err)
	generateOuter1SRSDuration := time.Since(generateOuter1SRSStart)
	fmt.Printf("generate outer1 srs duration:%v\n", generateOuter1SRSDuration)

	// create PLONK setup. NB! UNSAFE
	fmt.Printf("setup outer1 start...\n")
	setupOuter1Start := time.Now()
	outer1PK, outer1VK, err := native_plonk.Setup(outer1CCS, outer1SRS, outer1SRSLagrange) // UNSAFE! Use MPC
	assert.NoError(err)
	setupOuter1Duration := time.Since(setupOuter1Start)
	fmt.Printf("setup outer1 duration:%v\n", setupOuter1Duration)

	// create prover witness from the assignment
	outer1SecretWitness, err := frontend.NewWitness(outer1Assignment, outer1Field)
	assert.NoError(err)
	// create public witness from the assignment
	outer1PublicWitness, err := outer1SecretWitness.Public()
	assert.NoError(err)

	// construct the PLONK proof of verifying PLONK proof in-circuit
	fmt.Printf("prove outer1 start...\n")
	proveOuter1Start := time.Now()
	outer1Proof, err := native_plonk.Prove(outer1CCS, outer1PK, outer1SecretWitness, plonk.GetNativeProverOptions(outer2Field, outer1Field))
	assert.NoError(err)
	proveOuter1Duration := time.Since(proveOuter1Start)
	fmt.Printf("prove outer1 duration:%v\n", proveOuter1Duration)

	// verify the PLONK proof
	fmt.Printf("verify outer1 start...\n")
	verifyOuter1Start := time.Now()
	err = native_plonk.Verify(outer1Proof, outer1VK, outer1PublicWitness, plonk.GetNativeVerifierOptions(outer2Field, outer1Field))
	assert.NoError(err)
	verifyOuter1Duration := time.Since(verifyOuter1Start)
	fmt.Printf("verify outer1 duration:%v\n", verifyOuter1Duration)

	//outer2
	fmt.Printf("-------------------outer2---------------------\n")
	circuit2Vk, err := plonk.ValueOfVerifyingKey[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](outer1VK)
	assert.NoError(err)
	circuit2Witness, err := plonk.ValueOfWitness[sw_bw6761.ScalarField](outer1PublicWitness)
	assert.NoError(err)
	circuit2Proof, err := plonk.ValueOfProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](outer1Proof)
	assert.NoError(err)

	outer2Circuit := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: plonk.PlaceholderWitness[sw_bw6761.ScalarField](outer1CCS),
		Proof:        plonk.PlaceholderProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](outer1CCS),
		VerifyingKey: circuit2Vk,
	}
	outer2Assignment := &OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		InnerWitness: circuit2Witness,
		Proof:        circuit2Proof,
	}

	fmt.Printf("compile outer2 start...\n")
	compileOuter2Start := time.Now()
	outer2CCS, err := frontend.Compile(outer2Field, scs.NewBuilder, outer2Circuit)
	if err != nil {
		panic("compile failed: " + err.Error())
	}
	compileOuter2Duration := time.Since(compileOuter2Start)
	fmt.Printf("compile outer2 duration:%v\n", compileOuter2Duration)
	fmt.Printf("outer2 Ccs nbConstraints:%v, nbSecretWitness:%v, nbPublicInstance:%v\n", outer2CCS.GetNbConstraints(), outer2CCS.GetNbSecretVariables(), outer2CCS.GetNbPublicVariables())

	// NB! UNSAFE! Use MPC.
	fmt.Printf("generate start srs for outer2 circuit...\n")
	generateOuter2SRSStart := time.Now()
	outer2SRS, outer2SRSLagrange, err := unsafekzg.NewSRS(outer2CCS)
	assert.NoError(err)
	generateOuter2SRSDuration := time.Since(generateOuter2SRSStart)
	fmt.Printf("generate outer2 srs duration:%v\n", generateOuter2SRSDuration)

	// create PLONK setup. NB! UNSAFE
	fmt.Printf("setup outer2 start...\n")
	setupOuter2Start := time.Now()
	outer2PK, outer2VK, err := native_plonk.Setup(outer2CCS, outer2SRS, outer2SRSLagrange) // UNSAFE! Use MPC
	assert.NoError(err)
	setupOuter2Duration := time.Since(setupOuter2Start)
	fmt.Printf("setup outer2 duration:%v\n", setupOuter2Duration)

	// create prover witness from the assignment
	outer2SecretWitness, err := frontend.NewWitness(outer2Assignment, outer2Field)
	assert.NoError(err)
	// create public witness from the assignment
	outer2PublicWitness, err := outer2SecretWitness.Public()
	assert.NoError(err)

	// construct the PLONK proof of verifying PLONK proof in-circuit
	fmt.Printf("prove outer2 start...\n")
	proveOuter2Start := time.Now()
	outer2Proof, err := native_plonk.Prove(outer2CCS, outer2PK, outer2SecretWitness)
	assert.NoError(err)
	proveOuter2Duration := time.Since(proveOuter2Start)
	fmt.Printf("prove outer2 duration:%v\n", proveOuter2Duration)

	// verify the PLONK proof
	fmt.Printf("verify outer2 start...\n")
	verifyOuter2Start := time.Now()
	err = native_plonk.Verify(outer2Proof, outer2VK, outer2PublicWitness)
	assert.NoError(err)
	verifyOuter2Duration := time.Since(verifyOuter2Start)
	fmt.Printf("verify outer2 duration:%v\n", verifyOuter2Duration)
}
