package sha256

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"math/bits"
	"os"
	"testing"
	"time"
)

type Sha256Circuit struct {
	Input  []uints.U8
	Output []uints.U8
}

func (c *Sha256Circuit) Define(api frontend.API) error {
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}

	hasher.Write(c.Input)
	output := hasher.Sum()

	for i := 0; i < 32; i++ {
		api.AssertIsEqual(output[i].Val, c.Output[i].Val)
	}

	return nil
}

func TestSha256Circuit(t *testing.T) {
	assert := test.NewAssert(t)
	msg := []byte("hello, world")
	h := sha256.Sum256(msg)

	inputVar := uints.NewU8Array(msg)
	outputVar := uints.NewU8Array(h[:])

	circuit := &Sha256Circuit{
		Input:  make([]uints.U8, len(inputVar)),
		Output: make([]uints.U8, len(outputVar)),
	}

	assignment := &Sha256Circuit{
		Input:  inputVar,
		Output: outputVar,
	}

	// generate CompiledConstraintSystem
	compileStart := time.Now()
	fmt.Printf("compile start @%v...\n", compileStart)
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
	assert.NoError(err)
	fmt.Printf("nbConstraints:%v, nbWitness:%v, nbPublicWitness:%v, nbInternalVariables:%v\n", ccs.GetNbConstraints(), ccs.GetNbSecretVariables(), ccs.GetNbPublicVariables(), ccs.GetNbInternalVariables())
	witness, _ := frontend.NewWitness(assignment, ecc.BLS12_377.ScalarField())
	publicWitness, _ := witness.Public()
	assert.NoError(err)
	compileDuration := time.Since(compileStart)
	fmt.Printf("compile duration:%v\n", compileDuration)

	sizeSystem := ccs.GetNbConstraints() + ccs.GetNbPublicVariables()

	sizeLagrange := ecc.NextPowerOfTwo(uint64(sizeSystem))
	index := getPow2Index(sizeLagrange)
	srsFile := fmt.Sprintf("bls12377_pow_%v.srs", index)
	lSrsFile := fmt.Sprintf("bls12377_pow_%v.lsrs", index)

	fsrs, err := os.Open(srsFile)
	assert.NoError(err)

	flsrs, err := os.Open(lSrsFile)
	assert.NoError(err)

	srs := kzg.NewSRS(ecc.BLS12_377)
	_, err = srs.ReadFrom(fsrs)
	assert.NoError(err)

	srsLagrange := kzg.NewSRS(ecc.BLS12_377)
	_, err = srsLagrange.ReadFrom(flsrs)
	assert.NoError(err)

	setupStart := time.Now()
	fmt.Printf("setup start@%v...\n", setupStart)
	pk, vk, err := native_plonk.Setup(ccs, srs, srsLagrange)
	assert.NoError(err)
	setupDuration := time.Since(setupStart)
	fmt.Printf("setup duration:%v\n", setupDuration)

	proveStart := time.Now()
	fmt.Printf("prove start@%v...\n", proveStart)
	proof, err := native_plonk.Prove(ccs, pk, witness)
	assert.NoError(err)
	proveDuration := time.Since(proveStart)
	fmt.Printf("prove duration:%v\n", proveDuration)

	verifyStart := time.Now()
	fmt.Printf("verify start@%v...\n", verifyStart)
	err = native_plonk.Verify(proof, vk, publicWitness)
	assert.NoError(err)
	verifyDuration := time.Since(verifyStart)
	fmt.Printf("verify duration : %v\n", verifyDuration)
}

// n must be 2^k
func getPow2Index(n uint64) int {
	c := bits.OnesCount64(n)
	if c != 1 {
		panic("n must be 2^k")
	}

	t := bits.LeadingZeros64(n)
	if t == 0 {
		panic("next power of 2 overflows uint64")
	}
	return 63 - t
}
