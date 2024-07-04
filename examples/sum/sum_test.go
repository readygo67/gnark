package sha256

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"math/bits"
	"os"
	"runtime/debug"
	"testing"
	"time"
)

type SumCircuit struct {
	X []frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *SumCircuit) Define(api frontend.API) error {

	sum := api.Add(c.X[0], c.X[1], c.X[2:]...)
	api.AssertIsEqual(c.Y, sum)

	return nil
}

func TestSha256Circuit(t *testing.T) {
	debug.SetMaxStack(2000000000)
	assert := test.NewAssert(t)

	for i := 16; i < 21; i++ {
		l := 1 << i
		circuit := &SumCircuit{
			X: make([]frontend.Variable, l),
		}

		xs := make([]frontend.Variable, l)
		sum := 0
		for j := 0; j < l; j++ {
			xs[j] = frontend.Variable(j)
			sum += j
		}

		assignment := &SumCircuit{
			X: xs,
			Y: frontend.Variable(sum),
		}

		fmt.Printf("----------%v---------\n", i)
		// generate CompiledConstraintSystem
		compileStart := time.Now()
		fmt.Printf("compile start @%v...\n", compileStart)
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
		assert.NoError(err)
		fmt.Printf("nbConstraints:%v, nbWitness:%v, nbPublicWitness:%v, nbInternalVariables:%v\n", ccs.GetNbConstraints(), ccs.GetNbSecretVariables(), ccs.GetNbPublicVariables(), ccs.GetNbInternalVariables())
		witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		publicWitness, _ := witness.Public()
		assert.NoError(err)
		compileDuration := time.Since(compileStart)
		fmt.Printf("compile duration:%v\n", compileDuration)

		sizeSystem := ccs.GetNbConstraints() + ccs.GetNbPublicVariables()

		sizeLagrange := ecc.NextPowerOfTwo(uint64(sizeSystem))
		index := getPow2Index(sizeLagrange)
		srsFile := fmt.Sprintf("../aztec/bn254_pow_%v.srs", index)
		lSrsFile := fmt.Sprintf("../aztec/bn254_pow_%v.lsrs", index)
		fmt.Printf("srsFile:%v\n", srsFile)
		fsrs, err := os.Open(srsFile)
		assert.NoError(err)

		flsrs, err := os.Open(lSrsFile)
		assert.NoError(err)

		srs := kzg.NewSRS(ecc.BN254)
		_, err = srs.ReadFrom(fsrs)
		assert.NoError(err)

		srsLagrange := kzg.NewSRS(ecc.BN254)
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
