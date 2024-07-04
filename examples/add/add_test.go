package add

import (
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"math/big"
	"os"
	"testing"
)

func TestCubic_Plonk_BN254(t *testing.T) {
	field := ecc.BN254.ScalarField()
	assert := test.NewAssert(t)
	var circuit Circuit
	assignment := &Circuit{
		X: 3,
		Y: 3,
	}

	ccs, err := frontend.Compile(field, scs.NewBuilder, &circuit)
	fmt.Printf("nbConstraints: %v,nbSecret: %v, nbPubVariables: %v, nbInternalVariables: %v\n", ccs.GetNbConstraints(), ccs.GetNbSecretVariables(), ccs.GetNbPublicVariables(), ccs.GetNbInternalVariables())
	assert.NoError(err)
	// NB! UNSAFE! Use MPC.
	srs, lsrs, err := unsafekzg.NewSRS(ccs, unsafekzg.WithTau(big.NewInt(5)))
	assert.NoError(err)

	pk, vk, err := native_plonk.Setup(ccs, srs, lsrs)
	assert.NoError(err)

	wit, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	proof, err := native_plonk.Prove(ccs, pk, wit)
	assert.NoError(err)
	pubWit, err := wit.Public()
	assert.NoError(err)
	err = native_plonk.Verify(proof, vk, pubWit)
	assert.NoError(err)

	f, err := os.Create("verifier.sol")
	assert.NoError(err)
	defer f.Close()

	err = vk.ExportSolidity(f)
	assert.NoError(err)

	bn254proof := proof.(*plonk_bn254.Proof)
	proofBytes := bn254proof.MarshalSolidity()
	fmt.Printf("proof: %v\n", hex.EncodeToString(proofBytes)) //在remix输入时需要手动添加0x

	//save public witness to file
	s, err := frontend.NewSchema(&circuit)
	assert.NoError(err)

	// serialize the vector to JSON
	data, err := pubWit.ToJSON(s)
	assert.NoError(err)

	fPublicWitness, err := os.Create("publicWitness.json")
	assert.NoError(err)
	defer fPublicWitness.Close()

	_, err = fPublicWitness.Write(data)
	assert.NoError(err)
}
