// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cubic

import (
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/stretchr/testify/assert"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark/test"
)

func TestCubicEquation(t *testing.T) {
	assert := test.NewAssert(t)

	var cubicCircuit Circuit

	assert.ProverFailed(&cubicCircuit, &Circuit{
		X: 42,
		Y: 42,
	})

	assert.ProverSucceeded(&cubicCircuit, &Circuit{
		X: 3,
		Y: 35,
	})
}
func TestCubic_Plonk_BN254(t *testing.T) {
	field := ecc.BN254.ScalarField()
	assert := test.NewAssert(t)
	var circuit Circuit
	assignment := &Circuit{
		X: 3,
		Y: 35,
	}

	ccs, err := frontend.Compile(field, scs.NewBuilder, &circuit)
	fmt.Printf("nbConstraints: %v\n", ccs.GetNbConstraints())
	assert.NoError(err)
	// NB! UNSAFE! Use MPC.
	srs, lsrs, err := unsafekzg.NewSRS(ccs, unsafekzg.WithTau(big.NewInt(5)))
	assert.NoError(err)

	pk, vk, err := native_plonk.Setup(ccs, srs, lsrs)
	assert.NoError(err)

	//wit 中
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

//	type Circuit struct {
//		// struct tags on a variable is optional
//		// default uses variable name and secret visibility.
//		X frontend.Variable `gnark:"x"`
//		Y frontend.Variable `gnark:",public"`
//	}
func TestCubic_GROTH16_BLS12381(t *testing.T) {
	field := ecc.BLS12_381.ScalarField()
	assert := test.NewAssert(t)
	var circuit Circuit

	for i := 0; i < 100; i++ {

		assignment := &Circuit{
			X: i,
			Y: i*i*i + i + 5,
		}

		ccs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
		assert.NoError(err)
		// NB! UNSAFE! Use MPC.

		pk, vk, err := groth16.Setup(ccs)
		assert.NoError(err)

		wit, err := frontend.NewWitness(assignment, field)
		assert.NoError(err)
		proof, err := groth16.Prove(ccs, pk, wit)
		assert.NoError(err)
		pubWit, err := wit.Public()
		assert.NoError(err)
		err = groth16.Verify(proof, vk, pubWit)
		assert.NoError(err)
	}
}

// 验证G1s = [G1, alpha*G1, alpha^2*G1, alpha^3*G1, ...]
// 1 = [12436184717236109307 3962172157175319849 7381016538464732718 1011752739694698287]
// 5 = [1949230679015292902 16913946402569752895 5177146667339417225 1571765431670520771]
// G1Generator = {X:[15230403791020821917 754611498739239741 7381016538464732716 1011752739694698287] Y:[12014063508332092218 1509222997478479483 14762033076929465432 2023505479389396574]}
// G2Generator = X:{A0:[10269251484633538598 15918845024527909234 18138289588161026783 1825990028691918907] A1:[12660871435976991040 6936631231174072516 714191060563144582 1512910971262892907]} Y:{A0:[7034053747528165878 18338607757778656120 18419188534790028798 2953656481336934918] A1:[7208393106848765678 15877432936589245627 6195041853444001910 983087530859390082]}}
func TestG1s(t *testing.T) {
	_, _, gen1Aff, gen2Aff := bn254.Generators()
	size := 8

	var alpha fr.Element
	alphaBig := big.NewInt(5)
	alpha.SetBigInt(alphaBig)

	//
	alphas := make([]fr.Element, size)
	alphas[0] = fr.One()
	for i := 1; i < len(alphas); i++ {
		alphas[i].Mul(&alphas[i-1], &alpha)
	}

	for i := 0; i < len(alphas); i++ {
		fmt.Printf("alpha val: %v\n", alphas[i].Uint64())
	}
	fmt.Printf("alphas: %+v\n", alphas)

	{ //检查相邻alpha 的商是alpha。
		quotients := make([]fr.Element, size-1)
		for i := 0; i < len(quotients); i++ {
			quotients[i].Div(&alphas[i+1], &alphas[i])
		}

		for i := 1; i < len(quotients); i++ {
			assert.True(t, quotients[0].Equal(&quotients[i]))
		}
	}

	g1s := make([]bn254.G1Affine, size)
	g1s[0] = gen1Aff
	_alphaBig := alphaBig
	for i := 1; i < len(g1s); i++ {
		g1s[i].ScalarMultiplication(&gen1Aff, _alphaBig)
		_alphaBig = big.NewInt(0).Mul(_alphaBig, alphaBig)
	}
	_g1s := bn254.BatchScalarMultiplicationG1(&gen1Aff, alphas)
	fmt.Printf("g1s: %+v\n", g1s)
	fmt.Printf("g1s: %+v\n", _g1s)
	//g1s = append(gen1Aff, g1s)

	alphaG2 := bn254.G2Affine{}
	alphaG2.ScalarMultiplication(&gen2Aff, alphaBig)
	fmt.Printf("G2:%+v, alphaG2: %+v\n", gen2Aff, alphaG2)

}
