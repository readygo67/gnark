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

package mimc

import (
	"fmt"
	"github.com/consensys/gnark-crypto/hash"
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestPreimage(t *testing.T) {
	assert := test.NewAssert(t)

	for i := 0; i < 10; i++ {

		r := rand.Int63()
		fmt.Printf("r: %v\n", r)
		goMimc := hash.MIMC_BN254.New()
		goMimc.Write(big.NewInt(r).Bytes())
		h := goMimc.Sum(nil)
		err := test.IsSolved(&Circuit{}, &Circuit{
			PreImage: r,
			Hash:     h,
		}, ecc.BN254.ScalarField())
		assert.NoError(err)
	}
}
