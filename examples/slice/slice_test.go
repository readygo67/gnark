package slice

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"testing"
)

type BalancesCircuit struct {
	InitialBalances []frontend.Variable
	FinalBalances   []frontend.Variable
	TransferAmounts []frontend.Variable
}

func (circuits *BalancesCircuit) Define(api frontend.API) error {
	for i, _ := range circuits.InitialBalances {
		api.AssertIsEqual(circuits.FinalBalances[i], api.Sub(circuits.InitialBalances[i], circuits.TransferAmounts[i]))
	}
	return nil
}

func TestBalanceCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit BalancesCircuit

	//Must Specify the length of the slices here
	circuit.InitialBalances = make([]frontend.Variable, 5)
	circuit.FinalBalances = make([]frontend.Variable, 5)
	circuit.TransferAmounts = make([]frontend.Variable, 5)

	assignment := &BalancesCircuit{
		InitialBalances: []frontend.Variable{100, 200, 300, 400, 500},
		FinalBalances:   []frontend.Variable{90, 180, 270, 360, 450},
		TransferAmounts: []frontend.Variable{10, 20, 30, 40, 50},
	}

	err := test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	//Different slice length result different nbConstraints number, different nbConstraints number means different circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	fmt.Printf("nbConstraints: %v\n", ccs.GetNbConstraints())

}

func TestBalanceCircuit2(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit BalancesCircuit

	for i := 1; i < 10; i++ {
		circuit.InitialBalances = make([]frontend.Variable, i*100)
		circuit.FinalBalances = make([]frontend.Variable, i*100)
		circuit.TransferAmounts = make([]frontend.Variable, i*100)

		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
		assert.NoError(err)
		fmt.Printf("sliceLenght:%v, nbConstraints: %v\n", i*100, ccs.GetNbConstraints())
	}

}
