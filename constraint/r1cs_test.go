package constraint_test

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"reflect"
	"testing"
)

func ExampleR1CS_GetR1Cs() {
	// build a constraint system; this is (usually) done by the frontend package
	// for this Example we want to manipulate the constraints and output a string representation
	// and build the linear expressions "manually".
	r1cs := cs.NewR1CS(0)

	blueprint := r1cs.AddBlueprint(&constraint.BlueprintGenericR1C{})

	ONE := r1cs.AddPublicVariable("1") // the "ONE" wire
	Y := r1cs.AddPublicVariable("Y")
	X := r1cs.AddSecretVariable("X")

	v0 := r1cs.AddInternalVariable() // X²
	v1 := r1cs.AddInternalVariable() // X³

	// coefficients
	cOne := r1cs.FromInterface(1)
	cFive := r1cs.FromInterface(5)

	// X² == X * X
	r1cs.AddR1C(constraint.R1C{
		L: constraint.LinearExpression{r1cs.MakeTerm(cOne, X)},
		R: constraint.LinearExpression{r1cs.MakeTerm(cOne, X)},
		O: constraint.LinearExpression{r1cs.MakeTerm(cOne, v0)},
	}, blueprint)

	// X³ == X² * X
	r1cs.AddR1C(constraint.R1C{
		L: constraint.LinearExpression{r1cs.MakeTerm(cOne, v0)},
		R: constraint.LinearExpression{r1cs.MakeTerm(cOne, X)},
		O: constraint.LinearExpression{r1cs.MakeTerm(cOne, v1)},
	}, blueprint)

	// Y == X³ + X + 5
	r1cs.AddR1C(constraint.R1C{
		R: constraint.LinearExpression{r1cs.MakeTerm(cOne, ONE)},
		L: constraint.LinearExpression{r1cs.MakeTerm(cOne, Y)},
		O: constraint.LinearExpression{
			r1cs.MakeTerm(cFive, ONE),
			r1cs.MakeTerm(cOne, X),
			r1cs.MakeTerm(cOne, v1),
		},
	}, blueprint)

	// get the constraints
	constraints := r1cs.GetR1Cs()

	for _, r1c := range constraints {
		fmt.Println(r1c.String(r1cs))
		// for more granularity use constraint.NewStringBuilder(r) that embeds a string.Builder
		// and has WriteLinearExpression and WriteTerm methods.
	}

	// Output:
	// X ⋅ X == v0
	// v0 ⋅ X == v1
	// Y ⋅ 1 == 5 + X + v1
}

type cubic struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *cubic) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func ExampleR1CS_Solve() {
	// build a constraint system and a witness;
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &cubic{})
	fmt.Printf("NbConstraints:%v, NbInstructions:%v\n", ccs.GetNbConstraints(), ccs.GetNbInstructions())
	fmt.Printf("NbPublic:%v, NbSecret:%v, NbInternal:%v\n", ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables(), ccs.GetNbInternalVariables())

	w, _ := frontend.NewWitness(&cubic{X: 3, Y: 35}, ecc.BN254.ScalarField())

	_solution, _ := ccs.Solve(w)

	// concrete solution
	solution := _solution.(*cs.R1CSSolution)

	// solution vector should have [1, 3, 35, 9, 27]
	for _, v := range solution.W {
		fmt.Println(v.String())
	}

	// Output:
	// 1
	// 35
	// 3
	// 9
	// 27
}

func TestCubicCircuit_Compile(t *testing.T) {
	// build a constraint system and a witness;
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &cubic{})
	fmt.Printf("NbConstraints:%v, NbInstructions:%v\n", ccs.GetNbConstraints(), ccs.GetNbInstructions())
	fmt.Printf("NbPublic:%v, NbSecret:%v, NbInternal:%v\n", ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables(), ccs.GetNbInternalVariables())

	w, _ := frontend.NewWitness(&cubic{X: 3, Y: 35}, ecc.BN254.ScalarField())

	_solution, _ := ccs.Solve(w)

	// concrete solution
	solution := _solution.(*cs.R1CSSolution)

	// solution vector should have [1, 3, 35, 9, 27]
	for _, v := range solution.W {
		fmt.Println(v.String())
	}

}

func TestGetTypeByReflect(t *testing.T) {
	//使用反射（reflect）来初始化一个全局变量 tVariable。其主要目的是获取一个结构体字段的类型，然后将该类型赋值给 tVariable
	var tVariable reflect.Type
	type Variable interface{}

	v := reflect.ValueOf(struct{ A Variable }{})
	tVariable = v.FieldByName("A").Type()
	fmt.Println(tVariable)
}
