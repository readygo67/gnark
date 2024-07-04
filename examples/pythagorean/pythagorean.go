package pythagorean

import "github.com/consensys/gnark/frontend"

// Circuit defines a simple circuit
type Circuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	A frontend.Variable `gnark:"a"`
	B frontend.Variable `gnark:"b"`
	C frontend.Variable `gnark:"c"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *Circuit) Define(api frontend.API) error {
	a := api.Mul(circuit.A, circuit.A)
	b := api.Mul(circuit.B, circuit.B)
	c := api.Mul(circuit.C, circuit.C)
	api.AssertIsEqual(c, api.Add(a, b))
	return nil
}
