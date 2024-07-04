package add

import "github.com/consensys/gnark/frontend"

// Circuit defines a simple circuit
// x**3 + x + 5 == y
type Circuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:"y"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(circuit.Y, circuit.X)
	return nil
}
