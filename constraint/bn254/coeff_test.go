package cs

import (
	"fmt"
	"testing"
)

func TestCoeffTable_AddCoeff(t *testing.T) {
	tab := newCoeffTable(10)
	fmt.Printf("%#v\n", tab.CoeffToString(0))

	p := &field{}

	el := p.FromInterface(100)
	id := tab.AddCoeff(el)
	fmt.Printf("%#v\n", tab.CoeffToString(int(id)))

	el = p.FromInterface(-100)
	id = tab.AddCoeff(el)
	fmt.Printf("%#v\n", tab.CoeffToString(int(id)))
}
