package main

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test/unsafekzg"
	"os"
)

func main() {

	{
		bls12377Field := ecc.BLS12_377.ScalarField()
		bls12377Tau, err := rand.Int(rand.Reader, bls12377Field)
		if err != nil {
			panic(err)
		}
		fmt.Printf("bls12377 tau: %v\n", bls12377Tau)
		for i := 16; i <= 28; i++ {
			srsFile := fmt.Sprintf("bls12377_pow_%v.srs", i)
			lSrsFile := fmt.Sprintf("bls12377_pow_%v.lsrs", i)

			size := 1<<uint(i) - 1
			srs, lsrs, err := unsafekzg.NewSRSWithSize(size, bls12377Field, unsafekzg.WithTau(bls12377Tau))
			if err != nil {
				panic(err)
			}

			fsrs, err := os.Create(srsFile)
			defer fsrs.Close()
			if err != nil {
				panic(err)
			}

			_, err = srs.WriteTo(fsrs)
			if err != nil {
				panic(err)
			}

			flsrs, err := os.Create(lSrsFile)
			defer flsrs.Close()
			if err != nil {
				panic(err)
			}

			_, err = lsrs.WriteTo(flsrs)
			if err != nil {
				panic(err)
			}

		}
	}

	{
		bw6761Field := ecc.BW6_761.ScalarField()
		bw6761Tau, err := rand.Int(rand.Reader, bw6761Field)
		if err != nil {
			panic(err)
		}
		fmt.Printf("bw6761 tau: %v\n", bw6761Field)
		for i := 16; i <= 28; i++ {
			srsFile := fmt.Sprintf("bw6761_pow_%v.srs", i)
			lSrsFile := fmt.Sprintf("bw6761_pow_%v.lsrs", i)

			size := 1<<uint(i) - 1
			srs, lsrs, err := unsafekzg.NewSRSWithSize(size, bw6761Field, unsafekzg.WithTau(bw6761Tau))
			if err != nil {
				panic(err)
			}

			fsrs, err := os.Create(srsFile)
			defer fsrs.Close()
			if err != nil {
				panic(err)
			}

			_, err = srs.WriteTo(fsrs)
			if err != nil {
				panic(err)
			}

			flsrs, err := os.Create(lSrsFile)
			defer flsrs.Close()
			if err != nil {
				panic(err)
			}

			_, err = lsrs.WriteTo(flsrs)
			if err != nil {
				panic(err)
			}

		}
	}

}
