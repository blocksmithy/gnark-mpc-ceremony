// Command gendemo emits a small DEMO circuit (cubic: x³+x+5==y) as ccs.bin plus a
// sealed phase-1 commons.bin, so a local rehearsal can run without a real circuit.
// FOR REHEARSAL/TESTING ONLY - a real ceremony uses the project's actual ccs.bin
// and a reused powers-of-tau.
package main

import (
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/blocksmithy/gnark-mpc-ceremony/ceremony"
)

type cubic struct {
	X frontend.Variable `gnark:",secret"`
	Y frontend.Variable `gnark:",public"`
}

func (c *cubic) Define(api frontend.API) error {
	x3 := api.Mul(c.X, c.X, c.X)
	api.AssertIsEqual(c.Y, api.Add(x3, c.X, 5))
	return nil
}

func main() {
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &cubic{})
	if err != nil {
		panic(err)
	}
	fc, err := os.Create("ccs.bin")
	if err != nil {
		panic(err)
	}
	if _, err := ccs.WriteTo(fc); err != nil {
		panic(err)
	}
	_ = fc.Close()

	b, err := ceremony.BackendFor("bls12-381")
	if err != nil {
		panic(err)
	}
	p1, err := b.InitPhase1(7) // 2^7 >= cubic constraints
	if err != nil {
		panic(err)
	}
	if err := b.ContributePhase1(p1); err != nil {
		panic(err)
	}
	commons, err := b.SealPhase1(7, []byte("demo-beacon-phase1"), []ceremony.Blob{p1})
	if err != nil {
		panic(err)
	}
	cm, err := os.Create("commons.bin")
	if err != nil {
		panic(err)
	}
	if _, err := commons.WriteTo(cm); err != nil {
		panic(err)
	}
	_ = cm.Close()
}
