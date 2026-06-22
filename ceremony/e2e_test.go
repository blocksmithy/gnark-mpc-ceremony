package ceremony

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// cubic is a tiny circuit (x³ + x + 5 == y) standing in for ANY gnark circuit -
// the whole point of this tool is that it is circuit-agnostic.
type cubic struct {
	X frontend.Variable `gnark:",secret"`
	Y frontend.Variable `gnark:",public"`
}

func (c *cubic) Define(api frontend.API) error {
	x3 := api.Mul(c.X, c.X, c.X)
	api.AssertIsEqual(c.Y, api.Add(x3, c.X, 5))
	return nil
}

// TestEndToEnd runs a full ceremony through the sequencer with several
// participants and proves the resulting keys actually verify a Groth16 proof.
func TestEndToEnd(t *testing.T) {
	const power = 7 // 2^7 = 128 >= cubic constraints
	backend, err := BackendFor("bls12-381")
	if err != nil {
		t.Fatal(err)
	}

	// Compile the circuit -> ccs.bin (the only project-specific input).
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &cubic{})
	if err != nil {
		t.Fatal(err)
	}
	var ccsBuf byteBuf
	if _, err := ccs.WriteTo(&ccsBuf); err != nil {
		t.Fatal(err)
	}
	ccsBytes := ccsBuf.b

	circuitFP, err := backend.CircuitFingerprint(bytes.NewReader(ccsBytes))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("circuit fingerprint: %s", circuitFP)

	// ---- Phase 1 (one contributor here; production reuses an external PoT) ----
	p1, err := backend.InitPhase1(power)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.ContributePhase1(p1); err != nil {
		t.Fatal(err)
	}
	commons, err := backend.SealPhase1(power, []byte("phase1-beacon-e2e"), []Blob{p1})
	if err != nil {
		t.Fatal(err)
	}
	var commonsBuf byteBuf
	if _, err := commons.WriteTo(&commonsBuf); err != nil {
		t.Fatal(err)
	}
	commonsBytes := commonsBuf.b

	// ---- Phase 2 init head ----
	initHead, err := backend.InitPhase2(bytes.NewReader(ccsBytes), bytes.NewReader(commonsBytes))
	if err != nil {
		t.Fatal(err)
	}

	// ---- Participants: 3 login tokens (the dev-team flow) ----
	type participant struct{ token, name string }
	parts := make([]participant, 3)
	allow := map[string]string{}
	for i := range parts {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("dev-%d", i+1)
		parts[i] = participant{tok, name}
		allow[tok] = name
	}

	store, err := NewLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seq, err := NewSequencer(SequencerConfig{
		Backend:     backend,
		Store:       store,
		Providers:   map[string]AuthProvider{"token": NewTokenAllowlist(allow)},
		SlotTimeout: time.Minute,
	}, initHead, circuitFP)
	if err != nil {
		t.Fatal(err)
	}
	defer seq.Close()

	srv := httptest.NewServer(seq.Handler())
	defer srv.Close()

	// Each participant runs the real client flow, sequentially, using their token.
	for _, p := range parts {
		receipt, err := Join(ClientConfig{
			ServerURL:     srv.URL,
			Token:         p.token,
			Backend:       backend,
			ExpectCircuit: circuitFP,
			PollInterval:  20 * time.Millisecond,
			Log:           func(f string, a ...any) { t.Logf("["+p.name+"] "+f, a...) },
		})
		if err != nil {
			t.Fatalf("participant %s: %v", p.name, err)
		}
		if receipt == nil {
			t.Fatalf("participant %s: nil receipt", p.name)
		}
	}

	// Transcript: chained, one entry per participant.
	tr := seq.Transcript()
	if tr.Len() != len(parts) {
		t.Fatalf("transcript len = %d, want %d", tr.Len(), len(parts))
	}
	if err := tr.Verify(); err != nil {
		t.Fatalf("transcript chain invalid: %v", err)
	}

	// ---- Finalize from the SEQUENCER's stored chain + beacon ----
	chain, err := store.LoadChain(backend)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != len(parts) {
		t.Fatalf("stored chain len = %d, want %d", len(chain), len(parts))
	}
	keys, err := backend.FinalizePhase2(bytes.NewReader(ccsBytes), bytes.NewReader(commonsBytes), []byte("phase2-beacon-e2e"), chain)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	t.Logf("VK fingerprint: %s", keys.VKFingerprint)

	// Determinism: finalize again -> identical VK fingerprint (reproducible by anyone).
	chain2, _ := store.LoadChain(backend)
	keys2, err := backend.FinalizePhase2(bytes.NewReader(ccsBytes), bytes.NewReader(commonsBytes), []byte("phase2-beacon-e2e"), chain2)
	if err != nil {
		t.Fatal(err)
	}
	if keys.VKFingerprint != keys2.VKFingerprint {
		t.Fatalf("finalize not reproducible: %s != %s", keys.VKFingerprint, keys2.VKFingerprint)
	}

	// ---- The real test: do the ceremony keys actually prove + verify? ----
	pk := groth16.NewProvingKey(ecc.BLS12_381)
	if _, err := pk.ReadFrom(bytes.NewReader(keys.PK)); err != nil {
		t.Fatal(err)
	}
	vk := groth16.NewVerifyingKey(ecc.BLS12_381)
	if _, err := vk.ReadFrom(bytes.NewReader(keys.VK)); err != nil {
		t.Fatal(err)
	}
	provCCS := groth16.NewCS(ecc.BLS12_381)
	if _, err := provCCS.ReadFrom(bytes.NewReader(keys.CCS)); err != nil {
		t.Fatal(err)
	}

	// x = 3 -> 27 + 3 + 5 = 35
	witness, err := frontend.NewWitness(&cubic{X: 3, Y: 35}, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(provCCS, pk, witness)
	if err != nil {
		t.Fatalf("prove with ceremony keys: %v", err)
	}
	pubWitness, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, pubWitness); err != nil {
		t.Fatalf("verify with ceremony keys: %v", err)
	}

	// Negative: a wrong public input must NOT verify.
	badWitness, _ := frontend.NewWitness(&cubic{X: 3, Y: 36}, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err := groth16.Verify(proof, vk, badWitness); err == nil {
		t.Fatal("verify accepted a wrong public input - soundness broken")
	}
}
