package ceremony

import (
	"bytes"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// TestResume simulates a host restart mid-ceremony: a second Sequencer built on
// the SAME store must pick up the accepted contributions, not wipe them.
func TestResume(t *testing.T) {
	const power = 7
	backend, _ := BackendFor("bls12-381")

	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &cubic{})
	if err != nil {
		t.Fatal(err)
	}
	var ccsBuf byteBuf
	if _, err := ccs.WriteTo(&ccsBuf); err != nil {
		t.Fatal(err)
	}
	fp, _ := backend.CircuitFingerprint(bytes.NewReader(ccsBuf.b))

	p1, _ := backend.InitPhase1(power)
	_ = backend.ContributePhase1(p1)
	commons, _ := backend.SealPhase1(power, []byte("beacon"), []Blob{p1})
	var cbuf byteBuf
	_, _ = commons.WriteTo(&cbuf)
	initHead, err := backend.InitPhase2(bytes.NewReader(ccsBuf.b), bytes.NewReader(cbuf.b))
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	tok, _ := GenerateToken()
	allow := map[string]string{tok: "dev"}
	mkSeq := func() *Sequencer {
		store, _ := NewLocalStorage(dir) // SAME dir -> resume on the 2nd call
		s, err := NewSequencer(SequencerConfig{
			Backend: backend, Store: store,
			Providers:   map[string]AuthProvider{"token": NewTokenAllowlist(allow)},
			SlotTimeout: time.Minute,
		}, initHead, fp)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	contribute := func(s *Sequencer) {
		srv := httptest.NewServer(s.Handler())
		defer srv.Close()
		if _, err := Join(ClientConfig{
			ServerURL: srv.URL, Token: tok, Backend: backend,
			ExpectCircuit: fp, PollInterval: 20 * time.Millisecond,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// First sequencer: fresh, one contribution.
	s1 := mkSeq()
	if s1.Transcript().Len() != 0 {
		t.Fatalf("fresh sequencer should start at 0, got %d", s1.Transcript().Len())
	}
	contribute(s1)
	if s1.Transcript().Len() != 1 {
		t.Fatalf("after 1 contribution want 1, got %d", s1.Transcript().Len())
	}
	s1.Close()

	// Restart: new sequencer on the SAME store must RESUME with the contribution.
	s2 := mkSeq()
	if s2.Transcript().Len() != 1 {
		t.Fatalf("resumed sequencer should have 1 contribution, got %d (state was wiped!)", s2.Transcript().Len())
	}
	if err := s2.Transcript().Verify(); err != nil {
		t.Fatalf("resumed transcript chain invalid: %v", err)
	}

	// A further contribution must chain onto the resumed head (-> #1, total 2).
	contribute(s2)
	if s2.Transcript().Len() != 2 {
		t.Fatalf("after resume + 1 more want 2, got %d", s2.Transcript().Len())
	}
	if err := s2.Transcript().Verify(); err != nil {
		t.Fatalf("post-resume transcript chain invalid: %v", err)
	}
	s2.Close()
}
