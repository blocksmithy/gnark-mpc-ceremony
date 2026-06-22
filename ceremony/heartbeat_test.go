package ceremony

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// TestHeartbeatExtendsDeadline proves the fix for the live 409 ("slot expired
// before contribution committed"): a participant who keeps heartbeating holds the
// slot past its original timeout, instead of being dropped mid-upload.
func TestHeartbeatExtendsDeadline(t *testing.T) {
	backend, _ := BackendFor("bls12-381")
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &cubic{})
	if err != nil {
		t.Fatal(err)
	}
	var ccsBuf byteBuf
	_, _ = ccs.WriteTo(&ccsBuf)
	fp, _ := backend.CircuitFingerprint(bytes.NewReader(ccsBuf.b))
	p1, _ := backend.InitPhase1(7)
	_ = backend.ContributePhase1(p1)
	commons, _ := backend.SealPhase1(7, []byte("b"), []Blob{p1})
	var cb byteBuf
	_, _ = commons.WriteTo(&cb)
	initHead, _ := backend.InitPhase2(bytes.NewReader(ccsBuf.b), bytes.NewReader(cb.b))

	tok, _ := GenerateToken()
	store, _ := NewLocalStorage(t.TempDir())
	seq, err := NewSequencer(SequencerConfig{
		Backend:     backend,
		Store:       store,
		Providers:   map[string]AuthProvider{"token": NewTokenAllowlist(map[string]string{tok: "dev"})},
		SlotTimeout: 2 * time.Second, // short, so the test is quick
	}, initHead, fp)
	if err != nil {
		t.Fatal(err)
	}
	defer seq.Close()
	srv := httptest.NewServer(seq.Handler())
	defer srv.Close()

	var chal ChallengeResponse
	httpGET(t, srv.URL+"/auth/challenge", &chal)
	var jr JoinResponse
	httpPOST(t, srv.URL+"/lobby/join", JoinRequest{Provider: "token", Proof: tok, Challenge: chal.Challenge}, &jr)

	var st0 StatusResponse
	httpGET(t, srv.URL+"/lobby/status?session="+jr.Session, &st0)
	if !st0.YourTurn {
		t.Fatalf("should hold the slot immediately, got position %d", st0.Position)
	}

	// Heartbeat just before the 2s expiry -> deadline must move out.
	time.Sleep(1200 * time.Millisecond)
	var hb StatusResponse
	httpPOST(t, srv.URL+"/slot/heartbeat?session="+jr.Session, nil, &hb)
	if hb.DeadlineUnix <= st0.DeadlineUnix {
		t.Fatalf("heartbeat did not extend the deadline (%d <= %d)", hb.DeadlineUnix, st0.DeadlineUnix)
	}

	// Now past the ORIGINAL 2s timeout - but the heartbeat extended it, so the slot
	// must still be ours (without the heartbeat this is exactly the 409 we hit live).
	time.Sleep(1300 * time.Millisecond)
	var st1 StatusResponse
	httpGET(t, srv.URL+"/lobby/status?session="+jr.Session, &st1)
	if !st1.YourTurn {
		t.Fatal("slot expired despite heartbeats - the live 409 bug is NOT fixed")
	}
}

func httpGET(t *testing.T, url string, v any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s -> %d: %s", url, resp.StatusCode, b)
	}
	if v != nil {
		_ = json.NewDecoder(resp.Body).Decode(v)
	}
}

func httpPOST(t *testing.T, url string, req, v any) {
	t.Helper()
	var body io.Reader
	if req != nil {
		b, _ := json.Marshal(req)
		body = bytes.NewReader(b)
	}
	resp, err := http.Post(url, "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s -> %d: %s", url, resp.StatusCode, b)
	}
	if v != nil {
		_ = json.NewDecoder(resp.Body).Decode(v)
	}
}
