package ceremony

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// ClientConfig drives the participant flow (`ceremony join`). The contribution
// (entropy) happens here, on the participant's machine - the soundness invariant.
//
// Pick ONE auth mode:
//   - Token (simplest): set Token to your login token. No signing, nothing secret
//     to derive; the coordinator handed you this bearer credential.
//   - Ed25519: set PrivHex (and optionally Identity); the client signs the join
//     challenge - no secret is sent over the wire.
type ClientConfig struct {
	ServerURL     string
	Provider      string // defaults to "token" if Token set, else "ed25519-allowlist"
	Token         string // login token (bearer credential) - token mode
	Identity      string // ed25519 pubkey hex (must match PrivHex) - ed25519 mode
	PrivHex       string // ed25519 private key (hex), used only to sign the challenge
	Backend       Backend
	ExpectCircuit string // optional; if set, the server's circuit fingerprint MUST match
	PollInterval  time.Duration
	HTTPClient    *http.Client
	WorkDir       string               // where to save the contributed blob (safety net); default os.TempDir()
	Log           func(string, ...any) // optional progress log
}

// Join runs the full participant flow and returns the inclusion receipt.
func Join(cfg ClientConfig) (*ReceiptResponse, error) {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 0}
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}
	logf := cfg.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}

	tokenMode := cfg.Token != ""
	if cfg.Provider == "" {
		if tokenMode {
			cfg.Provider = "token"
		} else {
			cfg.Provider = "ed25519-allowlist"
		}
	}
	if !tokenMode {
		// Ed25519 mode: derive/validate the identity from the private key.
		pub, err := PublicFromPrivate(cfg.PrivHex)
		if err != nil {
			return nil, err
		}
		if cfg.Identity == "" {
			cfg.Identity = pub
		} else if cfg.Identity != pub {
			return nil, fmt.Errorf("identity %q does not match the public key of the provided private key (%q)", cfg.Identity, pub)
		}
	}

	// 1. Info + circuit check (#1: "am I keying the right circuit?").
	var info InfoResponse
	if err := cfg.getJSON("/info", &info); err != nil {
		return nil, fmt.Errorf("GET /info: %w", err)
	}
	if info.Curve != cfg.Backend.CurveName() {
		return nil, fmt.Errorf("server curve %q != backend curve %q", info.Curve, cfg.Backend.CurveName())
	}
	if cfg.ExpectCircuit != "" && info.CircuitFingerprint != cfg.ExpectCircuit {
		return nil, fmt.Errorf("server circuit fingerprint %q != expected %q - REFUSING to contribute", info.CircuitFingerprint, cfg.ExpectCircuit)
	}
	logf("ceremony curve=%s circuit=%s contributions=%d", info.Curve, info.CircuitFingerprint, info.Contributions)

	// 2. Challenge -> 3. sign -> join.
	var chal ChallengeResponse
	if err := cfg.getJSON("/auth/challenge", &chal); err != nil {
		return nil, fmt.Errorf("GET /auth/challenge: %w", err)
	}
	chalBytes, err := hex.DecodeString(chal.Challenge)
	if err != nil {
		return nil, fmt.Errorf("bad challenge: %w", err)
	}
	var proofHex, identity string
	if tokenMode {
		proofHex = cfg.Token // the bearer credential (hex); no signing
		identity = ""        // the server maps the token to a participant name
	} else {
		proof, err := SignChallenge(cfg.PrivHex, chalBytes)
		if err != nil {
			return nil, err
		}
		proofHex = hex.EncodeToString(proof)
		identity = cfg.Identity
	}
	var join JoinResponse
	if err := cfg.postJSON("/lobby/join", JoinRequest{
		Provider: cfg.Provider, Identity: identity, Challenge: chal.Challenge, Proof: proofHex,
	}, &join); err != nil {
		return nil, fmt.Errorf("POST /lobby/join: %w", err)
	}
	logf("joined lobby; queue position %d", join.Position)

	// 4. Wait for our slot.
	for {
		var st StatusResponse
		if err := cfg.getJSON("/lobby/status?session="+join.Session, &st); err != nil {
			return nil, fmt.Errorf("GET /lobby/status: %w", err)
		}
		if st.Closed {
			return nil, fmt.Errorf("ceremony closed before our slot")
		}
		if st.YourTurn {
			logf("it's your turn - slot open until %s", fmtDeadline(st.DeadlineUnix))
			break
		}
		eta := ""
		if st.EtaSeconds > 0 {
			eta = fmt.Sprintf(" - ~%s until your turn", (time.Duration(st.EtaSeconds) * time.Second).Round(time.Second))
		}
		if st.Position == 1 {
			logf("you're next - 1 contribution ahead of you%s", eta)
		} else {
			logf("waiting in queue: %d ahead of you%s", st.Position, eta)
		}
		time.Sleep(cfg.PollInterval)
	}

	// Keep the slot alive while we download/contribute/upload (minutes of work). The
	// heartbeat pushes the deadline out; if this client dies, beats stop and the slot
	// frees for the next person.
	stopHB := cfg.startHeartbeat(join.Session)
	defer stopHB()

	// 5. Download the head (progress bar) + re-check the circuit fingerprint header.
	logf("downloading head (this is a large file; progress below)...")
	headBytes, fp, err := cfg.getHeadProgress(join.Session)
	if err != nil {
		return nil, fmt.Errorf("download head: %w", err)
	}
	if cfg.ExpectCircuit != "" && fp != cfg.ExpectCircuit {
		return nil, fmt.Errorf("head circuit fingerprint %q != expected %q", fp, cfg.ExpectCircuit)
	}

	// 6. Contribute LOCALLY - the only secret-touching step, on this machine.
	logf("contributing locally (folding in your randomness; this can take a few minutes)...")
	head := cfg.Backend.NewPhase2()
	if _, err := head.ReadFrom(bytes.NewReader(headBytes)); err != nil {
		return nil, fmt.Errorf("parse head: %w", err)
	}
	if err := cfg.Backend.ContributePhase2(head); err != nil {
		return nil, fmt.Errorf("contribute: %w", err)
	}
	var out byteBuf
	if _, err := head.WriteTo(&out); err != nil {
		return nil, fmt.Errorf("serialize contribution: %w", err)
	}
	// Safety net: persist the contributed blob so a flaky upload never loses the
	// (expensive) work.
	savePath := cfg.saveContribution(join.Session, out.b, logf)

	// 7. Upload (progress bar + retries) -> receipt.
	logf("uploading your contribution (%d MB)...", len(out.b)>>20)
	receipt, err := cfg.uploadWithRetry(join.Session, out.b, logf)
	if err != nil {
		if savePath != "" {
			return nil, fmt.Errorf("%w\n  your contribution is saved at %s - re-run join to retry", err, savePath)
		}
		return nil, err
	}
	logf("recorded as contribution #%d (new=%s)", receipt.Index, receipt.NewSHA256)
	// Auto-verify our own inclusion in the published transcript - no need for the
	// participant to send anything; the coordinator already has it server-side.
	if err := cfg.verifyInclusion(receipt); err != nil {
		logf("note: could not auto-verify inclusion (%v); your receipt above is your proof", err)
	} else {
		logf("verified in the published transcript - you're done, nothing to send")
	}
	return receipt, nil
}

// FetchTranscript downloads the public transcript (the coordinator's auto-collected
// record of every accepted contribution - no manual receipt-gathering needed).
func FetchTranscript(serverURL string) (*Transcript, error) {
	resp, err := http.Get(serverURL + "/transcript")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, b)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return LoadTranscriptJSON(b)
}

// verifyInclusion fetches /transcript and confirms our contribution is recorded.
func (cfg ClientConfig) verifyInclusion(receipt *ReceiptResponse) error {
	resp, err := cfg.HTTPClient.Get(cfg.ServerURL + "/transcript")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	tr, err := LoadTranscriptJSON(b)
	if err != nil {
		return err
	}
	for _, e := range tr.Entries {
		if e.NewSHA256 == receipt.NewSHA256 {
			return nil
		}
	}
	return fmt.Errorf("contribution %s not yet visible in transcript", receipt.NewSHA256)
}

// startHeartbeat pings /slot/heartbeat every 20s to keep the slot alive while we
// work; returns a stop func to call when done.
func (cfg ClientConfig) startHeartbeat(session string) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	hb := &http.Client{Timeout: 30 * time.Second}
	url := cfg.ServerURL + "/slot/heartbeat?session=" + session
	go func() {
		defer close(done)
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if resp, err := hb.Post(url, "application/json", nil); err == nil {
					_ = resp.Body.Close()
				}
			}
		}
	}()
	return func() { close(stop); <-done }
}

// fmtDeadline renders a slot deadline as 24h UTC + time remaining (no unix seconds).
func fmtDeadline(unix int64) string {
	if unix <= 0 {
		return "unknown"
	}
	d := time.Unix(unix, 0).UTC()
	return fmt.Sprintf("%s UTC (%s left)", d.Format("15:04:05"), time.Until(d).Round(time.Second))
}

func (cfg ClientConfig) saveContribution(session string, body []byte, logf func(string, ...any)) string {
	dir := cfg.WorkDir
	if dir == "" {
		dir = os.TempDir()
	}
	id := session
	if len(id) > 8 {
		id = id[:8]
	}
	path := filepath.Join(dir, "ceremony-contribution-"+id+".bin")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		logf("note: could not save a local backup of your contribution (%v)", err)
		return ""
	}
	return path
}

// ---- tiny HTTP helpers ----

func (cfg ClientConfig) getJSON(path string, v any) error {
	resp, err := cfg.HTTPClient.Get(cfg.ServerURL + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func (cfg ClientConfig) postJSON(path string, req, v any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	resp, err := cfg.HTTPClient.Post(cfg.ServerURL+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func (cfg ClientConfig) getHeadProgress(session string) ([]byte, string, error) {
	resp, err := cfg.HTTPClient.Get(cfg.ServerURL + "/slot/head?session=" + session)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}
	b, err := io.ReadAll(newProgress(resp.Body, resp.ContentLength, "download"))
	if err != nil {
		return nil, "", err
	}
	return b, resp.Header.Get("X-Circuit-Fingerprint"), nil
}

// uploadWithRetry uploads the contribution, retrying on transient failures. The
// blob is held in memory (and saved to disk), so a retry never re-runs the
// expensive contribute step. Heartbeats keep the slot alive across attempts.
func (cfg ClientConfig) uploadWithRetry(session string, body []byte, logf func(string, ...any)) (*ReceiptResponse, error) {
	var lastErr error
	for attempt := 1; attempt <= 4; attempt++ {
		if attempt > 1 {
			logf("upload attempt %d/4 (retrying - your work is saved, slot kept alive)...", attempt)
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		receipt, err := cfg.uploadBlob(session, body)
		if err == nil {
			return receipt, nil
		}
		lastErr = err
		logf("  upload failed: %v", err)
	}
	return nil, lastErr
}

func (cfg ClientConfig) uploadBlob(session string, body []byte) (*ReceiptResponse, error) {
	pr := newProgress(bytes.NewReader(body), int64(len(body)), "upload  ")
	req, err := http.NewRequest(http.MethodPost, cfg.ServerURL+"/slot/contribute?session="+session, pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(body))
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}
	var receipt ReceiptResponse
	if err := json.NewDecoder(resp.Body).Decode(&receipt); err != nil {
		return nil, err
	}
	return &receipt, nil
}

// progressReader wraps a reader and prints a live bar (percent if total known,
// bytes + MB/s + ETA) to stderr. Only renders for sizeable (>4 MB) transfers so it
// stays quiet in tests and on tiny circuits.
type progressReader struct {
	r           io.Reader
	total, read int64
	label       string
	start, last time.Time
}

func newProgress(r io.Reader, total int64, label string) *progressReader {
	now := time.Now()
	return &progressReader{r: r, total: total, label: label, start: now, last: now}
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)
	if p.total >= 4<<20 || (p.total < 0 && p.read >= 4<<20) {
		if time.Since(p.last) >= 400*time.Millisecond {
			p.render(false)
			p.last = time.Now()
		}
		if err == io.EOF {
			p.render(true)
		}
	}
	return n, err
}

func (p *progressReader) render(done bool) {
	el := time.Since(p.start).Seconds()
	if el <= 0 {
		el = 0.001
	}
	rate := float64(p.read) / el / 1e6 // MB/s
	if p.total > 0 {
		pct := 100 * float64(p.read) / float64(p.total)
		eta := "-"
		if rate > 0 && p.read < p.total {
			eta = (time.Duration(float64(p.total-p.read)/(rate*1e6)) * time.Second).Round(time.Second).String()
		}
		fmt.Fprintf(os.Stderr, "\r  %s %5.1f%%  %d/%d MB  %5.1f MB/s  ETA %-7s", p.label, pct, p.read>>20, p.total>>20, rate, eta)
	} else {
		fmt.Fprintf(os.Stderr, "\r  %s %d MB  %5.1f MB/s        ", p.label, p.read>>20, rate)
	}
	if done {
		fmt.Fprintln(os.Stderr)
	}
}
