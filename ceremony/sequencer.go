package ceremony

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// SequencerConfig configures a ceremony coordinator.
type SequencerConfig struct {
	Backend      Backend
	Store        Storage
	Providers    map[string]AuthProvider // by Name()
	SlotTimeout  time.Duration           // a slot left idle this long is abandoned (head unchanged)
	ChallengeTTL time.Duration           // how long an issued auth challenge stays valid
	MaxBlobBytes int64                   // upload cap; 0 -> 2 GiB default
}

type session struct {
	id       string
	identity Identity
	joined   time.Time
}

// Sequencer is the scalable, strictly-sequential Phase-2 coordinator: a lobby +
// queue + single advancing head. It only ever handles PUBLIC blobs (see the
// soundness invariant in backend.go); it never runs a contribution or sees a secret.
type Sequencer struct {
	cfg         SequencerConfig
	mu          sync.Mutex
	head        Blob
	initHash    string
	circuitFP   string
	tr          *Transcript
	queue       []*session
	active      *session
	activeSince time.Time // when the current slot was opened (for avg/ETA)
	deadline    time.Time
	avgContrib  time.Duration // rolling average wall-time per accepted contribution
	closed      bool
	chals       map[string]time.Time
	stop        chan struct{}
}

// NewSequencer starts a fresh ceremony from an uncontributed init head (the
// output of InitPhase2). It persists the init head + an empty transcript and
// starts the slot-expiry loop.
func NewSequencer(cfg SequencerConfig, initHead Blob, circuitFP string) (*Sequencer, error) {
	if cfg.SlotTimeout <= 0 {
		cfg.SlotTimeout = 10 * time.Minute
	}
	if cfg.ChallengeTTL <= 0 {
		cfg.ChallengeTTL = 5 * time.Minute
	}
	if cfg.MaxBlobBytes <= 0 {
		cfg.MaxBlobBytes = 2 << 30
	}
	var head Blob
	var initHash string
	var tr *Transcript

	// RESUME an in-progress ceremony if persisted state exists (e.g. the host VM
	// restarted mid-ceremony). Without this, re-running from initHead would wipe
	// every accepted contribution. State (head + transcript + blobs) lives on the
	// durable store; on restart we pick up exactly where we left off.
	if existing, err := cfg.Store.LoadTranscript(); err == nil && existing != nil {
		if existing.Circuit != circuitFP {
			return nil, fmt.Errorf("resume: persisted circuit %s != configured %s", existing.Circuit, circuitFP)
		}
		head = cfg.Backend.NewPhase2()
		if err := cfg.Store.LoadHead(head); err != nil {
			return nil, fmt.Errorf("resume: load head: %w", err)
		}
		tr = existing
		initHash = existing.InitHash
		fmt.Fprintf(os.Stderr, "RESUMED ceremony: %d contribution(s) already accepted\n", tr.Len())
	} else {
		h, err := HashBlob(initHead)
		if err != nil {
			return nil, err
		}
		initHash = hex.EncodeToString(h)
		tr = &Transcript{Curve: cfg.Backend.CurveName(), Circuit: circuitFP, InitHash: initHash}
		head = initHead
		if err := cfg.Store.SaveHead(initHead); err != nil {
			return nil, err
		}
		if err := cfg.Store.SaveTranscript(tr); err != nil {
			return nil, err
		}
	}
	s := &Sequencer{
		cfg: cfg, head: head, initHash: initHash, circuitFP: circuitFP, tr: tr,
		chals: make(map[string]time.Time), stop: make(chan struct{}),
	}
	go s.expiryLoop()
	return s, nil
}

// Close stops the expiry loop and marks the lobby closed.
func (s *Sequencer) Close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.stop)
	}
	s.mu.Unlock()
}

func (s *Sequencer) expiryLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.mu.Lock()
			if s.active != nil && time.Now().After(s.deadline) {
				s.active = nil // abandon: head UNCHANGED -> cannot harm soundness
				s.promoteLocked()
			}
			s.mu.Unlock()
		}
	}
}

func (s *Sequencer) promoteLocked() {
	if s.active == nil && !s.closed && len(s.queue) > 0 {
		s.active = s.queue[0]
		s.queue = s.queue[1:]
		now := time.Now()
		s.activeSince = now
		s.deadline = now.Add(s.cfg.SlotTimeout)
	}
}

// Transcript exposes the live transcript (for finalize / inspection).
func (s *Sequencer) Transcript() *Transcript { return s.tr }

func token() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("ceremony: crypto/rand failed: " + err.Error()) // fail closed
	}
	return hex.EncodeToString(b[:])
}

// Handler returns the HTTP API.
func (s *Sequencer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /info", s.handleInfo)
	mux.HandleFunc("GET /auth/challenge", s.handleChallenge)
	mux.HandleFunc("POST /lobby/join", s.handleJoin)
	mux.HandleFunc("GET /lobby/status", s.handleStatus)
	mux.HandleFunc("POST /slot/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("GET /slot/head", s.handleHead)
	mux.HandleFunc("POST /slot/contribute", s.handleContribute)
	mux.HandleFunc("GET /transcript", s.handleTranscript)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Sequencer) handleInfo(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	resp := InfoResponse{
		Curve: s.cfg.Backend.CurveName(), CircuitFingerprint: s.circuitFP,
		Contributions: s.tr.Len(), QueueLen: len(s.queue), SlotActive: s.active != nil, Closed: s.closed,
		AvgContributionSeconds: int64(s.avgContrib.Seconds()),
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, resp)
}

func (s *Sequencer) handleChallenge(w http.ResponseWriter, _ *http.Request) {
	c := token() + token() // 32 bytes
	s.mu.Lock()
	// opportunistic prune
	now := time.Now()
	for k, t := range s.chals {
		if now.After(t) {
			delete(s.chals, k)
		}
	}
	s.chals[c] = now.Add(s.cfg.ChallengeTTL)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, ChallengeResponse{Challenge: c})
}

func (s *Sequencer) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req JoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	prov, ok := s.cfg.Providers[req.Provider]
	if !ok {
		http.Error(w, "unknown auth provider", http.StatusBadRequest)
		return
	}
	chalBytes, err := hex.DecodeString(req.Challenge)
	if err != nil {
		http.Error(w, "bad challenge encoding", http.StatusBadRequest)
		return
	}
	proof, err := hex.DecodeString(req.Proof)
	if err != nil {
		http.Error(w, "bad proof encoding", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		http.Error(w, "ceremony closed", http.StatusGone)
		return
	}
	exp, known := s.chals[req.Challenge]
	if !known || time.Now().After(exp) {
		s.mu.Unlock()
		http.Error(w, "unknown or expired challenge", http.StatusUnauthorized)
		return
	}
	delete(s.chals, req.Challenge) // single use
	s.mu.Unlock()

	identity, err := prov.Verify(chalBytes, req.Identity, proof)
	if err != nil {
		http.Error(w, "authentication failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	sess := &session{id: token(), identity: identity, joined: time.Now()}
	s.mu.Lock()
	s.queue = append(s.queue, sess)
	s.promoteLocked()
	pos := s.positionLocked(sess.id)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, JoinResponse{Session: sess.id, Position: pos})
}

// positionLocked returns 0 if it's the session's active slot, else its 1-based
// place in the waiting queue, or -1 if unknown.
func (s *Sequencer) positionLocked(id string) int {
	if s.active != nil && s.active.id == id {
		return 0
	}
	for i, q := range s.queue {
		if q.id == id {
			return i + 1
		}
	}
	return -1
}

func (s *Sequencer) handleStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("session")
	s.mu.Lock()
	pos := s.positionLocked(id)
	resp := StatusResponse{Position: pos, YourTurn: pos == 0, Closed: s.closed}
	if pos == 0 {
		resp.DeadlineUnix = s.deadline.Unix()
	} else if pos >= 1 && s.avgContrib > 0 {
		// pos people are ahead (incl. the active one); est. wait = pos × avg.
		resp.EtaSeconds = int64(pos) * int64(s.avgContrib.Seconds())
	}
	s.mu.Unlock()
	if pos < 0 {
		http.Error(w, "unknown session (expired or never joined)", http.StatusGone)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleHeartbeat keeps the active slot alive while the participant is actively
// downloading/contributing/uploading (which takes many minutes). Each heartbeat
// pushes the deadline out by one slot-timeout, so someone genuinely making
// progress is never dropped - only a truly idle/dead session is.
func (s *Sequencer) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("session")
	s.mu.Lock()
	if s.active == nil || s.active.id != id {
		s.mu.Unlock()
		http.Error(w, "not your slot", http.StatusForbidden)
		return
	}
	s.deadline = time.Now().Add(s.cfg.SlotTimeout)
	dl := s.deadline.Unix()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, StatusResponse{Position: 0, YourTurn: true, DeadlineUnix: dl})
}

func (s *Sequencer) handleHead(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("session")
	s.mu.Lock()
	if s.active == nil || s.active.id != id {
		s.mu.Unlock()
		http.Error(w, "not your slot", http.StatusForbidden)
		return
	}
	head := s.head
	fp := s.circuitFP
	deadline := s.deadline
	s.mu.Unlock()
	// Serialize once so we can send Content-Length (lets the client render a real
	// download progress bar / ETA). Only the active participant reaches here, and
	// the head is stable while they hold the slot.
	var buf byteBuf
	if _, err := head.WriteTo(&buf); err != nil {
		http.Error(w, "serialize head: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(buf.b)))
	w.Header().Set("X-Circuit-Fingerprint", fp)
	w.Header().Set("X-Deadline-Unix", fmt.Sprintf("%d", deadline.Unix()))
	_, _ = w.Write(buf.b)
}

func (s *Sequencer) handleContribute(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("session")

	s.mu.Lock()
	if s.active == nil || s.active.id != id {
		s.mu.Unlock()
		http.Error(w, "not your slot", http.StatusForbidden)
		return
	}
	sess := s.active
	prevHead := s.head
	s.deadline = time.Now().Add(s.cfg.SlotTimeout) // fresh window for the (long) upload read + verify
	s.mu.Unlock()

	body := http.MaxBytesReader(w, r.Body, s.cfg.MaxBlobBytes)
	raw, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	next := s.cfg.Backend.NewPhase2()
	if _, err := next.ReadFrom(bytes.NewReader(raw)); err != nil {
		http.Error(w, "malformed contribution: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Verify the contribution extends the current head (PoK + challenge chain).
	if err := s.cfg.Backend.VerifyPhase2Step(prevHead, next); err != nil {
		http.Error(w, "contribution verification failed: "+err.Error(), http.StatusBadRequest)
		return // slot stays open until the deadline; the participant may retry
	}

	prevHash, err := HashBlob(prevHead)
	if err != nil {
		http.Error(w, "hash prev: "+err.Error(), http.StatusInternalServerError)
		return
	}
	newHash, err := HashBlob(next)
	if err != nil {
		http.Error(w, "hash next: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check the slot is still ours and the head hasn't moved (it can't, but be safe).
	if s.active == nil || s.active.id != sess.id {
		http.Error(w, "slot expired before contribution committed", http.StatusConflict)
		return
	}
	index := s.tr.Len()
	ref, err := s.cfg.Store.SaveBlob(index, next)
	if err != nil {
		http.Error(w, "persist contribution: "+err.Error(), http.StatusInternalServerError)
		return
	}
	entry := TranscriptEntry{
		Provider: sess.identity.Provider, Identity: sess.identity.ID, Display: sess.identity.Display,
		PrevSHA256: hex.EncodeToString(prevHash), NewSHA256: hex.EncodeToString(newHash),
		BlobRef: ref, Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.tr.Append(entry); err != nil {
		http.Error(w, "transcript: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Record this contribution's wall-time (slot-open -> accepted) as a rolling
	// average, so waiting participants get an honest ETA.
	if !s.activeSince.IsZero() {
		sample := time.Since(s.activeSince)
		if s.avgContrib == 0 {
			s.avgContrib = sample
		} else {
			s.avgContrib = (s.avgContrib*3 + sample) / 4 // EMA, weighted to recent
		}
	}
	s.head = next
	if err := s.cfg.Store.SaveHead(next); err != nil {
		http.Error(w, "persist head: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.cfg.Store.SaveTranscript(s.tr); err != nil {
		http.Error(w, "persist transcript: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.active = nil
	s.promoteLocked()

	writeJSON(w, http.StatusOK, ReceiptResponse{
		Index: index, PrevSHA256: entry.PrevSHA256, NewSHA256: entry.NewSHA256, BlobRef: ref,
	})
}

func (s *Sequencer) handleTranscript(w http.ResponseWriter, _ *http.Request) {
	b, err := s.tr.snapshot()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}
