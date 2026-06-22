package ceremony

import (
	"encoding/json"
	"fmt"
	"sync"
)

// TranscriptEntry records one accepted contribution. The log is append-only and
// hash-chained: prev_sha256[n] == new_sha256[n-1] (and prev_sha256[0] == the init
// head hash). Anyone can replay the chain + beacon and reproduce the keys.
type TranscriptEntry struct {
	Index       int    `json:"index"`
	Provider    string `json:"provider"`
	Identity    string `json:"identity"`
	Display     string `json:"display,omitempty"`
	PrevSHA256  string `json:"prev_sha256"`
	NewSHA256   string `json:"new_sha256"`
	BlobRef     string `json:"blob_ref,omitempty"` // storage ref; an IPFS CID in M2
	IdentitySig string `json:"identity_sig,omitempty"`
	Timestamp   string `json:"ts,omitempty"`
}

// Transcript is the public, append-only record of a ceremony.
type Transcript struct {
	mu       sync.Mutex
	Curve    string            `json:"curve"`
	Circuit  string            `json:"circuit_fingerprint"`
	InitHash string            `json:"init_sha256"` // hash of the uncontributed init head
	Entries  []TranscriptEntry `json:"entries"`
}

// Append adds an entry, enforcing the hash-chain linkage.
func (t *Transcript) Append(e TranscriptEntry) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	var wantPrev string
	if len(t.Entries) == 0 {
		wantPrev = t.InitHash
	} else {
		wantPrev = t.Entries[len(t.Entries)-1].NewSHA256
	}
	if e.PrevSHA256 != wantPrev {
		return fmt.Errorf("transcript chain break at index %d: prev=%s expected=%s", len(t.Entries), e.PrevSHA256, wantPrev)
	}
	e.Index = len(t.Entries)
	t.Entries = append(t.Entries, e)
	return nil
}

// Verify re-checks the whole chain from the init head.
func (t *Transcript) Verify() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	prev := t.InitHash
	for i, e := range t.Entries {
		if e.Index != i {
			return fmt.Errorf("entry %d has index %d", i, e.Index)
		}
		if e.PrevSHA256 != prev {
			return fmt.Errorf("chain break at index %d", i)
		}
		prev = e.NewSHA256
	}
	return nil
}

func (t *Transcript) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.Entries)
}

// snapshot returns a JSON-marshalable copy under the lock.
func (t *Transcript) snapshot() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	type alias struct {
		Curve    string            `json:"curve"`
		Circuit  string            `json:"circuit_fingerprint"`
		InitHash string            `json:"init_sha256"`
		Entries  []TranscriptEntry `json:"entries"`
	}
	return json.MarshalIndent(alias{t.Curve, t.Circuit, t.InitHash, t.Entries}, "", "  ")
}

// LoadTranscriptJSON parses a transcript document.
func LoadTranscriptJSON(b []byte) (*Transcript, error) {
	var a struct {
		Curve    string            `json:"curve"`
		Circuit  string            `json:"circuit_fingerprint"`
		InitHash string            `json:"init_sha256"`
		Entries  []TranscriptEntry `json:"entries"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, err
	}
	return &Transcript{Curve: a.Curve, Circuit: a.Circuit, InitHash: a.InitHash, Entries: a.Entries}, nil
}
