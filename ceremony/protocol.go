package ceremony

// HTTP DTOs shared by the sequencer and the participant client. The wire format
// is plain JSON (+ raw blob bodies for state transfer) so a wasm/browser client
// can be added later without changing the sequencer.

// InfoResponse is the public, unauthenticated ceremony status (GET /info).
type InfoResponse struct {
	Curve                  string `json:"curve"`
	CircuitFingerprint     string `json:"circuit_fingerprint"`
	Contributions          int    `json:"contributions"`
	QueueLen               int    `json:"queue_len"`
	SlotActive             bool   `json:"slot_active"`
	Closed                 bool   `json:"closed"`
	AvgContributionSeconds int64  `json:"avg_contribution_seconds,omitempty"` // rolling avg wall-time per contribution
}

// ChallengeResponse carries a single-use server nonce (GET /auth/challenge).
type ChallengeResponse struct {
	Challenge string `json:"challenge"` // hex
}

// JoinRequest authenticates and enters the lobby (POST /lobby/join).
type JoinRequest struct {
	Provider  string `json:"provider"`
	Identity  string `json:"identity"`
	Challenge string `json:"challenge"` // hex, echoed from /auth/challenge
	Proof     string `json:"proof"`     // hex signature over the challenge
}

// JoinResponse returns the session token and queue position.
type JoinResponse struct {
	Session  string `json:"session"`
	Position int    `json:"position"` // 0 == it is your slot now
}

// StatusResponse reports the caller's lobby position (GET /lobby/status).
type StatusResponse struct {
	Position     int   `json:"position"`
	YourTurn     bool  `json:"your_turn"`
	DeadlineUnix int64 `json:"deadline_unix,omitempty"`
	EtaSeconds   int64 `json:"eta_seconds,omitempty"` // est. seconds until your turn (position × avg), 0 if unknown
	Closed       bool  `json:"closed"`
}

// ReceiptResponse confirms an accepted contribution (POST /slot/contribute).
type ReceiptResponse struct {
	Index      int    `json:"index"`
	PrevSHA256 string `json:"prev_sha256"`
	NewSHA256  string `json:"new_sha256"`
	BlobRef    string `json:"blob_ref"`
}
