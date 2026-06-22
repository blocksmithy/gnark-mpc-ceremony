package ceremony

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Identity is a verified participant identity recorded in the transcript.
type Identity struct {
	Provider string `json:"provider"`
	ID       string `json:"id"`
	Display  string `json:"display,omitempty"`
}

// AuthProvider gates who may enter the lobby and binds a name to each
// contribution. Auth has ZERO bearing on soundness (it is about Sybil/DoS
// resistance and credibility, not the trapdoor), so providers are swappable.
//
// Verify checks that `proof` authenticates `identity` against the server-issued
// single-use `challenge`.
type AuthProvider interface {
	Name() string
	Verify(challenge []byte, identity string, proof []byte) (Identity, error)
}

// Ed25519Allowlist authenticates an ed25519 public key (hex) that is on a curated
// allowlist, by an ed25519 signature over the server challenge. This is the
// cryptographic core of Cardano wallet auth (Cardano keys are ed25519); the full
// CIP-8/CIP-30 COSE_Sign1 wallet provider wraps this once its exact format is
// confirmed against the CIP text (see docs §11). Good for the dev-team test and a
// curated testnet ceremony.
type Ed25519Allowlist struct {
	allow map[string]string // pubkeyHex -> display name
}

// NewEd25519Allowlist builds an allowlist from {pubkeyHex: display} entries.
func NewEd25519Allowlist(entries map[string]string) *Ed25519Allowlist {
	m := make(map[string]string, len(entries))
	for k, v := range entries {
		m[k] = v
	}
	return &Ed25519Allowlist{allow: m}
}

func (a *Ed25519Allowlist) Name() string { return "ed25519-allowlist" }

func (a *Ed25519Allowlist) Verify(challenge []byte, identity string, proof []byte) (Identity, error) {
	display, ok := a.allow[identity]
	if !ok {
		return Identity{}, fmt.Errorf("identity %q is not on the allowlist", identity)
	}
	pub, err := hex.DecodeString(identity)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return Identity{}, fmt.Errorf("identity %q is not a valid ed25519 public key", identity)
	}
	if len(proof) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), challenge, proof) {
		return Identity{}, fmt.Errorf("signature verification failed for %q", identity)
	}
	return Identity{Provider: a.Name(), ID: identity, Display: display}, nil
}

// GenerateKey makes a fresh ed25519 keypair (hex). The public key is the
// participant's allowlist identity; the private key signs the join challenge.
func GenerateKey() (pubHex, privHex string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(pub), hex.EncodeToString(priv), nil
}

// SignChallenge signs a server challenge with an ed25519 private key (hex).
func SignChallenge(privHex string, challenge []byte) ([]byte, error) {
	priv, err := hex.DecodeString(privHex)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key")
	}
	return ed25519.Sign(ed25519.PrivateKey(priv), challenge), nil
}

// PublicFromPrivate derives the hex public key from a hex private key.
func PublicFromPrivate(privHex string) (string, error) {
	priv, err := hex.DecodeString(privHex)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid ed25519 private key")
	}
	pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub), nil
}

// TokenAllowlist is the simplest login: a curated set of opaque bearer tokens
// ("login keys" / invite codes), each mapped to a participant name. The
// coordinator generates the tokens and hands one to each teammate; the teammate
// presents it to join. There is NO signing and NO private key to distribute - a
// token is just an access credential. Auth has zero bearing on soundness, so for
// a dev-team / curated testnet ceremony this is sufficient (and what to use).
//
// (For a public ceremony, swap in the Cardano-wallet / OAuth providers - see the
// roadmap. The ed25519 provider above remains available as a no-secret-sent
// alternative.)
type TokenAllowlist struct {
	allow map[string]string // tokenHex -> display name
}

// NewTokenAllowlist builds a token allowlist from {tokenHex: name} entries.
func NewTokenAllowlist(entries map[string]string) *TokenAllowlist {
	m := make(map[string]string, len(entries))
	for k, v := range entries {
		m[k] = v
	}
	return &TokenAllowlist{allow: m}
}

func (a *TokenAllowlist) Name() string { return "token" }

func (a *TokenAllowlist) Verify(_ []byte, _ string, proof []byte) (Identity, error) {
	tok := hex.EncodeToString(proof)
	name, ok := a.allow[tok]
	if !ok {
		return Identity{}, fmt.Errorf("invalid login token")
	}
	display := name
	if display == "" {
		display = "anonymous"
	}
	return Identity{Provider: a.Name(), ID: name, Display: display}, nil
}

// GenerateToken makes a fresh opaque login token (16 random bytes, hex).
func GenerateToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
