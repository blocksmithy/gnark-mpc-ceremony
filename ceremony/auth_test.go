package ceremony

import (
	"encoding/hex"
	"testing"
)

func TestTokenAllowlist(t *testing.T) {
	tok, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	a := NewTokenAllowlist(map[string]string{tok: "alice"})

	// proof bytes are the server's hex-decode of the token the client sent.
	proof, _ := hex.DecodeString(tok)
	id, err := a.Verify(nil, "", proof)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if id.Display != "alice" || id.Provider != "token" {
		t.Fatalf("unexpected identity %+v", id)
	}

	// an unknown token must be rejected.
	bad, _ := GenerateToken()
	badProof, _ := hex.DecodeString(bad)
	if _, err := a.Verify(nil, "", badProof); err == nil {
		t.Fatal("unknown token accepted")
	}
}

func TestEd25519Allowlist(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	a := NewEd25519Allowlist(map[string]string{pub: "bob"})

	challenge := []byte("server-challenge-bytes")
	sig, err := SignChallenge(priv, challenge)
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.Verify(challenge, pub, sig)
	if err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if id.Display != "bob" {
		t.Fatalf("unexpected identity %+v", id)
	}

	// wrong challenge must fail (signature won't verify).
	if _, err := a.Verify([]byte("different"), pub, sig); err == nil {
		t.Fatal("signature verified against the wrong challenge")
	}
	// off-allowlist key must fail even with a valid signature.
	otherPub, otherPriv, _ := GenerateKey()
	otherSig, _ := SignChallenge(otherPriv, challenge)
	if _, err := a.Verify(challenge, otherPub, otherSig); err == nil {
		t.Fatal("off-allowlist identity accepted")
	}
}
