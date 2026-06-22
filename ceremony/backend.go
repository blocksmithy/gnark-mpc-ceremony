// Package ceremony is a reusable, circuit-agnostic Groth16 trusted-setup (MPC)
// coordinator built on gnark's mpcsetup. It drives a Phase-1 + Phase-2 ceremony
// for ANY gnark circuit (consumed as a serialized constraint system, ccs.bin) and
// scales via a sequencer service (lobby/queue/slot/verify-advance/transcript).
//
// Soundness invariant: the contribution step - generating fresh
// secret randomness and folding it in - runs ONLY on the participant's own
// machine (ContributePhase1/ContributePhase2). The coordinator NEVER generates,
// receives, or sees any secret; it only ever operates on PUBLIC blobs
// (Init*/Verify*/Seal*/Finalize*). A Groth16 setup is sound as long as at least
// one contributor generated real randomness and destroyed it; the trapdoor is the
// product of every contributor's secret. A fully-compromised coordinator that
// only handles public blobs cannot recover the trapdoor or forge a contribution.
package ceremony

import (
	"crypto/sha256"
	"fmt"
	"io"
)

// Blob is an opaque, serializable MPC state: a Phase-1 or Phase-2 contribution,
// or the sealed Phase-1 commons. The coordinator shuttles and hashes Blobs
// without interpreting them; only a Backend understands their internals.
type Blob interface {
	io.WriterTo
	io.ReaderFrom
}

// Keys is the output of a finalized Phase-2 ceremony: standard gnark serialized
// constraint system + proving/verifying keys, plus the VK fingerprint a prover
// pins to fail closed on any non-ceremony key. Projects convert VK to their own
// on-chain wire format separately - this tool stays generic.
type Keys struct {
	CCS           []byte
	PK            []byte
	VK            []byte
	VKFingerprint string // sha256 hex of the canonical gnark VK serialization
}

// Backend abstracts the curve-specific Groth16 MPC operations (gnark mpcsetup).
// M1 implements BLS12-381 only; this interface is the seam that keeps adding a
// curve (BN254, BLS12-377, BW6-761) additive - see BackendFor.
type Backend interface {
	CurveName() string

	// ---- Phase 2: circuit-specific (the sequencer path + finalize) ----
	NewPhase2() Blob
	InitPhase2(ccs, commons io.Reader) (Blob, error)
	ContributePhase2(b Blob) error // soundness invariant: local secret; participant only
	VerifyPhase2Step(prev, next Blob) error
	FinalizePhase2(ccs, commons io.Reader, beacon []byte, chain []Blob) (*Keys, error)

	// ---- Phase 1: circuit-independent (CLI helper; production reuses an external PoT) ----
	NewPhase1() Blob
	InitPhase1(power uint8) (Blob, error)
	ContributePhase1(b Blob) error // soundness invariant: local secret; participant only
	VerifyPhase1Step(prev, next Blob) error
	SealPhase1(power uint8, beacon []byte, chain []Blob) (commons Blob, err error)

	// CircuitFingerprint is sha256 of the canonical serialized constraint system -
	// the circuit identity a ceremony keys (compare to a pinned circuit_id).
	CircuitFingerprint(ccs io.Reader) (string, error)
}

// BackendFor returns the MPC backend for a curve. M1: bls12-381 only; the switch
// is where BN254/BLS12-377/BW6-761 backends slot in additively.
func BackendFor(curve string) (Backend, error) {
	switch curve {
	case "bls12-381", "bls12381", "BLS12_381", "":
		return blsBackend{}, nil
	default:
		return nil, fmt.Errorf("unsupported curve %q (M1 implements bls12-381 only)", curve)
	}
}

// HashBlob returns sha256(blob serialization). This is the SAME hash gnark
// mpcsetup uses as the challenge-chain link, so a Phase-2 blob's hash IS its
// successor's expected Challenge - the transcript chain and the cryptographic
// chain are one and the same.
func HashBlob(b Blob) ([]byte, error) {
	h := sha256.New()
	if _, err := b.WriteTo(h); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
