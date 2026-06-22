package ceremony

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	mpcsetup "github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
	cs "github.com/consensys/gnark/constraint/bls12-381"
)

// blsBackend implements Backend over gnark's bls12-381 mpcsetup.
type blsBackend struct{}

func (blsBackend) CurveName() string { return "bls12-381" }

func (blsBackend) NewPhase1() Blob { return new(mpcsetup.Phase1) }
func (blsBackend) NewPhase2() Blob { return new(mpcsetup.Phase2) }

func readR1CS(r io.Reader) (*cs.R1CS, error) {
	ccs := groth16.NewCS(ecc.BLS12_381)
	if _, err := ccs.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("read ccs: %w", err)
	}
	r1cs, ok := ccs.(*cs.R1CS)
	if !ok {
		return nil, fmt.Errorf("unexpected constraint system type %T (want *bls12-381.R1CS)", ccs)
	}
	return r1cs, nil
}

func readCommons(r io.Reader) (*mpcsetup.SrsCommons, error) {
	var c mpcsetup.SrsCommons
	if _, err := c.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("read commons: %w", err)
	}
	return &c, nil
}

// ---- Phase 1 ----

func (blsBackend) InitPhase1(power uint8) (Blob, error) {
	return mpcsetup.NewPhase1(uint64(1) << power), nil
}

func (blsBackend) ContributePhase1(b Blob) error {
	p, ok := b.(*mpcsetup.Phase1)
	if !ok {
		return fmt.Errorf("not a bls12-381 phase1 blob: %T", b)
	}
	p.Contribute() // secret randomness generated internally and dropped on return
	return nil
}

func (blsBackend) VerifyPhase1Step(prev, next Blob) error {
	p, ok := prev.(*mpcsetup.Phase1)
	if !ok {
		return fmt.Errorf("prev not a phase1 blob: %T", prev)
	}
	n, ok := next.(*mpcsetup.Phase1)
	if !ok {
		return fmt.Errorf("next not a phase1 blob: %T", next)
	}
	return p.Verify(n)
}

func (blsBackend) SealPhase1(power uint8, beacon []byte, chain []Blob) (Blob, error) {
	ps := make([]*mpcsetup.Phase1, len(chain))
	for i, b := range chain {
		p, ok := b.(*mpcsetup.Phase1)
		if !ok {
			return nil, fmt.Errorf("chain[%d] not a phase1 blob: %T", i, b)
		}
		ps[i] = p
	}
	commons, err := mpcsetup.VerifyPhase1(uint64(1)<<power, beacon, ps...)
	if err != nil {
		return nil, err
	}
	return &commons, nil
}

// ---- Phase 2 ----

func (blsBackend) InitPhase2(ccs, commons io.Reader) (Blob, error) {
	r1cs, err := readR1CS(ccs)
	if err != nil {
		return nil, err
	}
	cm, err := readCommons(commons)
	if err != nil {
		return nil, err
	}
	var p mpcsetup.Phase2
	p.Initialize(r1cs, cm)
	return &p, nil
}

func (blsBackend) ContributePhase2(b Blob) error {
	p, ok := b.(*mpcsetup.Phase2)
	if !ok {
		return fmt.Errorf("not a bls12-381 phase2 blob: %T", b)
	}
	p.Contribute() // secret randomness generated internally and dropped on return
	return nil
}

func (blsBackend) VerifyPhase2Step(prev, next Blob) error {
	p, ok := prev.(*mpcsetup.Phase2)
	if !ok {
		return fmt.Errorf("prev not a phase2 blob: %T", prev)
	}
	n, ok := next.(*mpcsetup.Phase2)
	if !ok {
		return fmt.Errorf("next not a phase2 blob: %T", next)
	}
	return p.Verify(n)
}

func (blsBackend) FinalizePhase2(ccs, commons io.Reader, beacon []byte, chain []Blob) (*Keys, error) {
	r1cs, err := readR1CS(ccs)
	if err != nil {
		return nil, err
	}
	cm, err := readCommons(commons)
	if err != nil {
		return nil, err
	}
	ps := make([]*mpcsetup.Phase2, len(chain))
	for i, b := range chain {
		p, ok := b.(*mpcsetup.Phase2)
		if !ok {
			return nil, fmt.Errorf("chain[%d] not a phase2 blob: %T", i, b)
		}
		ps[i] = p
	}
	pk, vk, err := mpcsetup.VerifyPhase2(r1cs, cm, beacon, ps...)
	if err != nil {
		return nil, err
	}

	var pkBuf, vkBuf, ccsBuf byteBuf
	if _, err := pk.WriteTo(&pkBuf); err != nil {
		return nil, fmt.Errorf("serialize pk: %w", err)
	}
	if _, err := vk.WriteTo(&vkBuf); err != nil {
		return nil, fmt.Errorf("serialize vk: %w", err)
	}
	if _, err := r1cs.WriteTo(&ccsBuf); err != nil {
		return nil, fmt.Errorf("serialize ccs: %w", err)
	}
	fp := sha256.Sum256(vkBuf.b)
	return &Keys{
		CCS:           ccsBuf.b,
		PK:            pkBuf.b,
		VK:            vkBuf.b,
		VKFingerprint: hex.EncodeToString(fp[:]),
	}, nil
}

func (blsBackend) CircuitFingerprint(ccs io.Reader) (string, error) {
	r1cs, err := readR1CS(ccs)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := r1cs.WriteTo(h); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// byteBuf is a minimal io.Writer collecting bytes (avoids bytes.Buffer's Read side).
type byteBuf struct{ b []byte }

func (w *byteBuf) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }
