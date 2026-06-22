// Command ingest-ptau converts an existing BLS12-381 powers-of-tau "challenge"
// file (the Filecoin/zcash `powersoftau` accumulator format) into a gnark
// mpcsetup SrsCommons (commons.bin), truncated to a target power. This is the
// "reuse Phase 1" path: instead of running our own powers-of-tau, we ingest a
// public, attested one.
//
// Default source: https://trusted-setup.filecoin.io/phase1/challenge_19
// (BLS12-381, 2^27, the only public BLS12-381 PoT large enough for big circuits).
//
// The challenge file is UNCOMPRESSED (G1=96B, G2=192B), prefixed by a 64-byte
// BLAKE2b header, with arrays in this order (lengths for source power P, N=2^P):
//
//	[64B header] tau_g1[2N-1] tau_g2[N] alphaTau_g1[N] betaTau_g1[N] beta_g2[1]
//
// which is EXACTLY gnark's SrsCommons. Because points are fixed-size, we fetch
// only the power-2^power prefixes via HTTP range requests (a few GB, not 77 GB).
//
// SAFETY: the tool REFUSES to write commons.bin unless the decoded points pass
// gnark's own SRS-consistency check (SameRatioMany) plus a beta-pairing check.
// Those checks are cryptographically binding, so any decode/format error (e.g. a
// wrong G2 component order) fails the gate rather than yielding a silent bad SRS.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	gcmpc "github.com/consensys/gnark-crypto/ecc/bls12-381/mpcsetup"
	gnarkmpc "github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
)

const (
	g1Uncompressed = 96
	g2Uncompressed = 192
)

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ingest-ptau: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	url := flag.String("url", "https://trusted-setup.filecoin.io/phase1/challenge_19", "challenge file URL (range requests)")
	file := flag.String("file", "", "local challenge file (alternative to --url)")
	srcPower := flag.Uint("source-power", 27, "the challenge file's power (challenge_19 = 27)")
	power := flag.Uint("power", 0, "target power to truncate to (N = 2^power); must be <= source-power")
	header := flag.Int64("header", 64, "leading header bytes before the accumulator (BLAKE2b prefix)")
	out := flag.String("out", "commons.bin", "output gnark SrsCommons")
	probe := flag.Bool("probe", false, "only validate the encoding on a tiny prefix (generators + tau ratio), don't write")
	flag.Parse()

	if *power == 0 || *power > *srcPower {
		die("--power is required and must be in [1, source-power]")
	}

	src := &rangeSource{url: *url, file: *file, header: *header, srcPower: *srcPower}

	if *probe {
		probeEncoding(src)
		return
	}

	N := int64(1) << *power
	t0 := time.Now()
	fmt.Fprintf(os.Stderr, "ingesting power-%d prefix (N=%d) from %s ...\n", *power, N, src.name())

	tauG1 := src.readG1(arrTauG1, 0, 2*N-1)
	fmt.Fprintf(os.Stderr, "  tau_g1:     %d points\n", len(tauG1))
	tauG2 := src.readG2(arrTauG2, 0, N)
	fmt.Fprintf(os.Stderr, "  tau_g2:     %d points\n", len(tauG2))
	alphaTau := src.readG1(arrAlpha, 0, N)
	fmt.Fprintf(os.Stderr, "  alphaTau:   %d points\n", len(alphaTau))
	betaTau := src.readG1(arrBeta, 0, N)
	fmt.Fprintf(os.Stderr, "  betaTau:    %d points\n", len(betaTau))
	betaG2 := src.readG2(arrBetaG2, 0, 1)[0]
	fmt.Fprintf(os.Stderr, "  beta_g2:    1 point\n")
	fmt.Fprintf(os.Stderr, "fetched+decoded in %s\n", time.Since(t0).Round(time.Second))

	verify(tauG1, tauG2, alphaTau, betaTau, betaG2)

	var commons gnarkmpc.SrsCommons
	commons.G1.Tau = tauG1
	commons.G1.AlphaTau = alphaTau
	commons.G1.BetaTau = betaTau
	commons.G2.Tau = tauG2
	commons.G2.Beta = betaG2

	f, err := os.Create(*out)
	if err != nil {
		die("create %s: %v", *out, err)
	}
	if _, err := commons.WriteTo(f); err != nil {
		_ = f.Close()
		die("write %s: %v", *out, err)
	}
	if err := f.Close(); err != nil {
		die("close %s: %v", *out, err)
	}
	fmt.Fprintf(os.Stderr, "\nOK - wrote %s (power %d). All SRS-consistency gates passed.\n", *out, *power)
}

// ---- array identities + byte offsets ----

type arrID int

const (
	arrTauG1 arrID = iota
	arrTauG2
	arrAlpha
	arrBeta
	arrBetaG2
)

// offsetOf returns the byte offset of element index `i` within array `a`, for a
// source file of power srcPower with the given header.
func offsetOf(header int64, srcPower uint, a arrID, i int64) int64 {
	srcN := int64(1) << srcPower
	srcTauG1Len := 2*srcN - 1
	offTauG1 := header
	offTauG2 := offTauG1 + srcTauG1Len*g1Uncompressed
	offAlpha := offTauG2 + srcN*g2Uncompressed
	offBeta := offAlpha + srcN*g1Uncompressed
	offBetaG2 := offBeta + srcN*g1Uncompressed
	switch a {
	case arrTauG1:
		return offTauG1 + i*g1Uncompressed
	case arrTauG2:
		return offTauG2 + i*g2Uncompressed
	case arrAlpha:
		return offAlpha + i*g1Uncompressed
	case arrBeta:
		return offBeta + i*g1Uncompressed
	case arrBetaG2:
		return offBetaG2 + i*g2Uncompressed
	}
	panic("bad arrID")
}

// ---- range source (HTTP or local file) ----

type rangeSource struct {
	url, file string
	header    int64
	srcPower  uint
}

func (s *rangeSource) name() string {
	if s.file != "" {
		return s.file
	}
	return s.url
}

// openRange returns a reader over [start, start+length) bytes of the source.
func (s *rangeSource) openRange(start, length int64) (io.ReadCloser, error) {
	if s.file != "" {
		f, err := os.Open(s.file)
		if err != nil {
			return nil, err
		}
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			_ = f.Close()
			return nil, err
		}
		return readCloser{io.LimitReader(f, length), f}, nil
	}
	req, err := http.NewRequest(http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, start+length-1))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusPartialContent {
		resp.Body.Close()
		return nil, fmt.Errorf("expected 206 Partial Content, got %d (server may not support range requests)", resp.StatusCode)
	}
	return resp.Body, nil
}

func (s *rangeSource) readG1(a arrID, first, count int64) []curve.G1Affine {
	start := offsetOf(s.header, s.srcPower, a, first)
	rc, err := s.openRange(start, count*g1Uncompressed)
	if err != nil {
		die("range fetch g1: %v", err)
	}
	defer rc.Close()
	// Subgroup checks ON (the decoder default): the ingested SRS is what every key
	// is derived from, so each point must be a valid prime-order group element.
	// This matches what gnark's own Phase1.Verify does at decode time.
	dec := curve.NewDecoder(bufio.NewReaderSize(rc, 1<<20))
	pts := make([]curve.G1Affine, count)
	for i := range pts {
		if err := dec.Decode(&pts[i]); err != nil {
			die("decode g1[%d]: %v", i, err)
		}
	}
	return pts
}

func (s *rangeSource) readG2(a arrID, first, count int64) []curve.G2Affine {
	start := offsetOf(s.header, s.srcPower, a, first)
	rc, err := s.openRange(start, count*g2Uncompressed)
	if err != nil {
		die("range fetch g2: %v", err)
	}
	defer rc.Close()
	// Subgroup checks ON (the decoder default) - see readG1.
	dec := curve.NewDecoder(bufio.NewReaderSize(rc, 1<<20))
	pts := make([]curve.G2Affine, count)
	for i := range pts {
		if err := dec.Decode(&pts[i]); err != nil {
			die("decode g2[%d]: %v", i, err)
		}
	}
	return pts
}

type readCloser struct {
	io.Reader
	c io.Closer
}

func (r readCloser) Close() error { return r.c.Close() }

// ---- verification gates ----

func verify(tauG1 []curve.G1Affine, tauG2 []curve.G2Affine, alphaTau, betaTau []curve.G1Affine, betaG2 curve.G2Affine) {
	_, _, g1gen, g2gen := curve.Generators()

	// 1. The SRS must start at the generators (τ^0 = 1).
	if !tauG1[0].Equal(&g1gen) {
		die("verification FAILED: tau_g1[0] is not the G1 generator (wrong offset/encoding/header)")
	}
	if !tauG2[0].Equal(&g2gen) {
		die("verification FAILED: tau_g2[0] is not the G2 generator (wrong offset/encoding/header)")
	}

	// 2. gnark's own SRS-consistency check: tau_g1, tau_g2, alphaTau, betaTau are
	//    all geometric sequences with the same ratio τ. Cryptographically binding.
	if err := gcmpc.SameRatioMany(tauG1, tauG2, alphaTau, betaTau); err != nil {
		die("verification FAILED: SameRatioMany: %v", err)
	}

	// 3. beta_g2 consistency: e(betaTau[0], g2gen) == e(g1gen, beta_g2), i.e. the
	//    β in beta_g2=[β]₂ matches the β in betaTau[0]=[β]₁.
	var negG1 curve.G1Affine
	negG1.Neg(&g1gen)
	ok, err := curve.PairingCheck(
		[]curve.G1Affine{betaTau[0], negG1},
		[]curve.G2Affine{g2gen, betaG2},
	)
	if err != nil {
		die("verification FAILED: beta pairing: %v", err)
	}
	if !ok {
		die("verification FAILED: beta_g2 inconsistent with betaTau[0]")
	}
	fmt.Fprintln(os.Stderr, "verification OK: generators + SameRatioMany + beta-pairing all pass.")
}

// probeEncoding downloads only tiny 2-element prefixes of ALL FIVE arrays and runs
// the full verification gate on them. This validates every byte offset and the
// encoding (including the G2 component order) against real data, for ~a few KB -
// so the full multi-GB ingest is high-confidence before it starts.
func probeEncoding(s *rangeSource) {
	const n = 16 // small but enough for SameRatioMany's linear-combination logic
	tauG1 := s.readG1(arrTauG1, 0, n)
	tauG2 := s.readG2(arrTauG2, 0, n)
	alphaTau := s.readG1(arrAlpha, 0, n)
	betaTau := s.readG1(arrBeta, 0, n)
	betaG2 := s.readG2(arrBetaG2, 0, 1)[0]

	_, _, g1gen, g2gen := curve.Generators()
	fmt.Fprintf(os.Stderr, "tau_g1[0]==G1 generator: %v\n", tauG1[0].Equal(&g1gen))
	fmt.Fprintf(os.Stderr, "tau_g2[0]==G2 generator: %v\n", tauG2[0].Equal(&g2gen))

	// Full gate on the 2-element prefixes (generators + SameRatioMany + beta-pairing).
	verify(tauG1, tauG2, alphaTau, betaTau, betaG2)
	fmt.Fprintln(os.Stderr, "\nENCODING + ALL OFFSETS CONFIRMED on real data - safe to run the full ingest.")
}
