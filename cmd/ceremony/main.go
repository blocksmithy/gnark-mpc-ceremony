// Command ceremony is the participant + coordinator CLI for a reusable, circuit-
// agnostic Groth16 MPC trusted setup (gnark mpcsetup). It works on any gnark
// circuit, consumed as a serialized constraint system (ccs.bin).
//
// Soundness invariant: phase1-contribute / phase2-contribute / join generate secret
// randomness and run on the PARTICIPANT's machine; the secret is never written to
// disk and never leaves the process. The coordinator subcommands only ever touch
// public blobs. See the ceremony package docs.
//
//	keygen            --out NAME                              # ed25519 identity (NAME.pub / NAME.key)
//
//	phase1-init       --power N --out p1_0000.bin
//	phase1-contribute --in PREV --out NEXT
//	phase1-seal       --power N --beacon HEX --out commons.bin  C1 C2 ... CN
//
//	phase2-init       --ccs ccs.bin --commons commons.bin --out p2_0000.bin
//	phase2-contribute --in PREV --out NEXT
//	phase2-finalize   --ccs ccs.bin --commons commons.bin --beacon HEX --keys DIR  C1 C2 ... CN
//
//	verify-circuit    --ccs ccs.bin                          # print the circuit fingerprint
//	join              --server URL --provider P --identity PUB --key NAME.key [--expect-circuit FP]
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blocksmithy/gnark-mpc-ceremony/ceremony"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	curve := "bls12-381"
	backend, err := ceremony.BackendFor(curve)
	if err != nil {
		die("%v", err)
	}
	switch os.Args[1] {
	case "keygen":
		keygen(os.Args[2:])
	case "keygen-team":
		keygenTeam(os.Args[2:])
	case "phase1-init":
		phase1Init(backend, os.Args[2:])
	case "phase1-contribute":
		phase1Contribute(backend, os.Args[2:])
	case "phase1-seal":
		phase1Seal(backend, os.Args[2:])
	case "phase2-init":
		phase2Init(backend, os.Args[2:])
	case "phase2-contribute":
		phase2Contribute(backend, os.Args[2:])
	case "phase2-finalize":
		phase2Finalize(backend, os.Args[2:])
	case "verify-circuit":
		verifyCircuit(backend, os.Args[2:])
	case "join":
		join(backend, os.Args[2:])
	case "transcript":
		cmdTranscript(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ceremony <keygen|keygen-team|phase1-init|phase1-contribute|phase1-seal|"+
		"phase2-init|phase2-contribute|phase2-finalize|verify-circuit|join|transcript> [flags]")
	os.Exit(2)
}

// cmdTranscript prints the coordinator's auto-collected record of every accepted
// contribution (names, timestamps, hashes) - no manual receipt-gathering needed.
func cmdTranscript(args []string) {
	fs := flag.NewFlagSet("transcript", flag.ExitOnError)
	server := fs.String("server", "", "sequencer base URL")
	_ = fs.Parse(args)
	if *server == "" {
		die("--server is required")
	}
	tr, err := ceremony.FetchTranscript(*server)
	if err != nil {
		die("fetch transcript: %v", err)
	}
	fmt.Printf("circuit %s\n%d contribution(s) recorded:\n\n", tr.Circuit, len(tr.Entries))
	fmt.Printf("%-3s  %-16s  %-20s  %s\n", "#", "who", "when (UTC)", "new_sha256")
	for _, e := range tr.Entries {
		fmt.Printf("%-3d  %-16s  %-20s  %s\n", e.Index, e.Display, e.Timestamp, e.NewSHA256)
	}
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ceremony: "+format+"\n", a...)
	os.Exit(1)
}

func writeBlob(path string, b ceremony.Blob) {
	f, err := os.Create(path)
	if err != nil {
		die("create %s: %v", path, err)
	}
	if _, err := b.WriteTo(f); err != nil {
		_ = f.Close()
		die("write %s: %v", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		die("sync %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		die("close %s: %v", path, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", path)
}

func readBlob(path string, b ceremony.Blob) {
	f, err := os.Open(path)
	if err != nil {
		die("open %s: %v", path, err)
	}
	defer f.Close()
	if _, err := b.ReadFrom(f); err != nil {
		die("read %s: %v", path, err)
	}
}

func mustOpen(path string) *os.File {
	f, err := os.Open(path)
	if err != nil {
		die("open %s: %v", path, err)
	}
	return f
}

func mustBeacon(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) == 0 {
		die("--beacon must be non-empty hex (a public random beacon fixed AFTER the last contribution)")
	}
	return b
}

// ---- keygen ----

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "participant", "basename for NAME.pub / NAME.key")
	_ = fs.Parse(args)
	pub, priv, err := ceremony.GenerateKey()
	if err != nil {
		die("generate key: %v", err)
	}
	if err := os.WriteFile(*out+".pub", []byte(pub+"\n"), 0o644); err != nil {
		die("write pub: %v", err)
	}
	if err := os.WriteFile(*out+".key", []byte(priv+"\n"), 0o600); err != nil {
		die("write key: %v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s.pub and %s.key (keep %s.key secret)\n", *out, *out, *out)
	fmt.Println(pub) // the allowlist identity
}

// keygenTeam mints N opaque login tokens (bearer credentials) and writes both the
// sequencer allowlist and a private handout sheet. The coordinator gives ONE
// token to each teammate; there are no private keys to distribute. Auth gates
// participation only - it has no bearing on soundness.
func keygenTeam(args []string) {
	fs := flag.NewFlagSet("keygen-team", flag.ExitOnError)
	n := fs.Int("n", 10, "number of login tokens to generate")
	prefix := fs.String("prefix", "dev", "participant name prefix")
	allowOut := fs.String("allowlist", "allow.txt", "allowlist for the sequencer ('<token> <name>' per line)")
	handoutOut := fs.String("handout", "tokens.txt", "private handout sheet ('<name> <token>' per line)")
	_ = fs.Parse(args)
	if *n <= 0 {
		die("--n must be > 0")
	}
	var allow, handout strings.Builder
	for i := 1; i <= *n; i++ {
		tok, err := ceremony.GenerateToken()
		if err != nil {
			die("generate token: %v", err)
		}
		name := fmt.Sprintf("%s-%02d", *prefix, i)
		fmt.Fprintf(&allow, "%s %s\n", tok, name)
		fmt.Fprintf(&handout, "%s %s\n", name, tok)
	}
	if err := os.WriteFile(*allowOut, []byte(allow.String()), 0o644); err != nil {
		die("write allowlist: %v", err)
	}
	if err := os.WriteFile(*handoutOut, []byte(handout.String()), 0o600); err != nil {
		die("write handout: %v", err)
	}
	fmt.Fprintf(os.Stderr, "generated %d login tokens\n  sequencer allowlist : %s   (pass to `sequencer --allowlist`)\n  handout sheet       : %s   (share ONE token per teammate, privately)\n", *n, *allowOut, *handoutOut)
}

// ---- phase 1 ----

func phase1Init(b ceremony.Backend, args []string) {
	fs := flag.NewFlagSet("phase1-init", flag.ExitOnError)
	power := fs.Uint("power", 0, "log2 of the SRS size; must be >= log2(circuit constraints)")
	out := fs.String("out", "p1_0000.bin", "output: initial (uncontributed) Phase1 state")
	_ = fs.Parse(args)
	if *power == 0 {
		die("--power is required")
	}
	p, err := b.InitPhase1(uint8(*power))
	if err != nil {
		die("%v", err)
	}
	writeBlob(*out, p)
}

func phase1Contribute(b ceremony.Backend, args []string) {
	fs := flag.NewFlagSet("phase1-contribute", flag.ExitOnError)
	in := fs.String("in", "", "previous Phase1 state")
	out := fs.String("out", "", "your contributed Phase1 state")
	_ = fs.Parse(args)
	if *in == "" || *out == "" {
		die("--in and --out are required")
	}
	p := b.NewPhase1()
	readBlob(*in, p)
	fmt.Fprintln(os.Stderr, "contributing (fresh local entropy; discarded on exit)...")
	if err := b.ContributePhase1(p); err != nil {
		die("%v", err)
	}
	writeBlob(*out, p)
}

func phase1Seal(b ceremony.Backend, args []string) {
	fs := flag.NewFlagSet("phase1-seal", flag.ExitOnError)
	power := fs.Uint("power", 0, "log2 SRS size used at init (must match)")
	beacon := fs.String("beacon", "", "public random beacon (hex), fixed AFTER the last contribution")
	out := fs.String("out", "commons.bin", "output: sealed phase-1 commons")
	_ = fs.Parse(args)
	contribs := fs.Args()
	if *power == 0 || *beacon == "" || len(contribs) == 0 {
		die("--power, --beacon and >=1 contribution file are required")
	}
	chain := make([]ceremony.Blob, len(contribs))
	for i, c := range contribs {
		chain[i] = b.NewPhase1()
		readBlob(c, chain[i])
	}
	fmt.Fprintf(os.Stderr, "verifying %d phase-1 contributions + applying beacon...\n", len(chain))
	commons, err := b.SealPhase1(uint8(*power), mustBeacon(*beacon), chain)
	if err != nil {
		die("phase-1 verification FAILED: %v", err)
	}
	writeBlob(*out, commons)
	fmt.Fprintln(os.Stderr, "OK - phase 1 sealed (circuit-independent, reusable).")
}

// ---- phase 2 ----

func phase2Init(b ceremony.Backend, args []string) {
	fs := flag.NewFlagSet("phase2-init", flag.ExitOnError)
	ccs := fs.String("ccs", "", "compiled circuit (ccs.bin)")
	commons := fs.String("commons", "commons.bin", "sealed phase-1 commons")
	out := fs.String("out", "p2_0000.bin", "output: initial (uncontributed) Phase2 state")
	_ = fs.Parse(args)
	if *ccs == "" {
		die("--ccs is required")
	}
	fc := mustOpen(*ccs)
	defer fc.Close()
	fm := mustOpen(*commons)
	defer fm.Close()
	p, err := b.InitPhase2(fc, fm)
	if err != nil {
		die("%v", err)
	}
	writeBlob(*out, p)
}

func phase2Contribute(b ceremony.Backend, args []string) {
	fs := flag.NewFlagSet("phase2-contribute", flag.ExitOnError)
	in := fs.String("in", "", "previous Phase2 state")
	out := fs.String("out", "", "your contributed Phase2 state")
	_ = fs.Parse(args)
	if *in == "" || *out == "" {
		die("--in and --out are required")
	}
	p := b.NewPhase2()
	readBlob(*in, p)
	fmt.Fprintln(os.Stderr, "contributing (fresh local entropy; discarded on exit)...")
	if err := b.ContributePhase2(p); err != nil {
		die("%v", err)
	}
	writeBlob(*out, p)
}

func phase2Finalize(b ceremony.Backend, args []string) {
	fs := flag.NewFlagSet("phase2-finalize", flag.ExitOnError)
	ccs := fs.String("ccs", "", "compiled circuit (ccs.bin)")
	commons := fs.String("commons", "commons.bin", "sealed phase-1 commons")
	beacon := fs.String("beacon", "", "public random beacon (hex), fixed AFTER the last contribution")
	keys := fs.String("keys", "", "output keys dir (ccs/pk/vk.bin)")
	_ = fs.Parse(args)
	contribs := fs.Args()
	if *ccs == "" || *beacon == "" || *keys == "" || len(contribs) == 0 {
		die("--ccs, --beacon, --keys and >=1 contribution file are required")
	}
	chain := make([]ceremony.Blob, len(contribs))
	for i, c := range contribs {
		chain[i] = b.NewPhase2()
		readBlob(c, chain[i])
	}
	fc := mustOpen(*ccs)
	defer fc.Close()
	fm := mustOpen(*commons)
	defer fm.Close()
	fmt.Fprintf(os.Stderr, "verifying %d phase-2 contributions + applying beacon -> deriving keys...\n", len(chain))
	res, err := b.FinalizePhase2(fc, fm, mustBeacon(*beacon), chain)
	if err != nil {
		die("phase-2 verification FAILED: %v", err)
	}
	if err := os.MkdirAll(*keys, 0o755); err != nil {
		die("mkdir keys: %v", err)
	}
	for name, data := range map[string][]byte{"ccs.bin": res.CCS, "pk.bin": res.PK, "vk.bin": res.VK} {
		if err := os.WriteFile(filepath.Join(*keys, name), data, 0o644); err != nil {
			die("write %s: %v", name, err)
		}
	}
	fmt.Fprintf(os.Stderr, "\nCEREMONY COMPLETE. Keys written to %s.\n", *keys)
	fmt.Fprintf(os.Stderr, "Pin this VK fingerprint so the prover accepts ONLY these keys:\n  %s\n", res.VKFingerprint)
	fmt.Println(res.VKFingerprint)
}

func verifyCircuit(b ceremony.Backend, args []string) {
	fs := flag.NewFlagSet("verify-circuit", flag.ExitOnError)
	ccs := fs.String("ccs", "", "compiled circuit (ccs.bin)")
	_ = fs.Parse(args)
	if *ccs == "" {
		die("--ccs is required")
	}
	fc := mustOpen(*ccs)
	defer fc.Close()
	fp, err := b.CircuitFingerprint(fc)
	if err != nil {
		die("%v", err)
	}
	fmt.Fprintf(os.Stderr, "circuit_fingerprint=%s\n", fp)
	fmt.Println(fp)
}

// ---- join (participant client) ----

func join(b ceremony.Backend, args []string) {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	server := fs.String("server", "", "sequencer base URL")
	tokenFlag := fs.String("token", "", "your login token (simplest); or use --key for ed25519 mode")
	provider := fs.String("provider", "", "auth provider (default: token if --token, else ed25519-allowlist)")
	identity := fs.String("identity", "", "ed25519 mode: your pubkey hex; defaults to the key's pubkey")
	keyfile := fs.String("key", "", "ed25519 mode: your private key file (from keygen)")
	expect := fs.String("expect-circuit", "", "optional: required circuit fingerprint (REFUSE if mismatch)")
	_ = fs.Parse(args)
	if *server == "" {
		die("--server is required")
	}
	if *tokenFlag == "" && *keyfile == "" {
		die("provide --token (login token) or --key (ed25519 key file)")
	}

	cfg := ceremony.ClientConfig{
		ServerURL: *server, Provider: *provider, Backend: b, ExpectCircuit: *expect,
		Log: func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) },
	}
	if *tokenFlag != "" {
		cfg.Token = strings.TrimSpace(*tokenFlag)
	} else {
		privRaw, err := os.ReadFile(*keyfile)
		if err != nil {
			die("read key: %v", err)
		}
		cfg.PrivHex = trimHex(string(privRaw))
		cfg.Identity = *identity
	}
	receipt, err := ceremony.Join(cfg)
	if err != nil {
		die("%v", err)
	}
	fmt.Fprintf(os.Stderr, "\nCONTRIBUTION ACCEPTED & auto-recorded in the transcript - the coordinator already has it, nothing to send.\n")
	fmt.Fprintf(os.Stderr, "  (your copy: index=%d new=%s)\n", receipt.Index, receipt.NewSHA256)
	fmt.Println(receipt.NewSHA256)
}

func trimHex(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			out = append(out, c)
		}
	}
	return string(out)
}
