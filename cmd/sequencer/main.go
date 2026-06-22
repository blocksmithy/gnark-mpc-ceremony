// Command sequencer runs the scalable Phase-2 ceremony coordinator: a lobby +
// queue + single advancing head, verifying each contribution and appending it to
// a public hash-chained transcript. It only ever handles PUBLIC blobs - it never
// runs a contribution or sees a secret (see the soundness invariant in the ceremony package).
//
//	sequencer --ccs ccs.bin --commons commons.bin --store ./state \
//	          --allowlist allow.txt [--listen :8080] [--slot-timeout 10m]
//
// allow.txt: one participant per line, "<ed25519-pubkey-hex> <display name>".
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blocksmithy/gnark-mpc-ceremony/ceremony"
)

func main() {
	listen := flag.String("listen", ":8080", "listen address")
	ccsPath := flag.String("ccs", "", "compiled circuit (ccs.bin)")
	commonsPath := flag.String("commons", "commons.bin", "sealed phase-1 commons")
	storeDir := flag.String("store", "./ceremony-state", "state directory (head, transcript, blobs)")
	allowPath := flag.String("allowlist", "", "allowlist file: '<token-or-pubkey> <name>' per line")
	authMode := flag.String("auth", "token", "auth provider: token (login tokens) | ed25519-allowlist")
	slotTimeout := flag.Duration("slot-timeout", 10*time.Minute, "abandon an idle slot after this long (head unchanged)")
	curve := flag.String("curve", "bls12-381", "curve (M1: bls12-381 only)")
	dist := flag.String("dist", "", "optional: directory of client binaries to serve at /download/")
	initHeadPath := flag.String("init-head", "", "pre-computed phase2-init head (p2_0000.bin); lets a light VM skip --ccs/--commons + the heavy InitPhase2")
	circuitFPFlag := flag.String("circuit-fp", "", "circuit fingerprint to publish (required with --init-head)")
	flag.Parse()

	if *allowPath == "" {
		fmt.Fprintln(os.Stderr, "sequencer: --allowlist is required")
		os.Exit(2)
	}

	backend, err := ceremony.BackendFor(*curve)
	if err != nil {
		fatal(err)
	}

	// circuitFP is known immediately (the flag, or a quick hash of ccs). The SLOW
	// part - loading/computing the init head - is deferred to a goroutine so the
	// server answers health checks right away ("warming up"), instead of the proxy
	// failing the machine during a multi-minute head load.
	var circuitFP string
	var loadHead func() (ceremony.Blob, error)
	if *initHeadPath != "" {
		if *circuitFPFlag == "" {
			fatal(fmt.Errorf("--circuit-fp is required with --init-head"))
		}
		circuitFP = *circuitFPFlag
		p := *initHeadPath
		loadHead = func() (ceremony.Blob, error) {
			f, err := os.Open(p)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			b := backend.NewPhase2()
			if _, err := b.ReadFrom(f); err != nil {
				return nil, fmt.Errorf("read --init-head: %w", err)
			}
			return b, nil
		}
	} else {
		if *ccsPath == "" {
			fatal(fmt.Errorf("provide --init-head (+ --circuit-fp), or --ccs + --commons"))
		}
		ccsBytes, err := os.ReadFile(*ccsPath)
		if err != nil {
			fatal(err)
		}
		commonsBytes, err := os.ReadFile(*commonsPath)
		if err != nil {
			fatal(err)
		}
		if circuitFP, err = backend.CircuitFingerprint(bytes.NewReader(ccsBytes)); err != nil {
			fatal(err)
		}
		loadHead = func() (ceremony.Blob, error) {
			return backend.InitPhase2(bytes.NewReader(ccsBytes), bytes.NewReader(commonsBytes))
		}
	}

	allow, err := loadAllowlist(*allowPath)
	if err != nil {
		fatal(err)
	}
	store, err := ceremony.NewLocalStorage(*storeDir)
	if err != nil {
		fatal(err)
	}
	var provider ceremony.AuthProvider
	switch *authMode {
	case "token":
		provider = ceremony.NewTokenAllowlist(allow)
	case "ed25519-allowlist":
		provider = ceremony.NewEd25519Allowlist(allow)
	default:
		fatal(fmt.Errorf("unknown --auth %q (want token | ed25519-allowlist)", *authMode))
	}

	// Swappable handler: serve "warming up" immediately, flip to the real sequencer
	// once the head is loaded. GET /info answers 200 from the first second, so Fly's
	// health check passes right away even though the head load takes minutes.
	var live atomic.Pointer[http.Handler]
	warm := warmingHandler(backend.CurveName(), circuitFP)
	live.Store(&warm)
	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*live.Load()).ServeHTTP(w, r)
	})

	go func() {
		t := time.Now()
		initHead, err := loadHead()
		if err != nil {
			fmt.Fprintln(os.Stderr, "FATAL loading init head:", err)
			os.Exit(1)
		}
		seq, err := ceremony.NewSequencer(ceremony.SequencerConfig{
			Backend:     backend,
			Store:       store,
			Providers:   map[string]ceremony.AuthProvider{provider.Name(): provider},
			SlotTimeout: *slotTimeout,
		}, initHead, circuitFP)
		if err != nil {
			fmt.Fprintln(os.Stderr, "FATAL building sequencer:", err)
			os.Exit(1)
		}
		h := buildHandler(seq, *dist)
		live.Store(&h)
		fmt.Fprintf(os.Stderr, "sequencer READY (head loaded in %s)\n", time.Since(t).Round(time.Second))
	}()

	fmt.Fprintf(os.Stderr, "sequencer listening on %s (warming up)\n  curve=%s circuit=%s allowlisted=%d slot-timeout=%s state=%s\n",
		*listen, backend.CurveName(), circuitFP, len(allow), slotTimeout.String(), *storeDir)
	if err := http.ListenAndServe(*listen, root); err != nil {
		fatal(err)
	}
}

// warmingHandler answers health checks (GET /info -> 200) while the init head loads,
// and returns 503 for everything else until the sequencer is ready.
func warmingHandler(curve, fp string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /info", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "{\"curve\":%q,\"circuit_fingerprint\":%q,\"ready\":false,\"warming\":true}\n", curve, fp)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "sequencer warming up (loading init head) - try again in a moment", http.StatusServiceUnavailable)
	})
	return mux
}

// buildHandler wires the live sequencer (+ optional /download static serving).
func buildHandler(seq *ceremony.Sequencer, dist string) http.Handler {
	if dist == "" {
		return seq.Handler()
	}
	outer := http.NewServeMux()
	outer.Handle("/download/", http.StripPrefix("/download/", http.FileServer(http.Dir(dist))))
	outer.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/download/", http.StatusFound)
	})
	outer.Handle("/", seq.Handler())
	return outer
}

func loadAllowlist(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	allow := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		name := ""
		if len(fields) > 1 {
			name = strings.Join(fields[1:], " ")
		}
		allow[fields[0]] = name
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(allow) == 0 {
		return nil, fmt.Errorf("allowlist %s is empty", path)
	}
	return allow, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "sequencer:", err)
	os.Exit(1)
}
