// Command finalize-stream is a memory-lean phase-2 finalize for large circuits.
//
// It replicates gnark mpcsetup.VerifyPhase2 but loads each contribution blob
// just-in-time (2 resident at a time, not the whole chain), GCs between blobs,
// and streams the proving key straight to disk instead of buffering it in RAM.
// Peak memory is ~ commons + r1cs + evals + 2 blobs + pk, well under the
// all-at-once path that OOMs on multi-million-constraint circuits.
//
// usage: finalize-stream --ccs ccs.bin --commons commons.bin --beacon HEX --keys DIR blob0 ... blobN
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	mpcsetup "github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
	cs "github.com/consensys/gnark/constraint/bls12-381"
)

func die(f string, a ...any) { fmt.Fprintf(os.Stderr, "finalize-stream: "+f+"\n", a...); os.Exit(1) }
func logf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "[%s] "+f+"\n", append([]any{time.Now().Format("15:04:05")}, a...)...)
}

func main() {
	args := os.Args[1:]
	var ccsPath, commonsPath, beaconHex, keysDir string
	var blobs []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ccs":
			i++
			ccsPath = args[i]
		case "--commons":
			i++
			commonsPath = args[i]
		case "--beacon":
			i++
			beaconHex = args[i]
		case "--keys":
			i++
			keysDir = args[i]
		default:
			blobs = append(blobs, args[i])
		}
	}
	if ccsPath == "" || commonsPath == "" || beaconHex == "" || keysDir == "" || len(blobs) == 0 {
		die("usage: --ccs ccs.bin --commons commons.bin --beacon HEX --keys DIR blob0 ... blobN")
	}
	beacon, err := hex.DecodeString(beaconHex)
	if err != nil {
		die("bad beacon hex: %v", err)
	}
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		die("mkdir keys: %v", err)
	}

	logf("reading r1cs %s", ccsPath)
	r1cs := readR1CS(ccsPath)
	logf("reading commons %s", commonsPath)
	commons := readCommons(commonsPath)

	logf("initializing phase2 + evaluations (one-time precompute)")
	prev := new(mpcsetup.Phase2)
	evals := prev.Initialize(r1cs, commons)
	runtime.GC()

	for i, p := range blobs {
		logf("loading + verifying contribution %d/%d  %s", i+1, len(blobs), filepath.Base(p))
		ci := new(mpcsetup.Phase2)
		f, err := os.Open(p)
		if err != nil {
			die("open %s: %v", p, err)
		}
		if _, err := ci.ReadFrom(f); err != nil {
			die("read %s: %v", p, err)
		}
		f.Close()
		if err := prev.Verify(ci); err != nil {
			die("CHAIN VERIFY FAILED at contribution %d (%s): %v", i, p, err)
		}
		prev = ci // advance; previous blob becomes GC-able
		ci = nil
		runtime.GC()
		printMem()
	}

	logf("applying beacon + sealing -> deriving keys (this is the heavy step)")
	pk, vk := prev.Seal(commons, &evals, beacon)
	prev = nil
	runtime.GC()

	// vk + its fingerprint (sha256 of the vk serialization), streamed.
	logf("writing vk.bin + fingerprint")
	vkf, err := os.Create(filepath.Join(keysDir, "vk.bin"))
	if err != nil {
		die("create vk: %v", err)
	}
	h := sha256.New()
	if _, err := vk.WriteTo(io.MultiWriter(vkf, h)); err != nil {
		die("write vk: %v", err)
	}
	vkf.Close()
	fp := hex.EncodeToString(h.Sum(nil))

	// pk streamed straight to disk (never buffered whole in RAM).
	logf("writing pk.bin (streamed)")
	pkf, err := os.Create(filepath.Join(keysDir, "pk.bin"))
	if err != nil {
		die("create pk: %v", err)
	}
	if _, err := pk.WriteTo(pkf); err != nil {
		die("write pk: %v", err)
	}
	pkf.Close()

	// ccs.bin: the keyed circuit (copy the input bytes verbatim).
	logf("copying ccs.bin")
	copyFile(ccsPath, filepath.Join(keysDir, "ccs.bin"))

	logf("CEREMONY COMPLETE. keys -> %s", keysDir)
	fmt.Fprintln(os.Stderr, "VK fingerprint (pin this):")
	fmt.Println(fp)
}

func readR1CS(path string) *cs.R1CS {
	f, err := os.Open(path)
	if err != nil {
		die("open ccs: %v", err)
	}
	defer f.Close()
	ccs := groth16.NewCS(ecc.BLS12_381)
	if _, err := ccs.ReadFrom(f); err != nil {
		die("read ccs: %v", err)
	}
	r, ok := ccs.(*cs.R1CS)
	if !ok {
		die("unexpected constraint system type %T (want *bls12-381.R1CS)", ccs)
	}
	return r
}

func readCommons(path string) *mpcsetup.SrsCommons {
	f, err := os.Open(path)
	if err != nil {
		die("open commons: %v", err)
	}
	defer f.Close()
	var c mpcsetup.SrsCommons
	if _, err := c.ReadFrom(f); err != nil {
		die("read commons: %v", err)
	}
	return &c
}

func copyFile(src, dst string) {
	in, err := os.Open(src)
	if err != nil {
		die("open %s: %v", src, err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		die("create %s: %v", dst, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		die("copy ccs: %v", err)
	}
}

func printMem() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	logf("  heap in-use: %.1f GiB (sys %.1f GiB)", float64(m.HeapInuse)/(1<<30), float64(m.Sys)/(1<<30))
}
