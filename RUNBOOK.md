# Runbook

The coordinator procedure for a Phase-2 ceremony. Participants need only the `join` command from the
README. Substitute your own circuit (`ccs.bin`); the tool is circuit-agnostic.

To rehearse the whole flow locally first:

```sh
bash scripts/rehearse.sh 3
```

This runs a complete ceremony on one machine — token minting, the sequencer, three contributions, and
finalization — on a demo circuit.

## 1. Inputs

A ceremony needs a Phase-1 `commons.bin` and the circuit's `ccs.bin`.

Phase-1 is circuit-independent. Reuse a public BLS12-381 powers-of-tau, or run a small one for
testing. `N` is the power; choose `N >= log2(constraints)`.

```sh
ingest-ptau --probe --power <N>            # validate encoding and offsets first
ingest-ptau --power <N> --out commons.bin  # import; aborts if the consistency checks fail
```

```sh
# or run your own, for testing:
ceremony phase1-init --power <N> --out p1_0000.bin
ceremony phase1-contribute --in p1_0000.bin --out p1_0001.bin
ceremony phase1-seal --power <N> --beacon <HEX> --out commons.bin p1_0001.bin
```

Compile your gnark circuit to `ccs.bin` (`ConstraintSystem.WriteTo`), then key it. For large circuits
this step is CPU- and memory-intensive and is performed once.

```sh
ceremony verify-circuit --ccs ccs.bin                                    # prints the fingerprint to publish
ceremony phase2-init --ccs ccs.bin --commons commons.bin --out p2_0000.bin
```

## 2. Sequencer

Run the sequencer on a host participants can reach (a public address, or a tunnel during testing).
Persist `--store` on durable storage; the ceremony resumes from it across restarts.

```sh
ceremony keygen-team --n 10 --prefix participant   # writes allow.txt (server) and tokens.txt (handout)
sequencer --init-head p2_0000.bin --circuit-fp <FP> --allowlist allow.txt --dist ./dist --store ./state --listen :8080
```

`--init-head` serves a precomputed head, so the server needs neither `ccs.bin` nor `commons.bin` and
performs no heavy initialization; pass `--ccs --commons` instead to compute the head on the server.
`--dist` serves the prebuilt client binaries and a landing page.

Distribute to each participant, privately: the URL, the circuit fingerprint, and one token.

## 3. Contributions

Participants run `join` (see the README). The sequencer admits one at a time; the rest wait. An idle
slot is abandoned after `--slot-timeout`, leaving the head unchanged, and the next participant
proceeds. Track progress with `ceremony transcript --server <URL>`.

## 4. Finalization

Fix a public beacon (for example a pre-announced Bitcoin block hash or a drand round) and finalize
over the accepted chain:

```sh
ceremony phase2-finalize --ccs ccs.bin --commons commons.bin --beacon <HEX> --keys ./keys ./state/blobs/*.bin
```

This re-verifies the chain, folds in the beacon, writes the proving and verifying keys, and prints the
verifying-key fingerprint. Publish `state/transcript.json` and the contribution blobs so the result
can be re-derived independently.

## Operational notes

- One honest contributor suffices for security; authentication only gates participation.
- Each contribution transfers a circuit-sized blob (hundreds of MB to GBs) and the server verifies it,
  so a contribution takes minutes. Run the ceremony asynchronously and prefer a dedicated-CPU host.
- For a reused Phase-1, publish its provenance: the source and its hash, the circuit fingerprint, the
  contributor list, and the beacon.
