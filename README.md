# gnark-mpc-ceremony

A circuit-agnostic coordinator for Groth16 trusted-setup (MPC) ceremonies, built on gnark's
`mpcsetup`. It runs the Phase-1 and Phase-2 ceremonies for any gnark circuit and scales to many
participants through a sequencer: a lobby, a single-slot queue, verify-and-advance, and a public
hash-chained transcript. The sequencer design follows the Ethereum KZG Summoning Ceremony.

The circuit enters only as a serialized constraint system (`ccs.bin`); the coordinator never imports
circuit code. BLS12-381 is implemented; the curve sits behind a `Backend` interface.

Status: research-grade. Code-reviewed, not externally audited.

## Build

Requires Go 1.25 or newer.

```sh
go build -o bin/ ./cmd/ceremony ./cmd/sequencer ./cmd/ingest-ptau
```

- `ceremony` — participant and coordinator CLI.
- `sequencer` — the coordinator service.
- `ingest-ptau` — import an existing BLS12-381 powers-of-tau as Phase-1 input.

## Participating

Build the client rather than trusting a binary; a compromised server still cannot learn your secret
(see [Security model](#security-model)). The coordinator provides a server URL, a login token, and the
circuit fingerprint.

```sh
go build -o ceremony ./cmd/ceremony
ceremony join --server <URL> --token <TOKEN> --expect-circuit <FINGERPRINT>
```

The client waits for its slot, downloads the current state, folds in fresh randomness locally, uploads
the result, and confirms its entry in the transcript. `--expect-circuit` aborts unless the server is
keying that circuit; the slot is held open by heartbeat while you work; a failed upload retries.

Prebuilt clients are also served at `<URL>/download/` for participants who prefer not to build; the
same `join` command applies.

## Security model

A Groth16 setup is secure if at least one participant samples real randomness and discards it; the
trapdoor is the product of every participant's secret. The design rests on one invariant:

> Contribution — sampling randomness and folding it into the accumulator — runs only on the
> participant's machine. The coordinator handles public data exclusively and never observes a secret.

The secret exists only in the participant's process and is discarded on exit. A compromised
coordinator therefore cannot recover the trapdoor or forge a contribution; at most it can drop or
reorder contributions, which the public transcript, per-participant inclusion checks, and the closing
beacon detect. The sequencer is a coordination layer over the same `mpcsetup` verification it would
run by hand, so a participant may bypass it and contribute manually for an identical result.

## Running a ceremony

[RUNBOOK.md](RUNBOOK.md) is the coordinator procedure end to end. In outline:

1. Obtain Phase-1 `commons.bin`: reuse a public powers-of-tau with `ingest-ptau`, or run a small one.
2. Compile the circuit to `ccs.bin` and key it with `ceremony phase2-init`.
3. Mint tokens with `ceremony keygen-team` and start the `sequencer`.
4. Participants contribute.
5. Finalize against a public beacon with `ceremony phase2-finalize`.

Finalization re-verifies the chain, folds in the beacon, and emits the proving and verifying keys plus
the verifying-key fingerprint. Converting the verifying key to an on-chain format is left to the
project.

## Layout

| Path | Contents |
|---|---|
| `ceremony/` | Library: the `Backend` interface and BLS12-381 implementation, transcript, storage, auth, sequencer, client. |
| `cmd/ceremony/` | Participant and coordinator CLI. |
| `cmd/sequencer/` | Coordinator service. |
| `cmd/ingest-ptau/` | Powers-of-tau import for Phase-1 reuse. |

## Development

```sh
go test ./...
```

`TestEndToEnd` runs a full ceremony through the sequencer and verifies a proof under the resulting
keys; `TestResume` covers restart recovery; `TestHeartbeat` covers slot keep-alive. Adding a curve is
additive: implement `Backend` and register it in `BackendFor`.

## Features

- [x] Phase-1 and Phase-2 ceremonies for any gnark circuit on BLS12-381.
- [x] Public hash-chained transcript; the client verifies its own inclusion.
- [x] Participant client with local contribution, transfer progress and ETA, upload retry, and an on-disk backup of the contribution.
- [x] Authentication by pre-generated login token or ed25519 allowlist.
- [x] Phase-1 reuse: import a public BLS12-381 powers-of-tau (`ingest-ptau`) with subgroup and SameRatio consistency checks.
- [ ] Cardano wallet authentication (CIP-8 / CIP-30): join by signing with a wallet, binding contributions to on-chain identities.
- [ ] Additional authentication providers (OAuth, email).
- [ ] S3-compatible storage and an IPFS-pinned public transcript.
- [ ] A browser (wasm) participant client.
- [ ] Additional curves (BN254, BLS12-377, BW6-761) through the `Backend` interface.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.
