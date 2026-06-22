#!/usr/bin/env bash
# rehearse.sh - a full local dress-rehearsal of the token ceremony flow:
# demo circuit -> keygen-team (login tokens) -> sequencer -> each teammate joins
# with their token -> finalize -> the keys are produced. FOR REHEARSAL ONLY.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
N="${1:-3}"
PORT="${2:-8099}"
WORK="$(mktemp -d)"
cd "$WORK"
echo "== rehearsal working dir: $WORK =="

echo "== building binaries + demo fixtures =="
( cd "$ROOT" && go build -o "$WORK/ceremony" ./cmd/ceremony \
             && go build -o "$WORK/sequencer" ./cmd/sequencer \
             && go build -o "$WORK/gendemo" ./internal/gendemo )
./gendemo     # writes ccs.bin + commons.bin into the work dir

echo "== minting $N login tokens =="
./ceremony keygen-team --n "$N" --prefix dev

FP="$(./ceremony verify-circuit --ccs ccs.bin 2>/dev/null)"
echo "== circuit fingerprint: $FP =="

echo "== starting sequencer on 127.0.0.1:$PORT =="
./sequencer --ccs ccs.bin --commons commons.bin --store ./state \
            --allowlist allow.txt --listen "127.0.0.1:$PORT" >sequencer.log 2>&1 &
SEQ=$!
trap 'kill $SEQ 2>/dev/null || true' EXIT
sleep 1

echo "== each teammate contributes with their token =="
while read -r name tok; do
  [ -z "$name" ] && continue
  echo "--- $name ---"
  ./ceremony join --server "http://127.0.0.1:$PORT" --token "$tok" --expect-circuit "$FP" 2>&1 \
    | grep -E "accepted as|CONTRIBUTION ACCEPTED|index="
done < tokens.txt

echo "== finalizing =="
./ceremony phase2-finalize --ccs ccs.bin --commons commons.bin \
           --beacon 00ff00ff --keys ./keys ./state/blobs/*.bin 2>&1 | tail -3

echo "== transcript =="
./ceremony >/dev/null 2>&1 || true
cat state/transcript.json | grep -E '"identity"|"new_sha256"' | sed 's/^/  /'

echo "== REHEARSAL COMPLETE - keys in $WORK/keys =="
