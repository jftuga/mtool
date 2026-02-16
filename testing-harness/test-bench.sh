#!/usr/bin/env bash
# test-bench.sh — integration tests for: mtool bench
set -euo pipefail

MTOOL="${MTOOL:?must be set}"

# Start a simple local HTTP server using mtool serve
TMPDIR_TEST="$(mktemp -d)"
trap 'kill $SERVER_PID 2>/dev/null; rm -rf "$TMPDIR_TEST"' EXIT

echo "ok" > "$TMPDIR_TEST/index.html"

# Find a free port
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

"$MTOOL" serve -addr ":$PORT" -dir "$TMPDIR_TEST" &
SERVER_PID=$!
sleep 1

# --- basic bench ---
output=$("$MTOOL" bench -n 5 -c 2 "http://127.0.0.1:$PORT/index.html" 2>&1)
echo "$output" | grep -qi "requests" || { echo "FAIL: bench output missing requests"; exit 1; }

# --- bench with jitter ---
output=$("$MTOOL" bench -n 3 -c 1 -jitter 10ms "http://127.0.0.1:$PORT/index.html" 2>&1)
echo "$output" | grep -qi "requests" || { echo "FAIL: bench with jitter missing output"; exit 1; }

# --- bench with method ---
output=$("$MTOOL" bench -n 3 -c 1 -method HEAD "http://127.0.0.1:$PORT/index.html" 2>&1)
echo "$output" | grep -qi "requests" || { echo "FAIL: bench with HEAD missing output"; exit 1; }

echo "bench: all tests passed"
