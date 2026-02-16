#!/usr/bin/env bash
# test-fetch.sh — integration tests for: mtool fetch
# Uses a local mtool serve instance to avoid external network dependencies
set -euo pipefail

MTOOL="${MTOOL:?must be set}"
TMPDIR_TEST="$(mktemp -d)"
trap 'kill $SERVER_PID 2>/dev/null; rm -rf "$TMPDIR_TEST"' EXIT

echo '{"status":"ok"}' > "$TMPDIR_TEST/api.json"
echo "hello fetch" > "$TMPDIR_TEST/hello.txt"

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

"$MTOOL" serve -addr ":$PORT" -dir "$TMPDIR_TEST" &
SERVER_PID=$!
sleep 1

BASE="http://127.0.0.1:$PORT"

# --- default GET ---
output=$("$MTOOL" fetch "$BASE/hello.txt" 2>&1)
echo "$output" | grep -q "hello fetch" || { echo "FAIL: default GET"; exit 1; }

# --- -headers flag ---
output=$("$MTOOL" fetch -headers "$BASE/hello.txt" 2>&1)
echo "$output" | grep -qi "content-type" || { echo "FAIL: -headers missing Content-Type"; exit 1; }

# --- -trace flag ---
output=$("$MTOOL" fetch -trace "$BASE/hello.txt" 2>&1)
echo "$output" | grep -qi "dns\|ttfb\|total" || { echo "FAIL: -trace missing timing"; exit 1; }

# --- -dump flag ---
output=$("$MTOOL" fetch -dump "$BASE/hello.txt" 2>&1)
echo "$output" | grep -q "GET" || { echo "FAIL: -dump missing GET"; exit 1; }

# --- -output to file ---
"$MTOOL" fetch -output "$TMPDIR_TEST/fetched.txt" "$BASE/hello.txt" 2>&1
[[ -f "$TMPDIR_TEST/fetched.txt" ]] || { echo "FAIL: -output file not created"; exit 1; }
grep -q "hello fetch" "$TMPDIR_TEST/fetched.txt" || { echo "FAIL: -output content mismatch"; exit 1; }

# --- -method POST with -body ---
output=$("$MTOOL" fetch -method POST -body '{"key":"val"}' "$BASE/api.json" 2>&1)
[[ -n "$output" ]] || { echo "FAIL: POST with body empty"; exit 1; }

# --- -header flag ---
output=$("$MTOOL" fetch -header "X-Test: hello" "$BASE/hello.txt" 2>&1)
echo "$output" | grep -q "hello fetch" || { echo "FAIL: custom header fetch"; exit 1; }

# --- -timeout flag ---
output=$("$MTOOL" fetch -timeout 5s "$BASE/hello.txt" 2>&1)
echo "$output" | grep -q "hello fetch" || { echo "FAIL: timeout fetch"; exit 1; }

echo "fetch: all tests passed"
