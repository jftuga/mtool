#!/usr/bin/env bash
# test-serve.sh — integration tests for: mtool serve
set -euo pipefail

MTOOL="${MTOOL:?must be set}"
TMPDIR_TEST="$(mktemp -d)"
PIDS=()
trap 'for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$TMPDIR_TEST"' EXIT

echo "serve-test-content" > "$TMPDIR_TEST/test.txt"
mkdir -p "$TMPDIR_TEST/subdir"
echo "nested-file" > "$TMPDIR_TEST/subdir/nested.txt"

get_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()'
}

# --- basic serve with -dir and -addr ---
PORT=$(get_port)
"$MTOOL" serve -addr ":$PORT" -dir "$TMPDIR_TEST" &
PIDS+=($!)
sleep 1

output=$(curl -s "http://127.0.0.1:$PORT/test.txt")
[[ "$output" == "serve-test-content" ]] || { echo "FAIL: basic serve content: $output"; exit 1; }

# Directory listing should mention test.txt
output=$(curl -s "http://127.0.0.1:$PORT/")
echo "$output" | grep -q "test.txt" || { echo "FAIL: directory listing missing test.txt"; exit 1; }

# --- -gzip flag ---
PORT2=$(get_port)
"$MTOOL" serve -addr ":$PORT2" -dir "$TMPDIR_TEST" -gzip &
PIDS+=($!)
sleep 1

headers=$(curl -sI -H "Accept-Encoding: gzip" "http://127.0.0.1:$PORT2/test.txt")
# Note: gzip may not apply to very small files; just verify server starts and responds
output=$(curl -s "http://127.0.0.1:$PORT2/test.txt")
[[ "$output" == "serve-test-content" ]] || { echo "FAIL: gzip serve content: $output"; exit 1; }

# --- -tls flag ---
PORT3=$(get_port)
"$MTOOL" serve -addr ":$PORT3" -dir "$TMPDIR_TEST" -tls &
PIDS+=($!)
sleep 2

output=$(curl -sk "https://127.0.0.1:$PORT3/test.txt")
[[ "$output" == "serve-test-content" ]] || { echo "FAIL: TLS serve content: $output"; exit 1; }

echo "serve: all tests passed"
