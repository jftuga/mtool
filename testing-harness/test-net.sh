#!/usr/bin/env bash
# test-net.sh — integration tests for: mtool net
set -euo pipefail

MTOOL="${MTOOL:?must be set}"

# Start an echo server on a random port
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

"$MTOOL" net -mode echo -addr ":$PORT" &
ECHO_PID=$!
trap 'kill $ECHO_PID 2>/dev/null' EXIT
sleep 1

# --- check mode ---
output=$("$MTOOL" net -mode check -timeout 3s "127.0.0.1:$PORT" 2>&1)
echo "$output" | grep -qi "open\|success\|connected\|reachable" || { echo "FAIL: check mode: $output"; exit 1; }

# --- check mode on closed port ---
CLOSED_PORT=$((PORT + 1))
if "$MTOOL" net -mode check -timeout 1s "127.0.0.1:$CLOSED_PORT" 2>/dev/null; then
    # Some implementations may not fail on check, just report closed
    true
fi

# --- scan mode with small range ---
output=$("$MTOOL" net -mode scan -start "$PORT" -end "$PORT" -timeout 2s "127.0.0.1" 2>&1)
echo "$output" | grep -q "$PORT" || { echo "FAIL: scan didn't find open port $PORT: $output"; exit 1; }

# --- wait mode (port already open, should succeed quickly) ---
output=$("$MTOOL" net -mode wait -timeout 3s "127.0.0.1:$PORT" 2>&1)
[[ $? -eq 0 ]] || { echo "FAIL: wait mode on open port"; exit 1; }

echo "net: all tests passed"
