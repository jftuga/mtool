#!/usr/bin/env bash
# test-inspect.sh — integration tests for: mtool inspect
set -euo pipefail

MTOOL="${MTOOL:?must be set}"

# --- TLS inspection (default mode) ---
output=$("$MTOOL" inspect www.example.com 2>&1)
echo "$output" | grep -qi "subject\|issuer\|expire\|cert" || { echo "FAIL: tls inspect missing cert info"; exit 1; }

# --- TLS with explicit -mode and -port ---
output=$("$MTOOL" inspect -mode tls -port 443 www.example.com 2>&1)
echo "$output" | grep -qi "subject\|issuer\|cert" || { echo "FAIL: tls explicit mode missing cert info"; exit 1; }

# --- DNS inspection ---
output=$("$MTOOL" inspect -mode dns www.example.com 2>&1)
echo "$output" | grep -qE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" || { echo "FAIL: dns inspect missing IP"; exit 1; }

echo "inspect: all tests passed"
