#!/usr/bin/env bash
# test-decode.sh — integration tests for: mtool decode
set -euo pipefail

MTOOL="${MTOOL:?must be set}"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

INPUT="Hello, World!"

# --- round-trip for each format ---
for fmt in base64 base32 hex ascii85 url html qp; do
    encoded=$(echo -n "$INPUT" | "$MTOOL" encode -format "$fmt")
    decoded=$(echo -n "$encoded" | "$MTOOL" decode -format "$fmt")
    [[ "$decoded" == "$INPUT" ]] || { echo "FAIL: $fmt round-trip: got '$decoded'"; exit 1; }
done

# --- decode known base64 value ---
decoded=$(echo -n "SGVsbG8=" | "$MTOOL" decode -format base64)
[[ "$decoded" == "Hello" ]] || { echo "FAIL: known base64 decode"; exit 1; }

# --- decode known hex value ---
decoded=$(echo -n "48656c6c6f" | "$MTOOL" decode -format hex)
[[ "$decoded" == "Hello" ]] || { echo "FAIL: known hex decode"; exit 1; }

# --- decode from file ---
echo -n "SGVsbG8=" > "$TMPDIR_TEST/encoded.txt"
decoded=$("$MTOOL" decode -format base64 "$TMPDIR_TEST/encoded.txt")
[[ "$decoded" == "Hello" ]] || { echo "FAIL: decode from file"; exit 1; }

echo "decode: all tests passed"
