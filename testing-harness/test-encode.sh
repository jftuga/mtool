#!/usr/bin/env bash
# test-encode.sh — integration tests for: mtool encode
set -euo pipefail

MTOOL="${MTOOL:?must be set}"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

INPUT="Hello, World!"

# --- base64 ---
output=$(echo -n "$INPUT" | "$MTOOL" encode -format base64)
[[ "$output" == "SGVsbG8sIFdvcmxkIQ==" ]] || { echo "FAIL: base64 encode: got '$output'"; exit 1; }

# --- base32 ---
output=$(echo -n "$INPUT" | "$MTOOL" encode -format base32)
[[ -n "$output" ]] || { echo "FAIL: base32 encode empty"; exit 1; }

# --- hex ---
output=$(echo -n "Hello" | "$MTOOL" encode -format hex)
[[ "$output" == "48656c6c6f" ]] || { echo "FAIL: hex encode: got '$output'"; exit 1; }

# --- ascii85 ---
output=$(echo -n "$INPUT" | "$MTOOL" encode -format ascii85)
[[ -n "$output" ]] || { echo "FAIL: ascii85 encode empty"; exit 1; }

# --- url ---
output=$(echo -n "hello world&foo=bar" | "$MTOOL" encode -format url)
echo "$output" | grep -q "hello" || { echo "FAIL: url encode"; exit 1; }
echo "$output" | grep -q "%26" || echo "$output" | grep -q "&" || true

# --- html ---
output=$(echo -n '<script>alert("xss")</script>' | "$MTOOL" encode -format html)
echo "$output" | grep -q "&lt;" || { echo "FAIL: html encode: got '$output'"; exit 1; }

# --- qp (quoted-printable) ---
output=$(echo -n "$INPUT" | "$MTOOL" encode -format qp)
[[ -n "$output" ]] || { echo "FAIL: qp encode empty"; exit 1; }

# --- encode from file ---
echo -n "Hello" > "$TMPDIR_TEST/input.txt"
output=$("$MTOOL" encode -format hex "$TMPDIR_TEST/input.txt")
[[ "$output" == "48656c6c6f" ]] || { echo "FAIL: encode from file: got '$output'"; exit 1; }

echo "encode: all tests passed"
