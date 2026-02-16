#!/usr/bin/env bash
# test-generate.sh — integration tests for: mtool generate
set -euo pipefail

MTOOL="${MTOOL:?must be set}"

# --- password mode (default) ---
output=$("$MTOOL" generate)
[[ ${#output} -ge 20 ]] || { echo "FAIL: default password too short: ${#output}"; exit 1; }

# --- password with -length ---
output=$("$MTOOL" generate -mode password -length 32)
[[ ${#output} -ge 32 ]] || { echo "FAIL: password length 32 too short"; exit 1; }

# --- password with -charset alpha ---
output=$("$MTOOL" generate -mode password -length 50 -charset alpha)
echo "$output" | grep -qE '^[a-zA-Z]+$' || { echo "FAIL: charset alpha has non-alpha chars: $output"; exit 1; }

# --- password with -charset alnum ---
output=$("$MTOOL" generate -mode password -length 50 -charset alnum)
echo "$output" | grep -qE '^[a-zA-Z0-9]+$' || { echo "FAIL: charset alnum has special chars: $output"; exit 1; }

# --- password with -charset full ---
output=$("$MTOOL" generate -mode password -length 10 -charset full)
[[ -n "$output" ]] || { echo "FAIL: charset full empty"; exit 1; }

# --- token mode ---
output=$("$MTOOL" generate -mode token -length 32)
echo "$output" | grep -qE '^[a-f0-9]+$' || { echo "FAIL: token not hex: $output"; exit 1; }

# --- bytes mode ---
output=$("$MTOOL" generate -mode bytes -length 16)
[[ -n "$output" ]] || { echo "FAIL: bytes empty"; exit 1; }

# --- uuid mode ---
output=$("$MTOOL" generate -mode uuid)
echo "$output" | grep -qE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
    || { echo "FAIL: uuid format invalid: $output"; exit 1; }

# --- bigint mode ---
output=$("$MTOOL" generate -mode bigint -length 64)
echo "$output" | grep -qE '^[0-9]+$' || { echo "FAIL: bigint not numeric: $output"; exit 1; }

# --- -count flag ---
output=$("$MTOOL" generate -mode uuid -count 5)
line_count=$(echo "$output" | wc -l | tr -d ' ')
[[ "$line_count" -eq 5 ]] || { echo "FAIL: count 5 got $line_count lines"; exit 1; }

# --- uniqueness: two passwords differ ---
pw1=$("$MTOOL" generate -mode password -length 20)
pw2=$("$MTOOL" generate -mode password -length 20)
[[ "$pw1" != "$pw2" ]] || { echo "FAIL: two passwords are identical"; exit 1; }

echo "generate: all tests passed"
