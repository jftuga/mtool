#!/usr/bin/env bash
# test-time.sh — integration tests for: mtool time
set -euo pipefail

MTOOL="${MTOOL:?must be set}"

# --- mode now (default) ---
output=$("$MTOOL" time 2>&1)
[[ -n "$output" ]] || { echo "FAIL: time now empty"; exit 1; }
# Should contain current year
echo "$output" | grep -q "202" || { echo "FAIL: time now missing year"; exit 1; }

# --- mode now explicit ---
output=$("$MTOOL" time -mode now 2>&1)
[[ -n "$output" ]] || { echo "FAIL: time -mode now empty"; exit 1; }

# --- mode fromepoch with epoch 0 ---
output=$("$MTOOL" time -mode fromepoch 0 2>&1)
echo "$output" | grep -q "1970" || { echo "FAIL: epoch 0 missing 1970: $output"; exit 1; }

# --- mode fromepoch with known epoch ---
output=$("$MTOOL" time -mode fromepoch 1700000000 2>&1)
echo "$output" | grep -q "2023" || { echo "FAIL: epoch 1700000000 missing 2023: $output"; exit 1; }

# --- mode toepoch ---
output=$("$MTOOL" time -mode toepoch "2023-01-01T00:00:00Z" 2>&1)
echo "$output" | grep -q "1672531200" || { echo "FAIL: toepoch 2023-01-01: $output"; exit 1; }

# --- -format flag (fromepoch uses local time for custom format) ---
output=$("$MTOOL" time -mode fromepoch -format "2006-01-02" 0 2>&1)
echo "$output" | grep -qE "1970-01-01|1969-12-31" || { echo "FAIL: custom format: $output"; exit 1; }

# --- -format flag with convert mode and -zone to get exact UTC result ---
output=$("$MTOOL" time -mode convert -format "2006-01-02" -zone UTC "1970-01-01T00:00:00Z" 2>&1)
echo "$output" | grep -q "1970-01-01" || { echo "FAIL: convert format UTC: $output"; exit 1; }

# --- -zone flag ---
output=$("$MTOOL" time -mode now -zone "America/New_York" 2>&1)
[[ -n "$output" ]] || { echo "FAIL: time with zone empty"; exit 1; }

output=$("$MTOOL" time -mode fromepoch -zone "UTC" 0 2>&1)
echo "$output" | grep -q "1970" || { echo "FAIL: fromepoch with UTC zone: $output"; exit 1; }

echo "time: all tests passed"
