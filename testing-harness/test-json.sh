#!/usr/bin/env bash
# test-json.sh — integration tests for: mtool json
set -euo pipefail

MTOOL="${MTOOL:?must be set}"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# --- pretty mode (default) ---
output=$(echo -n '{"a":1,"b":2}' | "$MTOOL" json -mode pretty)
echo "$output" | grep -q '"a"' || { echo "FAIL: pretty missing key"; exit 1; }
# Pretty output should have newlines
line_count=$(echo "$output" | wc -l | tr -d ' ')
[[ "$line_count" -gt 1 ]] || { echo "FAIL: pretty not multi-line"; exit 1; }

# --- compact mode ---
output=$(echo '{ "a" : 1 , "b" : 2 }' | "$MTOOL" json -mode compact)
[[ "$output" == '{"a":1,"b":2}' ]] || { echo "FAIL: compact: got '$output'"; exit 1; }

# --- validate mode (valid) ---
output=$(echo -n '{"valid":true}' | "$MTOOL" json -mode validate 2>&1)
echo "$output" | grep -qi "valid" || { echo "FAIL: validate valid json"; exit 1; }

# --- validate mode (invalid) ---
if echo -n '{bad json' | "$MTOOL" json -mode validate 2>/dev/null; then
    echo "FAIL: validate should fail on invalid json"
    exit 1
fi

# --- query mode ---
output=$(echo -n '{"user":{"name":"Alice","age":30}}' | "$MTOOL" json -mode query -query .user.name)
echo "$output" | grep -q "Alice" || { echo "FAIL: query .user.name: got '$output'"; exit 1; }

# --- query with array index ---
output=$(echo -n '{"items":[10,20,30]}' | "$MTOOL" json -mode query -query '.items[1]')
echo "$output" | grep -q "20" || { echo "FAIL: query array index: got '$output'"; exit 1; }

# --- -indent flag ---
output=$(echo -n '{"a":1}' | "$MTOOL" json -mode pretty -indent "    ")
echo "$output" | grep -q "    " || { echo "FAIL: custom indent not found"; exit 1; }

# --- from file ---
echo '{"from":"file"}' > "$TMPDIR_TEST/test.json"
output=$("$MTOOL" json -mode query -query .from "$TMPDIR_TEST/test.json")
echo "$output" | grep -q "file" || { echo "FAIL: json from file"; exit 1; }

echo "json: all tests passed"
