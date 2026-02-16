#!/usr/bin/env bash
# test-info.sh — integration tests for: mtool info
set -euo pipefail

MTOOL="${MTOOL:?must be set}"

# --- default (table) format ---
output=$("$MTOOL" info 2>&1)
echo "$output" | grep -qi "hostname\|os\|arch" || { echo "FAIL: table missing expected labels"; exit 1; }

# --- json format ---
output=$("$MTOOL" info -format json 2>&1)
echo "$output" | grep -q "{" || { echo "FAIL: json output missing brace"; exit 1; }

# --- xml format ---
output=$("$MTOOL" info -format xml 2>&1)
echo "$output" | grep -q "<" || { echo "FAIL: xml output missing angle bracket"; exit 1; }

# --- csv format ---
output=$("$MTOOL" info -format csv 2>&1)
echo "$output" | grep -q "," || { echo "FAIL: csv output missing comma"; exit 1; }

# --- -env flag ---
output=$("$MTOOL" info -env 2>&1)
echo "$output" | grep -qi "PATH\|HOME\|env" || { echo "FAIL: -env missing environment data"; exit 1; }

echo "info: all tests passed"
