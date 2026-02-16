#!/usr/bin/env bash
# test-decrypt.sh — integration tests for: mtool decrypt (separate from encrypt)
# Tests decrypt-specific edge cases
set -euo pipefail

MTOOL="${MTOOL:?must be set}"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

ORIGINAL="$TMPDIR_TEST/plain.txt"
echo "Decrypt-specific test data." > "$ORIGINAL"
ORIG_CONTENT=$(cat "$ORIGINAL")
PASSWORD="decrypt-test-pw"

# Encrypt first
"$MTOOL" encrypt -password "$PASSWORD" "$ORIGINAL" "$TMPDIR_TEST/enc.bin"

# --- decrypt with -password flag ---
"$MTOOL" decrypt -password "$PASSWORD" "$TMPDIR_TEST/enc.bin" "$TMPDIR_TEST/dec.txt"
[[ "$(cat "$TMPDIR_TEST/dec.txt")" == "$ORIG_CONTENT" ]] || { echo "FAIL: decrypt mismatch"; exit 1; }

# --- decrypt with wrong password (exit code != 0) ---
if "$MTOOL" decrypt -password "wrong" "$TMPDIR_TEST/enc.bin" "$TMPDIR_TEST/bad.txt" 2>/dev/null; then
    echo "FAIL: decrypt with wrong password should fail"
    exit 1
fi

# --- decrypt with MTOOL_PASSWORD env var ---
MTOOL_PASSWORD="$PASSWORD" "$MTOOL" decrypt "$TMPDIR_TEST/enc.bin" "$TMPDIR_TEST/dec2.txt"
[[ "$(cat "$TMPDIR_TEST/dec2.txt")" == "$ORIG_CONTENT" ]] || { echo "FAIL: decrypt via env var"; exit 1; }

# --- decrypt corrupted file should fail ---
echo "not encrypted data" > "$TMPDIR_TEST/corrupt.bin"
if "$MTOOL" decrypt -password "$PASSWORD" "$TMPDIR_TEST/corrupt.bin" "$TMPDIR_TEST/bad2.txt" 2>/dev/null; then
    echo "FAIL: decrypt corrupted file should fail"
    exit 1
fi

echo "decrypt: all tests passed"
