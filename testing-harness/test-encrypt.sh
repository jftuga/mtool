#!/usr/bin/env bash
# test-encrypt.sh — integration tests for: mtool encrypt + decrypt
set -euo pipefail

MTOOL="${MTOOL:?must be set}"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

ORIGINAL="$TMPDIR_TEST/plain.txt"
echo "This is secret data for encryption testing." > "$ORIGINAL"
ORIG_CONTENT=$(cat "$ORIGINAL")
PASSWORD="test-password-123!"

# --- encrypt with -password flag ---
"$MTOOL" encrypt -password "$PASSWORD" "$ORIGINAL" "$TMPDIR_TEST/encrypted.bin"
[[ -f "$TMPDIR_TEST/encrypted.bin" ]] || { echo "FAIL: encrypted file not created"; exit 1; }

# Ciphertext should differ from plaintext
if cmp -s "$ORIGINAL" "$TMPDIR_TEST/encrypted.bin"; then
    echo "FAIL: ciphertext same as plaintext"
    exit 1
fi

# --- decrypt with correct password ---
"$MTOOL" decrypt -password "$PASSWORD" "$TMPDIR_TEST/encrypted.bin" "$TMPDIR_TEST/decrypted.txt"
[[ "$(cat "$TMPDIR_TEST/decrypted.txt")" == "$ORIG_CONTENT" ]] || { echo "FAIL: decrypted content mismatch"; exit 1; }

# --- decrypt with wrong password should fail ---
if "$MTOOL" decrypt -password "wrong-password" "$TMPDIR_TEST/encrypted.bin" "$TMPDIR_TEST/bad.txt" 2>/dev/null; then
    echo "FAIL: decrypt with wrong password should have failed"
    exit 1
fi

# --- encrypt/decrypt with MTOOL_PASSWORD env var ---
MTOOL_PASSWORD="env-password-456" "$MTOOL" encrypt "$ORIGINAL" "$TMPDIR_TEST/encrypted2.bin"
MTOOL_PASSWORD="env-password-456" "$MTOOL" decrypt "$TMPDIR_TEST/encrypted2.bin" "$TMPDIR_TEST/decrypted2.txt"
[[ "$(cat "$TMPDIR_TEST/decrypted2.txt")" == "$ORIG_CONTENT" ]] || { echo "FAIL: env var password round-trip"; exit 1; }

echo "encrypt: all tests passed"
