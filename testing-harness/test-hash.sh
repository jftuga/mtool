#!/usr/bin/env bash
# test-hash.sh — integration tests for: mtool hash
set -euo pipefail

MTOOL="${MTOOL:?must be set}"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

echo -n "hello" > "$TMPDIR_TEST/hello.txt"

# --- sha256 (default) ---
output=$("$MTOOL" hash "$TMPDIR_TEST/hello.txt")
echo "$output" | grep -q "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" \
    || { echo "FAIL: sha256 mismatch: $output"; exit 1; }

# --- md5 ---
output=$("$MTOOL" hash -algo md5 "$TMPDIR_TEST/hello.txt")
echo "$output" | grep -q "5d41402abc4b2a76b9719d911017c592" \
    || { echo "FAIL: md5 mismatch: $output"; exit 1; }

# --- sha1 ---
output=$("$MTOOL" hash -algo sha1 "$TMPDIR_TEST/hello.txt")
echo "$output" | grep -q "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" \
    || { echo "FAIL: sha1 mismatch: $output"; exit 1; }

# --- sha512 ---
output=$("$MTOOL" hash -algo sha512 "$TMPDIR_TEST/hello.txt")
echo "$output" | grep -q "9b71d224bd62f3785d96d46ad3ea3d73" \
    || { echo "FAIL: sha512 mismatch (prefix)"; exit 1; }

# --- sha3-256 ---
output=$("$MTOOL" hash -algo sha3-256 "$TMPDIR_TEST/hello.txt")
[[ -n "$output" ]] || { echo "FAIL: sha3-256 empty"; exit 1; }

# --- sha3-512 ---
output=$("$MTOOL" hash -algo sha3-512 "$TMPDIR_TEST/hello.txt")
[[ -n "$output" ]] || { echo "FAIL: sha3-512 empty"; exit 1; }

# --- crc32 ---
output=$("$MTOOL" hash -algo crc32 "$TMPDIR_TEST/hello.txt")
[[ -n "$output" ]] || { echo "FAIL: crc32 empty"; exit 1; }

# --- crc64 ---
output=$("$MTOOL" hash -algo crc64 "$TMPDIR_TEST/hello.txt")
[[ -n "$output" ]] || { echo "FAIL: crc64 empty"; exit 1; }

# --- adler32 ---
output=$("$MTOOL" hash -algo adler32 "$TMPDIR_TEST/hello.txt")
[[ -n "$output" ]] || { echo "FAIL: adler32 empty"; exit 1; }

# --- fnv32 ---
output=$("$MTOOL" hash -algo fnv32 "$TMPDIR_TEST/hello.txt")
[[ -n "$output" ]] || { echo "FAIL: fnv32 empty"; exit 1; }

# --- fnv64 ---
output=$("$MTOOL" hash -algo fnv64 "$TMPDIR_TEST/hello.txt")
[[ -n "$output" ]] || { echo "FAIL: fnv64 empty"; exit 1; }

# --- fnv128 ---
output=$("$MTOOL" hash -algo fnv128 "$TMPDIR_TEST/hello.txt")
[[ -n "$output" ]] || { echo "FAIL: fnv128 empty"; exit 1; }

# --- hmac ---
output=$("$MTOOL" hash -algo sha256 -hmac "mysecret" "$TMPDIR_TEST/hello.txt")
[[ -n "$output" ]] || { echo "FAIL: hmac empty"; exit 1; }
# HMAC should differ from plain hash
plain=$("$MTOOL" hash -algo sha256 "$TMPDIR_TEST/hello.txt")
[[ "$output" != "$plain" ]] || { echo "FAIL: hmac same as plain hash"; exit 1; }

# --- stdin via pipe ---
output=$(echo -n "hello" | "$MTOOL" hash -algo sha256)
echo "$output" | grep -q "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" \
    || { echo "FAIL: stdin sha256 mismatch"; exit 1; }

echo "hash: all tests passed"
