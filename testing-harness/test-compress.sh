#!/usr/bin/env bash
# test-compress.sh — integration tests for: mtool compress
set -euo pipefail

MTOOL="${MTOOL:?must be set}"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

ORIGINAL="$TMPDIR_TEST/original.txt"
echo "The quick brown fox jumps over the lazy dog. Repeated text for compression ratio." > "$ORIGINAL"
ORIG_CONTENT=$(cat "$ORIGINAL")

# --- gzip round-trip ---
"$MTOOL" compress -format gzip "$ORIGINAL" "$TMPDIR_TEST/out.gz"
"$MTOOL" compress -d -format gzip "$TMPDIR_TEST/out.gz" "$TMPDIR_TEST/out-gz.txt"
[[ "$(cat "$TMPDIR_TEST/out-gz.txt")" == "$ORIG_CONTENT" ]] || { echo "FAIL: gzip round-trip"; exit 1; }

# --- gzip with -level ---
"$MTOOL" compress -format gzip -level 9 "$ORIGINAL" "$TMPDIR_TEST/out-l9.gz"
[[ -f "$TMPDIR_TEST/out-l9.gz" ]] || { echo "FAIL: gzip level 9 not created"; exit 1; }

# --- zlib round-trip ---
"$MTOOL" compress -format zlib "$ORIGINAL" "$TMPDIR_TEST/out.zlib"
"$MTOOL" compress -d -format zlib "$TMPDIR_TEST/out.zlib" "$TMPDIR_TEST/out-zlib.txt"
[[ "$(cat "$TMPDIR_TEST/out-zlib.txt")" == "$ORIG_CONTENT" ]] || { echo "FAIL: zlib round-trip"; exit 1; }

# --- lzw round-trip ---
"$MTOOL" compress -format lzw "$ORIGINAL" "$TMPDIR_TEST/out.lzw"
"$MTOOL" compress -d -format lzw "$TMPDIR_TEST/out.lzw" "$TMPDIR_TEST/out-lzw.txt"
[[ "$(cat "$TMPDIR_TEST/out-lzw.txt")" == "$ORIG_CONTENT" ]] || { echo "FAIL: lzw round-trip"; exit 1; }

# --- lzw with -litwidth (must use 8 for ASCII text, lower values only work for restricted byte ranges) ---
"$MTOOL" compress -format lzw -litwidth 8 "$ORIGINAL" "$TMPDIR_TEST/out-lw8.lzw"
"$MTOOL" compress -d -format lzw -litwidth 8 "$TMPDIR_TEST/out-lw8.lzw" "$TMPDIR_TEST/out-lw8.txt"
[[ "$(cat "$TMPDIR_TEST/out-lw8.txt")" == "$ORIG_CONTENT" ]] || { echo "FAIL: lzw litwidth round-trip"; exit 1; }

# --- bzip2 compress should fail ---
if "$MTOOL" compress -format bzip2 "$ORIGINAL" "$TMPDIR_TEST/out.bz2" 2>/dev/null; then
    echo "FAIL: bzip2 compress should have failed"
    exit 1
fi

echo "compress: all tests passed"
