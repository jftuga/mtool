#!/usr/bin/env bash
# test-archive.sh — integration tests for: mtool archive
set -euo pipefail

MTOOL="${MTOOL:?must be set}"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# Create test files
echo "file-one-content" > "$TMPDIR_TEST/one.txt"
echo "file-two-content" > "$TMPDIR_TEST/two.txt"
mkdir -p "$TMPDIR_TEST/subdir"
echo "nested" > "$TMPDIR_TEST/subdir/three.txt"

# --- tar.gz round-trip ---
"$MTOOL" archive -format tar.gz -output "$TMPDIR_TEST/out.tar.gz" \
    "$TMPDIR_TEST/one.txt" "$TMPDIR_TEST/two.txt"
[[ -f "$TMPDIR_TEST/out.tar.gz" ]] || { echo "FAIL: tar.gz not created"; exit 1; }

mkdir -p "$TMPDIR_TEST/extract-tgz"
"$MTOOL" archive -extract -output "$TMPDIR_TEST/extract-tgz" "$TMPDIR_TEST/out.tar.gz"
# Archive preserves full paths, so find the extracted file
found=$(find "$TMPDIR_TEST/extract-tgz" -name "one.txt" -type f)
[[ -n "$found" ]] || { echo "FAIL: tar.gz extracted one.txt not found"; exit 1; }
grep -q "file-one-content" "$found" || { echo "FAIL: tar.gz extract mismatch"; exit 1; }

# --- tar.zlib round-trip ---
"$MTOOL" archive -format tar.zlib -output "$TMPDIR_TEST/out.tar.zlib" \
    "$TMPDIR_TEST/one.txt" "$TMPDIR_TEST/two.txt"
[[ -f "$TMPDIR_TEST/out.tar.zlib" ]] || { echo "FAIL: tar.zlib not created"; exit 1; }

mkdir -p "$TMPDIR_TEST/extract-zlib"
"$MTOOL" archive -extract -output "$TMPDIR_TEST/extract-zlib" "$TMPDIR_TEST/out.tar.zlib"
found=$(find "$TMPDIR_TEST/extract-zlib" -name "one.txt" -type f)
[[ -n "$found" ]] || { echo "FAIL: tar.zlib extracted one.txt not found"; exit 1; }
grep -q "file-one-content" "$found" || { echo "FAIL: tar.zlib extract mismatch"; exit 1; }

# --- zip round-trip ---
"$MTOOL" archive -format zip -output "$TMPDIR_TEST/out.zip" \
    "$TMPDIR_TEST/one.txt" "$TMPDIR_TEST/two.txt"
[[ -f "$TMPDIR_TEST/out.zip" ]] || { echo "FAIL: zip not created"; exit 1; }

mkdir -p "$TMPDIR_TEST/extract-zip"
"$MTOOL" archive -extract -output "$TMPDIR_TEST/extract-zip" "$TMPDIR_TEST/out.zip"
found=$(find "$TMPDIR_TEST/extract-zip" -name "one.txt" -type f)
[[ -n "$found" ]] || { echo "FAIL: zip extracted one.txt not found"; exit 1; }
grep -q "file-one-content" "$found" || { echo "FAIL: zip extract mismatch"; exit 1; }

# --- archive a directory ---
"$MTOOL" archive -format tar.gz -output "$TMPDIR_TEST/dir.tar.gz" "$TMPDIR_TEST/subdir"
[[ -f "$TMPDIR_TEST/dir.tar.gz" ]] || { echo "FAIL: dir archive not created"; exit 1; }

echo "archive: all tests passed"
