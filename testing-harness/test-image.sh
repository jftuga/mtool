#!/usr/bin/env bash
# test-image.sh — integration tests for: mtool image
set -euo pipefail

MTOOL="${MTOOL:?must be set}"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# Create a small test PNG using Go (via mtool itself is not possible, so use python or base64)
# Minimal 1x1 red PNG (base64 encoded)
echo -n "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==" \
    | base64 -d > "$TMPDIR_TEST/test.png"

# --- png to jpg ---
"$MTOOL" image "$TMPDIR_TEST/test.png" "$TMPDIR_TEST/out.jpg"
[[ -f "$TMPDIR_TEST/out.jpg" ]] || { echo "FAIL: png->jpg not created"; exit 1; }
# JPEG files start with FF D8
xxd -l 2 "$TMPDIR_TEST/out.jpg" | grep -q "ffd8" || { echo "FAIL: out.jpg not valid JPEG"; exit 1; }

# --- png to gif ---
"$MTOOL" image "$TMPDIR_TEST/test.png" "$TMPDIR_TEST/out.gif"
[[ -f "$TMPDIR_TEST/out.gif" ]] || { echo "FAIL: png->gif not created"; exit 1; }

# --- jpg back to png ---
"$MTOOL" image "$TMPDIR_TEST/out.jpg" "$TMPDIR_TEST/back.png"
[[ -f "$TMPDIR_TEST/back.png" ]] || { echo "FAIL: jpg->png not created"; exit 1; }

# --- explicit -format flag ---
"$MTOOL" image -format jpg "$TMPDIR_TEST/test.png" "$TMPDIR_TEST/explicit.dat"
[[ -f "$TMPDIR_TEST/explicit.dat" ]] || { echo "FAIL: explicit format not created"; exit 1; }
xxd -l 2 "$TMPDIR_TEST/explicit.dat" | grep -q "ffd8" || { echo "FAIL: explicit format not JPEG"; exit 1; }

# --- -quality flag for JPEG ---
"$MTOOL" image -quality 10 "$TMPDIR_TEST/test.png" "$TMPDIR_TEST/low-q.jpg"
"$MTOOL" image -quality 100 "$TMPDIR_TEST/test.png" "$TMPDIR_TEST/high-q.jpg"
[[ -f "$TMPDIR_TEST/low-q.jpg" ]] || { echo "FAIL: low quality not created"; exit 1; }
[[ -f "$TMPDIR_TEST/high-q.jpg" ]] || { echo "FAIL: high quality not created"; exit 1; }

echo "image: all tests passed"
