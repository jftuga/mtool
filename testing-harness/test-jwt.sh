#!/usr/bin/env bash
# test-jwt.sh — integration tests for: mtool jwt
set -euo pipefail

MTOOL="${MTOOL:?must be set}"

# Known JWT token (HS256, payload: {"sub":"1234567890","name":"John Doe","iat":1516239022})
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# --- default decode ---
output=$("$MTOOL" jwt "$TOKEN" 2>&1)
echo "$output" | grep -q "John Doe" || { echo "FAIL: jwt decode missing name"; exit 1; }
echo "$output" | grep -q "1234567890" || { echo "FAIL: jwt decode missing sub"; exit 1; }
echo "$output" | grep -qi "HS256\|alg" || { echo "FAIL: jwt decode missing algorithm"; exit 1; }

# --- -raw flag ---
output=$("$MTOOL" jwt -raw "$TOKEN" 2>&1)
echo "$output" | grep -q "John Doe" || { echo "FAIL: raw jwt missing name"; exit 1; }

# --- invalid token ---
if "$MTOOL" jwt "not.a.valid.jwt" 2>/dev/null; then
    echo "FAIL: invalid token should have failed"
    exit 1
fi

echo "jwt: all tests passed"
