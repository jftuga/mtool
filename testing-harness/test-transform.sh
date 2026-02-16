#!/usr/bin/env bash
# test-transform.sh — integration tests for: mtool transform
set -euo pipefail

MTOOL="${MTOOL:?must be set}"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# --- upper ---
output=$(echo "hello world" | "$MTOOL" transform -mode upper)
[[ "$output" == "HELLO WORLD" ]] || { echo "FAIL: upper: got '$output'"; exit 1; }

# --- lower ---
output=$(echo "HELLO WORLD" | "$MTOOL" transform -mode lower)
[[ "$output" == "hello world" ]] || { echo "FAIL: lower: got '$output'"; exit 1; }

# --- title (proper title case: first letter of each word uppercased, rest lowercased) ---
output=$(echo "hello world" | "$MTOOL" transform -mode title)
[[ "$output" == "Hello World" ]] || { echo "FAIL: title: got '$output'"; exit 1; }

# --- title with mixed case input ---
output=$(echo -n "hELLO wORLD" | "$MTOOL" transform -mode title)
[[ "$output" == "Hello World" ]] || { echo "FAIL: title mixed case: got '$output'"; exit 1; }

# --- reverse (echo adds newline, which gets reversed to the front; use echo -n) ---
output=$(echo -n "abcdef" | "$MTOOL" transform -mode reverse)
[[ "$output" == "fedcba" ]] || { echo "FAIL: reverse: got '$output'"; exit 1; }

# --- count ---
output=$(printf "line1\nline2\nline3\n" | "$MTOOL" transform -mode count)
echo "$output" | grep -q "3" || { echo "FAIL: count: got '$output'"; exit 1; }

# --- replace with -pattern and -replacement ---
output=$(echo "foo bar foo" | "$MTOOL" transform -mode replace -pattern "foo" -replacement "baz")
[[ "$output" == "baz bar baz" ]] || { echo "FAIL: replace: got '$output'"; exit 1; }

# --- grep with -pattern ---
input=$(printf "apple\nbanana\napricot\n")
output=$(echo "$input" | "$MTOOL" transform -mode grep -pattern "^ap")
echo "$output" | grep -q "apple" || { echo "FAIL: grep missing apple"; exit 1; }
echo "$output" | grep -q "apricot" || { echo "FAIL: grep missing apricot"; exit 1; }
echo "$output" | grep -q "banana" && { echo "FAIL: grep should not have banana"; exit 1; }

# --- uniq ---
input=$(printf "a\na\nb\nb\nb\nc\n")
output=$(echo "$input" | "$MTOOL" transform -mode uniq)
line_count=$(echo "$output" | wc -l | tr -d ' ')
[[ "$line_count" -eq 3 ]] || { echo "FAIL: uniq expected 3 lines, got $line_count"; exit 1; }

# --- freq ---
input=$(printf "apple\nbanana\napple\napple\nbanana\n")
output=$(echo "$input" | "$MTOOL" transform -mode freq)
echo "$output" | grep -q "apple" || { echo "FAIL: freq missing apple"; exit 1; }
echo "$output" | grep -q "3" || { echo "FAIL: freq missing count 3"; exit 1; }

# --- sort (default: lexicographic ascending) ---
input=$(printf "cherry\napple\nbanana\n")
output=$(echo "$input" | "$MTOOL" transform -mode sort)
first_line=$(echo "$output" | head -1)
[[ "$first_line" == "apple" ]] || { echo "FAIL: sort first line: got '$first_line'"; exit 1; }

# --- sort -reverse ---
output=$(echo "$input" | "$MTOOL" transform -mode sort -reverse)
first_line=$(echo "$output" | head -1)
[[ "$first_line" == "cherry" ]] || { echo "FAIL: sort reverse first: got '$first_line'"; exit 1; }

# --- sort -numeric ---
input=$(printf "10\n2\n100\n1\n")
output=$(echo "$input" | "$MTOOL" transform -mode sort -numeric)
first_line=$(echo "$output" | head -1)
[[ "$first_line" == "1" ]] || { echo "FAIL: sort numeric first: got '$first_line'"; exit 1; }

# --- sort -ignore-case ---
input=$(printf "Banana\napple\nCherry\n")
output=$(echo "$input" | "$MTOOL" transform -mode sort -ignore-case)
first_line=$(echo "$output" | head -1)
first_lower=$(echo "$first_line" | tr '[:upper:]' '[:lower:]')
[[ "$first_lower" == "apple" ]] || { echo "FAIL: sort ignore-case first: got '$first_line'"; exit 1; }

# --- sort -field ---
input=$(printf "b 2\na 1\nc 3\n")
output=$(echo "$input" | "$MTOOL" transform -mode sort -field 2 -numeric)
first_line=$(echo "$output" | head -1)
echo "$first_line" | grep -q "1" || { echo "FAIL: sort field first: got '$first_line'"; exit 1; }

# --- from file ---
echo "FILE INPUT" > "$TMPDIR_TEST/input.txt"
output=$("$MTOOL" transform -mode lower "$TMPDIR_TEST/input.txt")
[[ "$output" == "file input" ]] || { echo "FAIL: transform from file: got '$output'"; exit 1; }

echo "transform: all tests passed"
