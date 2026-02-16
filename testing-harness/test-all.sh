#!/usr/bin/env bash
# test-all.sh — master runner for mtool shell-script integration tests
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MTOOL="${MTOOL:-$(dirname "$SCRIPT_DIR")/mtool}"

if [[ ! -x "$MTOOL" ]]; then
    echo "ERROR: mtool binary not found at $MTOOL"
    echo "Build it first:  go build -o mtool ."
    exit 1
fi

export MTOOL

PASS=0
FAIL=0
SKIP=0
FAILED_TESTS=()

run_test() {
    local script="$1"
    local name
    name="$(basename "$script" .sh)"

    printf "%-24s " "$name"

    if [[ ! -f "$script" ]]; then
        echo "SKIP (not found)"
        ((SKIP++))
        return
    fi

    local output
    if output=$(bash "$script" 2>&1); then
        echo "PASS"
        ((PASS++))
    else
        echo "FAIL"
        ((FAIL++))
        FAILED_TESTS+=("$name")
        # Show last 20 lines of output on failure
        echo "$output" | tail -20 | sed 's/^/    /'
    fi
}

echo "================================================================"
echo "mtool integration test suite"
echo "binary: $MTOOL"
echo "================================================================"
echo ""

for script in "$SCRIPT_DIR"/test-*.sh; do
    [[ "$(basename "$script")" == "test-all.sh" ]] && continue
    run_test "$script"
done

echo ""
echo "================================================================"
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "================================================================"

if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo ""
    echo "Failed tests:"
    for t in "${FAILED_TESTS[@]}"; do
        echo "  - $t"
    done
fi

exit "$FAIL"
