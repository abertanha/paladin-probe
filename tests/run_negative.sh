#!/usr/bin/env bash
# Run negative fixtures against the grader.
# Each fixture seeds exactly one defect; the runner asserts the expected
# check fires with the expected severity.
set -euo pipefail

GRADER=$(dirname "$0")/grader.py
FIXTURES_DIR=$(dirname "$0")/fixtures/negative
PASS=0
FAIL=0

check() {
    local fixture="$1"   # subdir name under fixtures/negative/
    local check_id="$2"   # e.g. G2.5
    local severity="$3"   # FAIL or WARN
    local label="$4"

    printf "  %-6s %s (expect %s %s)... " "$fixture" "$label" "$severity" "$check_id"

    output=$(python3 "$GRADER" "$FIXTURES_DIR/$fixture" 2>&1 || true)

    if echo "$output" | grep -Eq "^  $severity  $check_id "; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        echo "--- grader output ---"
        echo "$output" | head -40
        echo "---"
        FAIL=$((FAIL + 1))
    fi
}

echo "Negative fixture verification"
echo "============================="
echo ""

check "neg-g1.8" "G1.8" "WARN" "duplicate finding detection"
check "neg-g2.5" "G2.5" "FAIL" "lowercase Acceptance criteria heading"
check "neg-g2.6" "G2.6" "FAIL" "traceability AC/DP mismatch"
check "neg-g3.6" "G3.6" "WARN" "stale VEX timestamp"
check "neg-g5.1-semantic" "G5.1" "WARN" "threat-model row context mismatch"
check "neg-g5.2" "G5.2" "FAIL" "REPORT summary count divergence"
check "neg-g5.4" "G5.4" "WARN" "divergent probe dates"
check "neg-g5.6" "G5.6" "FAIL" "surface.md without endpoint structure"
check "neg-g5.7" "G5.7" "WARN" "threat-model missing finding category"

echo ""
echo "============================="
echo "  Passed: $PASS   Failed: $FAIL"
echo "============================="
exit $FAIL
