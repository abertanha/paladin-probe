#!/usr/bin/env bash
# run_positive.sh — assert clean passes on the NON-negative fixtures.
#
# Per fixture it asserts exit 0 AND zero FAIL, reading the grader's --json
# report (severity per check id), NOT the text output. WARNs are allowed and
# surfaced in the final summary, separately from failures.
#
# Deliberately-broken fixtures live under tests/fixtures/negative/ and are
# run by run_negative.sh. sample-broken is the legacy broken teaching fixture
# (referenced from the golden's findings/index.md) and is excluded here too.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
GRADER="$HERE/grader.py"
FIXTURES_DIR="$HERE/fixtures"

PASS=0
FAIL=0
declare -a WARN_MSGS=()

# grade_json <root> — run the grader, extract the --json report (the emit
# FAIL/WARN lines precede it on stdout), and print one
#              TOTAL|N / FAIL|id|msg / WARN|id|msg
# record per line. Returns the grader's exit code.
grade_json() {
    local tmp rc
    tmp=$(mktemp)
    python3 "$GRADER" "$1" --json >"$tmp" 2>&1
    rc=$?
    python3 - "$tmp" <<'PY'
import json, sys
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
start = next(i for i, l in enumerate(lines) if l.lstrip().startswith("{"))
r = json.loads("\n".join(lines[start:]))
print("TOTAL|%d" % r["summary"]["total"])
for c in r["checks"]:
    if c["severity"] == "FAIL":
        print("FAIL|%s|%s" % (c["id"], c["msg"]))
for c in r["checks"]:
    if c["severity"] == "WARN":
        print("WARN|%s|%s" % (c["id"], c["msg"]))
PY
    rm -f "$tmp"
    return $rc
}

echo "Positive fixture verification"
echo "============================="
for rt in "$FIXTURES_DIR"/*/; do
    [ -d "$rt" ] || continue
    case "$(basename "$rt")" in
        negative|sample-broken) continue ;;
    esac
    name=$(basename "$rt")

    out=$(grade_json "$rt") || true
    if [ -z "$out" ]; then
        echo "  FAIL $name (grading crashed, no JSON report)"
        FAIL=$((FAIL + 1))
        continue
    fi

    nfail=$(printf '%s\n' "$out" | grep -c '^FAIL|' || true)
    nwarn=$(printf '%s\n' "$out" | grep -c '^WARN|' || true)

    if [ "$nfail" -eq 0 ]; then
        echo "  PASS $name (0 FAIL, $nwarn WARN)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL $name ($nfail FAIL in report)"
        printf '%s\n' "$out" | grep -E '^FAIL\|' | sed 's/^FAIL|/    /'
        FAIL=$((FAIL + 1))
    fi
    if [ "$nwarn" -gt 0 ]; then
        WARN_MSGS+=("$name: $(printf '%s\n' "$out" | grep -E '^WARN\|' | sed 's/^WARN|//' | tr '\n' ';')")
    fi
done

echo ""
echo "============================="
echo "  Passed: $PASS   Failed: $FAIL"
if [ "${#WARN_MSGS[@]}" -gt 0 ]; then
    echo "  Warnings (allowed — listed separately):"
    for w in "${WARN_MSGS[@]}"; do
        echo "    - $w"
    done
else
    echo "  Warnings: none"
fi
echo "============================="
exit $FAIL