#!/usr/bin/env bash
# run_all.sh — full self-audit suite (negative + positive + consent).
#   run_negative.sh : deliberately-broken fixtures must trigger their defect.
#   run_positive.sh : clean fixtures must pass (exit 0, zero FAIL).
#   run_consent.sh  : wrapper consent contract (check granted/denied, refusal).
# Exit code is the SUM of the per-suite failure counts.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
neg_rc=0
pos_rc=0
consent_rc=0

"$HERE/run_negative.sh" || neg_rc=$?
echo ""
"$HERE/run_positive.sh" || pos_rc=$?
echo ""
"$HERE/run_consent.sh" || consent_rc=$?

total=$((neg_rc + pos_rc + consent_rc))
echo ""
echo "==================================="
echo "  run_all: neg failures=$neg_rc  positive failures=$pos_rc  consent failures=$consent_rc  total=$total"
echo "==================================="
exit $total