#!/usr/bin/env bash
# Version single-source regression (ticket 04): VERSION is the source of truth
# and paladin-probe@v<N> is always derived. Asserts:
#   1. wrapper (probe.sh) derives PROBE_VERSION from VERSION, not hardcode;
#   2. full-repo marker sweep is exactly one value == @v$(cat VERSION)
#      (tests/fixtures/negative/ is excluded: it deliberately seeds drift
#      for the G5.9 negative fixture and is governed by run_negative.sh);
#   3. sweep is idempotent (2nd run is a byte-level no-op);
#   4. a bump (VERSION -> 9, a 1-byte edit) is reconciled repo-wide by the
#      sweep, then reverted to the original value and swept back.
# Restores VERSION and re-reconciles on any failure (trap EXIT).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SYNC="$REPO_DIR/scripts/sync-version.sh"
VERSION_FILE="$REPO_DIR/VERSION"
ORIGINAL_VERSION="$(tr -d '[:space:]' < "$VERSION_FILE")"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

markers() { grep -rIho 'paladin-probe@v[0-9][0-9]*' --exclude-dir=.git --exclude-dir=negative "$REPO_DIR" | sort -u; }
marker_count() { markers | wc -l; }
fingerprint() { grep -rlI 'paladin-probe@v[0-9][0-9]*' --exclude-dir=.git --exclude-dir=negative "$REPO_DIR" | sort | xargs -r sha256sum | sha256sum | cut -d' ' -f1; }

cleanup() {
    if [ "$(tr -d '[:space:]' < "$VERSION_FILE")" != "$ORIGINAL_VERSION" ]; then
        printf '%s' "$ORIGINAL_VERSION" > "$VERSION_FILE"
    fi
    "$SYNC" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "run_version: VERSION=$ORIGINAL_VERSION  want=paladin-probe@v$ORIGINAL_VERSION"
echo "===================="
echo ""

# 1. wrapper derives (no hardcoded numeric version)
echo "derive: probe.sh PROBE_VERSION from VERSION..."
grep -q 'PROBE_VERSION="v$(cat' "$REPO_DIR/scripts/probe.sh" || fail "probe.sh PROBE_VERSION is not derived from VERSION"
echo "  PASS derive"

# 2. steady-state sweep: exactly one marker value
echo "sweep: full-repo markers at @v$(cat "$VERSION_FILE")..."
"$SYNC" >/dev/null || fail "steady-state sync exited non-zero"
[ "$(marker_count)" -eq 1 ] || fail "expected exactly 1 marker value, got: $(markers | tr '\n' ' ')"
[ "$(markers | head -1)" = "paladin-probe@v$ORIGINAL_VERSION" ] || fail "marker != paladin-probe@v$ORIGINAL_VERSION"
echo "  PASS sweep (1 value)"

# 3. idempotency at steady state
echo "idempotency: second run byte-level no-op..."
FP1="$(fingerprint)"
"$SYNC" >/dev/null || fail "second steady-state sync exited non-zero"
FP2="$(fingerprint)"
[ "$FP1" = "$FP2" ] || fail "second sync changed file bytes (not a no-op)"
echo "  PASS idempotency"

# 4. bump: edit VERSION to a new number, sweep reconciles everything
echo "bump: VERSION -> 9 (1-byte edit), reconcile all markers..."
printf '9' > "$VERSION_FILE"
[ "$(wc -c < "$VERSION_FILE")" -eq 1 ] || fail "VERSION is not a 1-byte edit"
"$SYNC" >/dev/null || fail "bump sync exited non-zero"
WANT="paladin-probe@v$(tr -d '[:space:]' < "$VERSION_FILE")"
[ "$(marker_count)" -eq 1 ] || fail "after bump: expected exactly 1 marker value, got: $(markers | tr '\n' ' ')"
[ "$(markers | head -1)" = "$WANT" ] || fail "after bump: marker != $WANT"
FP3="$(fingerprint)"
"$SYNC" >/dev/null || fail "second bump sync exited non-zero"
FP4="$(fingerprint)"
[ "$FP3" = "$FP4" ] || fail "bump sync is not idempotent"
echo "  PASS bump->9 sweep"

# revert
echo "revert: VERSION back to $ORIGINAL_VERSION, sweep back..."
printf '%s' "$ORIGINAL_VERSION" > "$VERSION_FILE"
"$SYNC" >/dev/null || fail "revert sync exited non-zero"
[ "$(marker_count)" -eq 1 ] || fail "after revert: expected exactly 1 marker value"
[ "$(markers | head -1)" = "paladin-probe@v$ORIGINAL_VERSION" ] || fail "after revert: marker mismatch"
echo "  PASS revert sweep"

echo ""
echo "===================="
echo "  run_version: all assertions passed"