#!/usr/bin/env bash
# run_consent.sh — pin the wrapper's consent contract at the CLI seam.
# Asserts, against the golden fixture (denied config) and a granted clone:
#   1. check denied  -> log_access/db_read_access/test_suite_oracle all =denied, exit 2
#   2. check granted -> the three granted lines, byte-format, exit 2
#   3. capture on an unconsented config -> refusal on stderr, exit 2
#   4. capture with an invalid --kind -> die, exit 8 (the external twin of
#      consent_globals' default arm — the arm itself is defensive; the kind
#      gate is what keeps it unreachable from outside)
# Builds scratch clones under mktemp; cleans up on exit; writes nothing to repo.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PROBE="$HERE/../scripts/probe.sh"
GOLDEN="$HERE/fixtures/sample-red-team"

PASS=0
FAIL=0

pass() { echo "  PASS $1"; PASS=$((PASS + 1)); }
fail() {
    echo "  FAIL $1"
    [ -z "${2:-}" ] || { echo "--- output ---"; echo "$2"; echo "---"; }
    FAIL=$((FAIL + 1))
}

get_rc() { "$@" >/dev/null 2>&1; return $?; }

assert_contains() {
    local label="$1" hay="$2" needle="$3"
    echo "$hay" | grep -qF -- "$needle" && pass "$label" || fail "$label (missing '$needle')" "$hay"
}

expect_exit() {
    local label="$1" want="$2" got="$3"
    [ "$got" -eq "$want" ] && pass "$label" || fail "$label (want exit $want, got $got)"
}

# scratch root: golden clone plus optional consent triplets appended to config.yaml
mkroot() {
    local dir
    dir="$(mktemp -d)"
    mkdir -p "$dir/.red-team"
    cp -r "$GOLDEN/.red-team/." "$dir/.red-team/"
    if [ -n "${1:-}" ]; then
        printf '%s\n' "$1" >> "$dir/.red-team/config.yaml"
    fi
    printf '%s' "$dir"
}

DENIED="$(mkroot)"
GRANTED="$(mkroot 'log_access:
  method: syslog
  target: /var/log/auth.log
db_read_access:
  kind: postgres
  dsn_env: TEST_DB_DSN
test_suite_oracle:
  command: pytest tests/oracle/test_auth.py')"
trap 'rm -rf "$DENIED" "$GRANTED"' EXIT

echo "Consent contract verification"
echo "============================="
echo ""

# 1. check on denied config
out="$(PALADIN_PROBE_ROOT="$DENIED" "$PROBE" check 2>&1 || true)"
assert_contains "check denied: log_access=denied" "$out" "log_access=denied"
assert_contains "check denied: db_read_access=denied" "$out" "db_read_access=denied"
assert_contains "check denied: test_suite_oracle=denied" "$out" "test_suite_oracle=denied"
set +e; PALADIN_PROBE_ROOT="$DENIED" "$PROBE" check >/dev/null 2>&1; rc=$?; set -e
expect_exit "check denied: exit 2" 2 "$rc"

# 2. check on granted config
out="$(PALADIN_PROBE_ROOT="$GRANTED" "$PROBE" check 2>&1 || true)"
assert_contains "check granted: log_access byte-format" "$out" "log_access=granted (method=syslog, target=/var/log/auth.log)"
assert_contains "check granted: db_read_access byte-format" "$out" "db_read_access=granted (kind=postgres, dsn_env=\$TEST_DB_DSN)"
assert_contains "check granted: test_suite_oracle=granted" "$out" "test_suite_oracle=granted"
set +e; PALADIN_PROBE_ROOT="$GRANTED" "$PROBE" check >/dev/null 2>&1; rc=$?; set -e
expect_exit "check granted: exit 2" 2 "$rc"

# 3. capture refuses on unconsented config (exit 2, refusal on stderr)
out="$(PALADIN_PROBE_ROOT="$DENIED" "$PROBE" capture --rt RT-999 --kind serverlog -- tail -1 /var/log/auth.log 2>&1 || true)"
assert_contains "capture refusal: message" "$out" "log_access (method+target) not consented — refusing capture"
set +e; PALADIN_PROBE_ROOT="$DENIED" "$PROBE" capture --rt RT-999 --kind serverlog -- tail -1 /var/log/auth.log >/dev/null 2>&1; rc=$?; set -e
expect_exit "capture refusal: exit 2" 2 "$rc"

# 4. invalid --kind dies (pair of the default arm)
out="$(PALADIN_PROBE_ROOT="$GRANTED" "$PROBE" capture --rt RT-999 --kind bogus -- echo x 2>&1 || true)"
assert_contains "capture bad kind: die message" "$out" "--kind must be serverlog | dbstate | test-oracle"
set +e; PALADIN_PROBE_ROOT="$GRANTED" "$PROBE" capture --rt RT-999 --kind bogus -- echo x >/dev/null 2>&1; rc=$?; set -e
expect_exit "capture bad kind: exit 8" 8 "$rc"

echo ""
echo "============================="
echo "  Passed: $PASS   Failed: $FAIL"
echo "============================="
exit $FAIL