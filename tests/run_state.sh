#!/usr/bin/env bash
# run_state.sh — verify `grader.py state` against the artifacts on disk.
#
# Asserts (on the golden fixture):
#   1. every state --json cell agrees with an INDEPENDENT re-derivation of the
#      .red-team/ tree (a minimal frontmatter reader, not the grader's parser);
#   2. output ordering is stable across runs (modulo derived_at);
#   3. the command is read-only (no byte in .red-team/ changes).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
GRADER="$HERE/grader.py"
GOLDEN="$HERE/fixtures/sample-red-team"
RT="$GOLDEN/.red-team"
PASS=0
FAIL=0

ok()  { echo "  PASS $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL $1"; FAIL=$((FAIL + 1)); }

echo "State query verification"
echo "========================"

# ── read-only: snapshot the tree, run state, confirm nothing changed ───────
snapshot() { find "$RT" -type f -exec sha256sum {} \; | sort; find "$RT" -type d | sort; }
before="$(snapshot)"
json="$(python3 "$GRADER" state "$GOLDEN" --json)"
after="$(snapshot)"
if [ "$before" = "$after" ]; then ok "state is read-only (tree snapshot unchanged)"; else bad "state wrote to .red-team/"; fi

# ── stable ordering ───────────────────────────────────────────────────────
json2="$(python3 "$GRADER" state "$GOLDEN" --json)"
a="$(printf '%s' "$json" | grep -v '"derived_at"')"
b="$(printf '%s' "$json2" | grep -v '"derived_at"')"
if [ "$a" = "$b" ]; then ok "ordering stable across runs"; else bad "ordering not stable"; fi

# ── cell-to-cell vs an independent disk re-derivation ─────────────────────
state_tmp="$(mktemp)"
printf '%s' "$json" > "$state_tmp"
verdict="$(python3 - "$GOLDEN" "$state_tmp" <<'PY'
import glob, json, os, re, sys

state = json.load(open(sys.argv[2], encoding="utf-8"))
rt = os.path.join(sys.argv[1], ".red-team")
errors = []

def check(name, got, want):
    if got != want:
        errors.append(f"{name}: got={got!r} want={want!r}")

def fm(path):
    text = open(path, encoding="utf-8").read()
    m = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
    d = {}
    if not m:
        return d
    for line in m.group(1).splitlines():
        mm = re.match(r"^([\w\-.]+):[ \t]*(.*)$", line)
        if mm:
            d[mm.group(1)] = mm.group(2).strip().strip("\"'")
    return d

findings = {}
for p in sorted(glob.glob(os.path.join(rt, "findings", "*.md"))):
    if os.path.basename(p) == "index.md":
        continue
    f = fm(p)
    if f.get("id"):
        findings[f["id"]] = f

counts = {"open": 0, "static_only": 0, "fixed": 0, "fp": 0, "duplicate": 0}
by_sev = {}
flist = []
for fid in sorted(findings):
    f = findings[fid]
    st, cf, sev = f.get("status", ""), f.get("confidence", ""), f.get("severity", "")
    if st == "Open" and cf == "High-verified":
        counts["open"] += 1
    elif st == "Open" and cf == "High-static":
        counts["static_only"] += 1
    if st in ("Fixed", "Remediated"):
        counts["fixed"] += 1
    elif st == "False Positive":
        counts["fp"] += 1
    elif st == "Duplicate":
        counts["duplicate"] += 1
    if sev:
        by_sev[sev] = by_sev.get(sev, 0) + 1
    flist.append({"id": fid, "status": st, "confidence": cf, "category": f.get("category", "")})

chains = [os.path.splitext(os.path.basename(p))[0]
          for p in sorted(glob.glob(os.path.join(rt, "chains", "CH-*.md")))]
manifests = sorted(glob.glob(os.path.join(rt, "evidence", "*", "manifest.sha256")))
aborted = [os.path.splitext(os.path.basename(p))[0]
           for p in sorted(glob.glob(os.path.join(rt, ".probe-state", "*.aborted")))]

dates = []
for name in ("REPORT.md", "surface.md", "threat-model.md"):
    try:
        text = open(os.path.join(rt, name), encoding="utf-8").read()
    except FileNotFoundError:
        continue
    m = re.search(r"(?:\*\*)?(?:Probe date|probe_date|Date):(?:\*\*)?\s*(\d{4}-\d{2}-\d{2})", text)
    if m:
        dates.append(m.group(1))
for p in glob.glob(os.path.join(rt, "findings", "*.md")) + glob.glob(os.path.join(rt, "evidence", "*", "*")):
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", os.path.basename(p))
    if m:
        dates.append(m.group(1))

check("counts", state["counts"], counts)
check("by_severity", state["by_severity"], {k: by_sev[k] for k in sorted(by_sev)})
check("findings", state["findings"], flist)
check("chains", state["chains"], chains)
check("evidence_manifests", state["evidence_manifests"], len(manifests))
check("aborted_hosts", state["aborted_hosts"], aborted)
check("last_probe_date", state["last_probe_date"], max(dates) if dates else None)

print("OK" if not errors else "; ".join(errors))
PY
)"
rm -f "$state_tmp"
if [ "$verdict" = "OK" ]; then ok "cells agree with disk (counts/by_severity/findings/chains/manifests/aborted/date)"; else bad "cell mismatch: $verdict"; fi

echo ""
echo "========================"
echo "  Passed: $PASS   Failed: $FAIL"
echo "========================"
exit $FAIL