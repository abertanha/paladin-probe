#!/usr/bin/env bash
# run_checkpoint.sh — verify the `probe.sh checkpoint` handoff mechanics.
#
# Runs against a throwaway copy of the golden fixture (never writes to a
# tracked fixture). Asserts:
#   1. --write produces a checkpoint whose frontmatter parses with the
#      grader's own YAML parser and whose mechanical fields (findings_written,
#      pending_high_static, evidence_manifests) agree with the tree on disk;
#   2. --read returns the current checkpoint verbatim;
#   3. probe.sh verify still exits 0 after a checkpoint is written;
#   4. one file per boundary: a second phase gets its own file and does not
#      touch the first; session_id is reused across boundaries;
#   5. the consent snapshot is copied from config.yaml, then frozen for the
#      session (a mid-session config edit does not leak in), and re-copied
#      for a new session.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PROBE="$HERE/../scripts/probe.sh"
GOLDEN="$HERE/fixtures/sample-red-team"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp -r "$GOLDEN/." "$WORK/"
RT="$WORK/.red-team"

PASS=0
FAIL=0
ok()  { echo "  PASS $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL $1"; FAIL=$((FAIL + 1)); }

sha() { sha256sum "$1" | awk '{print $1}'; }
sid() { sed -n 's/^session_id:[[:space:]]*//p' "$1" | head -1; }
ckpt_path() { printf '%s' "$1" | sed -n 's/^.*checkpoint=\([^ ]*\).*$/\1/p'; }

echo "Checkpoint verification"
echo "======================="

# ── 1. write the recon boundary ───────────────────────────────────────────
out1="$(bash "$PROBE" checkpoint --write --root "$WORK" --phase recon \
    --summary "RECON done; 2 hypotheses pending." \
    --next "live-confirm RT-003" --next "chain RT-001->RT-002" \
    --decided-open DP-001 --context-pct 12)"
recon="$(ckpt_path "$out1")"
if [ -f "$recon" ]; then ok "checkpoint written at the recon boundary"; else bad "checkpoint not written ($out1)"; fi

fm_verdict="$(python3 - "$HERE" "$WORK" "$recon" <<'PY'
import glob, os, sys
sys.path.insert(0, sys.argv[1])
from grader import parse_frontmatter, _parse_yaml

work, path = sys.argv[2], sys.argv[3]
fm = parse_frontmatter(open(path, encoding="utf-8").read())
rt = os.path.join(work, ".red-team")
errors = []

def chk(name, got, want):
    if got != want:
        errors.append(f"{name}: got={got!r} want={want!r}")

ids, pending = [], []
for p in sorted(glob.glob(os.path.join(rt, "findings", "*.md"))):
    if os.path.basename(p) == "index.md":
        continue
    f = parse_frontmatter(open(p, encoding="utf-8").read()) or {}
    if f.get("id"):
        ids.append(f["id"])
    if f.get("status") == "Open" and f.get("confidence") == "High-static" and f.get("id"):
        pending.append(f["id"])
manifests = len(glob.glob(os.path.join(rt, "evidence", "*", "manifest.sha256")))
cfg = _parse_yaml(open(os.path.join(rt, "config.yaml"), encoding="utf-8").read())

chk("phase", fm.get("phase"), "recon")
chk("effort", fm.get("effort"), "standard")
chk("consent_snapshot", fm.get("consent_snapshot"), cfg.get("consent"))
chk("context_budget_used_pct", fm.get("context_budget_used_pct"), 12)
chk("findings_written", sorted(fm.get("findings_written") or []), sorted(ids))
chk("pending_high_static", sorted(fm.get("pending_high_static") or []), sorted(pending))
chk("decided_open", fm.get("decided_open"), ["DP-001"])
chk("evidence_manifests", fm.get("evidence_manifests"), manifests)
chk("next_planned_steps", fm.get("next_planned_steps"),
    ["live-confirm RT-003", "chain RT-001->RT-002"])
if not fm.get("session_id"):
    errors.append("session_id missing")
print("OK" if not errors else "; ".join(errors))
PY
)"
if [ "$fm_verdict" = "OK" ]; then ok "frontmatter roundtrip; mechanical counts agree with disk"; else bad "frontmatter: $fm_verdict"; fi

# ── 2. --read returns the current checkpoint verbatim ─────────────────────
read1="$(bash "$PROBE" checkpoint --read --root "$WORK")"
if [ "$read1" = "$(cat "$recon")" ]; then ok "--read returns the checkpoint verbatim"; else bad "--read mismatch"; fi

# ── 3. probe.sh verify still passes after a write ─────────────────────────
if bash "$PROBE" verify --root "$WORK" >/dev/null 2>&1; then ok "probe.sh verify exit 0 after write"; else bad "verify non-zero after write"; fi

# ── 4. one file per boundary; session_id reused ───────────────────────────
recon_before="$(sha "$recon")"
out2="$(bash "$PROBE" checkpoint --write --root "$WORK" --phase model --summary "MODEL done." --next "probe auth")"
model="$(ckpt_path "$out2")"
if [ -f "$model" ] && [ "$model" != "$recon" ]; then ok "second boundary gets its own file"; else bad "boundary files collide"; fi
if [ "$(sha "$recon")" = "$recon_before" ]; then ok "writing model left the recon checkpoint intact"; else bad "recon checkpoint changed"; fi
if [ -n "$(sid "$recon")" ] && [ "$(sid "$recon")" = "$(sid "$model")" ]; then ok "session_id reused across boundaries"; else bad "session_id not reused"; fi

read2="$(bash "$PROBE" checkpoint --read --root "$WORK")"
if [ "$read2" = "$(cat "$model")" ]; then ok "--read returns the newest checkpoint"; else bad "--read returned the wrong checkpoint"; fi

# ── 5. consent snapshot: copied, frozen for the session, re-copied anew ────
sed -i 's/^  scope:.*/  scope: MUTATED/' "$RT/config.yaml"
bash "$PROBE" checkpoint --write --root "$WORK" --phase post-probe --summary "POST done." >/dev/null
post="$(ls -1 "$RT"/sessions/*_checkpoint-post-probe.md)"
if grep -q 'scope: auth + users endpoints' "$post"; then ok "consent snapshot frozen for the session"; else bad "mid-session config edit leaked into the snapshot"; fi
bash "$PROBE" checkpoint --write --root "$WORK" --phase verify --summary "new session" --session-id NEWSESSION >/dev/null
fresh="$(ls -1 "$RT"/sessions/*_checkpoint-verify.md)"
if grep -q 'scope: MUTATED' "$fresh"; then ok "a new session re-copies consent from config.yaml"; else bad "new session did not re-copy consent"; fi

# ── 6. rewriting a boundary replaces only that file ───────────────────────
post_before="$(sha "$post")"
bash "$PROBE" checkpoint --write --root "$WORK" --phase post-probe --summary "POST done v2." >/dev/null
if [ "$(sha "$RT"/sessions/*_checkpoint-post-probe.md)" != "$post_before" ]; then ok "rewriting a boundary updates its file"; else bad "rewrite did not update"; fi
if [ "$(sha "$recon")" = "$recon_before" ]; then ok "boundary files are independent"; else bad "rewrite corrupted another boundary"; fi

echo ""
echo "======================="
echo "  Passed: $PASS   Failed: $FAIL"
echo "======================="
exit $FAIL
