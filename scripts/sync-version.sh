#!/usr/bin/env bash
# Reconcile every paladin-probe@v<N> marker in the repo to @v$(cat VERSION).
#
# VERSION (skill root) is the single source of truth for the release number.
# A bump is: edit VERSION, then run this script — it rewrites every
# paladin-probe@v<N> occurrence repo-wide (SKILL.md, references/, fixtures,
# docs) to the new marker and verifies no divergence remains.
#
# tests/fixtures/negative/ is deliberately exempt: those fixtures seed
# version drift on purpose for the G5.9 negative test and are governed by
# tests/run_negative.sh, not by the reconcile sweep.
#
# Idempotent: steady state (every marker already == VERSION) is a
# byte-identical no-op. Exit 1 if VERSION is missing or any marker still
# differs after the sweep.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="$REPO_DIR/VERSION"

[ -f "$VERSION_FILE" ] || {
    echo "sync-version: VERSION missing at $VERSION_FILE (single source of truth)" >&2
    exit 1
}

NEW_N="$(tr -d '[:space:]' < "$VERSION_FILE")"
NEW_TOKEN="paladin-probe@v$NEW_N"

# Guard: tooling must never carry a *literal* paladin-probe@vN marker — the
# sweep would rewrite the harness itself (self-modifying, non-deterministic,
# as bash re-reads scripts incrementally). Fail loudly before touching anything.
tooling_literal="$(grep -rIl 'paladin-probe@v[0-9][0-9]*' \
    "$REPO_DIR/scripts" \
    "$REPO_DIR"/tests/*.sh "$REPO_DIR"/tests/*.py 2>/dev/null || true)"
if [ -n "$tooling_literal" ]; then
    echo "sync-version: literal marker in tooling (sweep would corrupt harness): $tooling_literal" >&2
    echo "  derive the version from VERSION instead of embedding it" >&2
    exit 1
fi

updated=0
ok=0
while IFS= read -r -d '' f; do
    [ "$f" = "$VERSION_FILE" ] && { ok=$((ok + 1)); continue; }
    current="$(grep -o 'paladin-probe@v[0-9][0-9]*' "$f" 2>/dev/null | sort -u || true)"
    [ -z "$current" ] && continue
    if [ "$current" = "$NEW_TOKEN" ]; then
        ok=$((ok + 1))
        continue
    fi
    sed -i -E "s/paladin-probe@v[0-9]+/$NEW_TOKEN/g" "$f"
    updated=$((updated + 1))
done < <(find "$REPO_DIR" -path "$REPO_DIR/.git" -prune -o \
         -path "$REPO_DIR/tests/fixtures/negative" -prune -o -type f -print0)

remaining="$(grep -rIho 'paladin-probe@v[0-9][0-9]*' --exclude-dir=.git \
             --exclude-dir=negative "$REPO_DIR" | sort -u || true)"
if [ -z "$remaining" ]; then
    echo "sync-version: no paladin-probe@vN markers found in repo" >&2
    exit 1
fi
if [ "$remaining" != "$NEW_TOKEN" ]; then
    echo "sync-version: divergence remaining: $remaining (expected $NEW_TOKEN)" >&2
    exit 1
fi

echo "sync-version: all markers at $NEW_TOKEN (updated $updated set, $ok already ok)"