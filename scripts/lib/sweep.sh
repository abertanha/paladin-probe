# scripts/lib/sweep.sh — single definition of the paladin-probe@vN marker
# pattern and the sweep exclusions. Consumed by scripts/sync-version.sh
# (reconcile) and tests/run_version.sh (regression) so the two can never
# drift apart on what "the mark" is or what is exempt.
#
# Rules this file must obey:
#   - never carry a literal @vN token: sync-version's tooling guard treats a
#     literal marker inside scripts/ as self-modifying and aborts (grep's BRE
#     does NOT match the character-class text below — that is deliberate);
#   - the marker is always derived from VERSION at call time;
#   - exclusions are matched by basename (`.git`, `negative`) so `find` and
#     `grep --exclude-dir` share one semantics. `tests/fixtures/negative/`
#     (basename `negative`) deliberately seeds version drift for the G5.9
#     negative test and is governed by tests/run_negative.sh.
set -euo pipefail

# Marker regex (BRE — compatible with `grep` BRE and `sed -E`).
SWEEP_MARKER_RE='paladin-probe@v[0-9][0-9]*'

# Basenames exempt from the sweep.
SWEEP_EXCLUDE=(.git negative)

# marker_values <repo> — distinct marker strings present in the tree.
marker_values() {
    local repo="$1" exargs=() d
    for d in "${SWEEP_EXCLUDE[@]}"; do exargs+=(--exclude-dir="$d"); done
    grep -rIho "$SWEEP_MARKER_RE" "${exargs[@]}" -- "$repo" | sort -u
}

# marker_files <repo> — files containing at least one marker, sorted.
marker_files() {
    local repo="$1" exargs=() d
    for d in "${SWEEP_EXCLUDE[@]}"; do exargs+=(--exclude-dir="$d"); done
    grep -rlI "$SWEEP_MARKER_RE" "${exargs[@]}" -- "$repo" | sort
}

# sweep_files <repo> — every non-excluded file below repo (NUL-terminated,
# for the sync-version write loop).
sweep_files() {
    local repo="$1" args=() d
    for d in "${SWEEP_EXCLUDE[@]}"; do args+=(-name "$d" -prune -o); done
    find "$repo" "${args[@]}" -type f -print0
}