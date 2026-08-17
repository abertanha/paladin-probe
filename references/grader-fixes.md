# Grader Fix Routines

**Purpose:** Step-by-step fix procedures for each paladin-probe grader check ID. The
agent MUST consult this file when the Self-Audit Loop (see `SKILL.md`) encounters
a FAIL severity check.

**Usage:** Do NOT read this file in bulk. Extract the check ID from the grader
output (e.g. `FAIL G5.2`, `WARN G5.1`), then load only the matching section:

```bash
awk '/^### G5\.2 /,/^---$/' references/grader-fixes.md
```

Replace `G5.2` with the check ID from the grader output (the `.` is regex-escaped;
the trailing space matches `### G5.1 (semantic) — …` headings too). Each section
is self-contained — `### Gx.y — Title` delimited by a `---` line (the last
section runs to EOF). Run one `awk` per failing check ID; never read sections
for PASS checks.

---

## G1.x — Finding Frontmatter Integrity

### G1.1 — Missing required frontmatter keys

| Findings affected | Missing key(s) |
|---|---|
| RT-002, RT-003, RT-004, RT-008 | `confidence` |

**Fix:**

1. Open the finding file (`findings/YYYY-MM-DD_rt-NNN.md`).
2. Locate the `---` frontmatter block.
3. Add the key `confidence:` with a value from the closed vocabulary
   `High-verified | High-static | Medium | Low` (bare `High` and `Verified`
   are NOT valid values):
   - Open findings: `High-verified` (live-probe confirmed, evidence block
     required) or `High-static` (code-confirmed only)
   - Remediated/Fixed findings: keep the last classification they had while
     open (usually `High-verified` if a probe confirmed them, else `High-static`)
   - False Positive findings: `Low` (confidence the vulnerability is real)
4. Save the file.

---

### G1.2 — Schema version mismatch

`schema_version` MUST be `2` on all finding files. If not:

1. Open the finding file frontmatter.
2. Change `schema_version: 1` to `schema_version: 2`.
3. Save.

---

### G1.4 — FP finding with non-N/A severity

**Fix:**

1. Open the finding file (`findings/YYYY-MM-DD_rt-NNN.md`).
2. In the frontmatter, change `severity: <X>` to `severity: N/A`.
3. Save.

---

### G1.5 — High-verified missing evidence block

**Fix:** Write the `evidence:` block into the frontmatter:

```yaml
evidence:
  captured_at: <ISO timestamp from the capture>
  captured_by: agent-bash-curl
  request: "<curl command or request summary>"
  response_status: <HTTP status code>
  response_excerpt: "<first 200 chars of response body>"
  capture_method: agent-bash-curl
```

If no live capture exists, confidence should be demoted to `High-static`.

---

### G1.6 — Standards regex violation

**Fix:** For each non-compliant `standards:` entry:

1. Check the `framework:` value against the closed vocabulary:  
   `CWE | OWASP-Top-2025 | OWASP-WSTG | OWASP-ASVS | OWASP-API-2023 | NIST-800-53 | PCI-DSS`
2. Check the `requirement_id:` value against the framework's regex (see `findings-format.md`):  
   - CWE: `^CWE-\d+$`
   - OWASP-Top-2025: `^A\d{2}$`
   - OWASP-WSTG: `^WSTG-\d+(\.\d+){0,2}$`
   - OWASP-ASVS: `^V\d+\.\d+\.\d+$`
   - OWASP-API-2023: `^API\d+$`
3. Correct any mismatches by referencing `references/owasp-coverage-matrix.md`.

---

### G1.7 — Standards priority order or row cap exceeded

**Fix:** Reorder or trim the `standards:` array:

1. Sort rows by priority: CWE → OWASP-Top-2025 → OWASP-WSTG → OWASP-ASVS → OWASP-API-2023
2. If more than 5 rows, drop NIST-800-53 and PCI-DSS first, then OWASP-API-2023, then OWASP-ASVS.
3. Ensure CWE is always first.

---

### G1.8 — Potential duplicate findings (WARN)

The WARN names two findings sharing the same CWE and either the same location
prefix or ≥2 shared title tokens.

**Fix — pick one:**

1. **Merge** into a single finding: keep the more general `title`/`location`,
   close the other with `status: Duplicate` (severity `N/A`, confidence
   `Low` — G1.4 enforces N/A). Add a `duplicate_of: <RT-NNN>` line in the
   body explaining the relationship.
2. **Distinguish** them if they are genuinely different layers: edit one
   finding's `title` so it no longer shares ≥2 tokens (e.g. "Secrets in Git
   History (Repository)" vs "Static Token — No Rotation (Runtime)"), or make
   the `location` prefixes disjoint.

After either fix, re-export CSV/SARIF/VEX and re-run the grader. A clean run
must emit `PASS G1.8`.

---

### G1.9 — Non-canonical category values (WARN)

The WARN lists findings whose `category:` is not one of the ten canonical
values (see SKILL.md "Probe Categories"). Typical offenders: abbreviations
(`Config`, `AuthZ`), OWASP names (`Security Misconfiguration`), or older
generations of the taxonomy (`Information Disclosure`).

**Fix:**

1. Map the value to its canonical equivalent (e.g. `Security Misconfiguration`
   → `Config Hardening`, `Information Disclosure` → `Secrets Exposure`,
   `Injection` → `Input Validation`, `Dependency` → `Dependency Audit`).
2. Change `category:` in the finding's frontmatter.
3. Propagate the same value everywhere it appears: `threat-model.md` table
   cells (G5.7 checks coverage by exact substring), `findings/index.md`,
   `exports/findings.csv`, `exports/findings.sarif`.
4. Re-run the grader — G1.9 and G5.7 must both clear.

---

### G1.10 — Skeptic review incomplete (WARN)

Evaluated only when at least one finding carries a `skeptic_review:` key. The
WARN names either High-verified/High-static findings missing the key, or
findings carrying a value outside `upheld | weakened | killed |
skipped-no-harness`.

**Fix:**

1. For each finding listed as missing: run the skeptic gate (see
   [skeptic-review.md](skeptic-review.md) for the prompt template) and add the
   flat key `skeptic_review: <verdict>` to the frontmatter, plus the
   `## Skeptic Review` body section.
2. If no subagent harness is available: `skeptic_review: skipped-no-harness`
   and a `## Skeptic Review` body section naming ≥3 concrete artifact paths
   checked and found absent.
3. For invalid values: replace with one of the four valid verdicts (or remove
   the key entirely if the session predates the skeptic gate — removing it on
   every finding silences the check).

---

## G2.x — Cross-Artifact Consistency

### G2.2 — traceability.json missing entries or stale titles

**Fix (regeneration):**

1. Read `findings/` for every `.md` file with frontmatter `id:`.
2. Read `remediation-requirements.md` for `## RT-NNN:` sections. Parse FR/AC/DP IDs from the `###` blocks.
3. Rebuild `traceability.json` from scratch:

```json
{
  "schema_version": 2,
  "findings": {
    "RT-NNN": {
      "title": "<from finding frontmatter>",
      "standards": ["<framework>:<requirement_id>", ...],
      "requirements": ["FR-NNN-1", "FR-NNN-2", ...],
      "acceptance_criteria": ["AC-NNN-1", ...],
      "decision_points": ["DP-NNN-1", ...],
      "domain_rules": [],
      "tests": {"passed": [], "failed": []},
      "status": "<from finding frontmatter>"
    }
  },
  "last_updated": "<now>"
}
```

4. Write the file. Bump `last_updated` to the current ISO timestamp.
5. Ensure `schema_version` is `2`.

---

### G2.3 — traceability.json schema_version ≠ 2

**Fix:** Change `"schema_version": 1` to `"schema_version": 2` in traceability.json.

---

### G2.5 — Remediation heading casing

**Fix:** If `### Acceptance criteria` (lowercase c) appears:

1. Open `remediation-requirements.md`.
2. Replace all occurrences of `### Acceptance criteria` with `### Acceptance Criteria`.
3. Save.

---

### G2.6 — traceability AC/DP arrays don't match remediation-requirements.md

**Fix (alignment-first):**

1. Read `traceability.json` and `remediation-requirements.md`.
2. For each `## RT-NNN` section in the rem file, parse the `### Acceptance Criteria` and `### Decision Points` bullet IDs.
3. Compare to `traceability.json.findings[RT-NNN].acceptance_criteria` and `decision_points`.
4. **If they already match, stop** — do not regenerate (alignment-first).
5. Only if they **diverge**, update only the diverged entries in `traceability.json`:
   - Patch `acceptance_criteria` and/or `decision_points` arrays
   - Bump `last_updated` to current ISO timestamp
   - Do **not** touch other fields (standards, requirements, tests, status)
6. Save `traceability.json`.

---

### G3.1 — CSV missing row

**Fix (add row):**

```csv
<id>,"<title>",<category>,<severity>,<cwe>,<status>,<confidence>,<location>,<detection_difficulty>,<kev_listed>,<owasp_top_2025>,<owasp_wstg>,<remediated_date>
```

1. Read finding frontmatter for `id`, `title`, `category`, `severity`, `cwe`, `status`, `confidence`, `location`, `detection_difficulty`, `kev_listed`.
2. `owasp_top_2025` = first `OWASP-Top-2025` value from `standards:`; blank if none.
3. `owasp_wstg` = first `OWASP-WSTG` value from `standards:`; blank if none.
4. `remediated_date` = extract from frontmatter or body; blank if Open/FP.
5. Append to `exports/findings.csv`. Re-sort rows by id.

---

### G3.2 — SARIF missing result

**Fix (add rule + result):**

1. Read finding `cwe`, `title`, `severity`, `status`, `confidence`, `standards`, `location`.
2. Compute SARIF level: error(High) / warning(Medium) / note(Low) / none(FP).
3. If no `rule` with that CWE id exists in `runs[0].tool.driver.rules[]`:
   ```json
   {"id": "CWE-NNN", "name": "<short title>", "shortDescription": {"text": "<title>"}, "defaultConfiguration": {"level": "<level>"}, "properties": {"category": "<category>", "precision": "very-high"}}
   ```
4. Append a `result`:
   ```json
   {"ruleId": "CWE-NNN", "ruleIndex": <index>, "level": "<level>", "message": {"text": "<title>"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "<location>"}}}], "properties": {"status": "<status>", "confidence": "<confidence>", "standards": "<framework>:<requirement_id>; ..."}}
   ```
5. Re-sort results by ruleIndex to maintain ordering.

---

### G3.3 — VEX missing statement

**Fix (add statement):**

1. Read finding `id`, `title`, `cwe`, `standards`, `status`, `confidence`.
2. Determine VEX status per the OpenVEX Mapping table in SKILL.md:
   - High-verified Open → `known_affected`
   - High-static Open → `under_investigation`
   - False Positive → `not_affected`
   - Fixed/Remediated → `fixed`
3. Build `vulnerability` block:
   ```json
   {"name": "<RT-NNN>", "description": "<title>", "aliases": ["CWE:CWE-NNN", "OWASP-Top-2025:A0X", ...]}
   ```
   **Never** put CWE ids in `vulnerability.cve`. That field is reserved for CVE ids only.
4. Build statement:
   ```json
   {"vulnerability": {...}, "products": [{"@id": "pkg:github/<org>/<repo>"}], "status": "<status>", "action_statement": "<remediation summary>"}
   ```

---

### G3.4 — VEX cve field carries CWE id

**Fix:**

For each affected statement in `vex.json`:

1. Read `vulnerability.cve`. If it starts with `CWE-`, this is wrong.
2. Move the full identifier (e.g., `CWE-306`) into `vulnerability.aliases` as `"CWE:CWE-306"` (if not already present).
3. Remove the `cve` field entirely, or replace it with a real CVE id if known.
4. Continue only after all CWE ids have been moved to aliases.

---

### G3.5 — VEX status doesn't match finding

**Fix:**

For each affected statement in `vex.json`:

1. Look up the finding's `confidence` and `status` from the finding file frontmatter or traceability.json.
2. Map to the correct VEX status per the OpenVEX Mapping table in SKILL.md.
3. Replace `"status": "<old>"` with `"status": "<correct>"`.
4. If changing FROM `under_investigation` TO `known_affected`, also remove `"justification": "requires_assessment"`.

---

### G3.6 — Exports stale relative to findings

**Fix:**

1. Read `vex.json` and `findings.sarif`.
2. Compare their `timestamp` (VEX) / `invocations[0].endTime` (SARIF) to the newest finding file's mtime.
3. **If findings haven't changed** (no `status` or `confidence` frontmatter edits since the last export), exports are still content-correct. Bump timestamps to now:
   - VEX: update `"timestamp"` to ISO now
   - SARIF: update `"invocations[0].startTime"`, `"invocations[0].endTime"`, and `"properties.generated_at"` to ISO now
4. **If findings HAVE changed**, regenerate exports from scratch per Phase E in SKILL.md, then bump timestamps.
5. Save both files.

---

## G4.x — Evidence Cleanliness

### G4.2 — Empty evidence directory

**Fix:**

1. Check `config.yaml` `consent` section and session notes for why the probe was skipped.
2. Write `evidence/RT-NNN/SKIPPED.md`:

```markdown
# RT-NNN: <title> — Probe skipped
**Skipped at:** <timestamp>
**Reason:** <e.g., "Turnstile blocked signup; no PROBE_AGX_PASSWORD set">
**To unblock:** <e.g., "Set PROBE_AGX_PASSWORD env var and re-run live phase">
```

3. If no documented reason exists, remove the empty directory entirely.

---

### G4.3 — X-Paladin-Probe header missing

**Fix:** For each `*-request.http` file that lacks the header:

1. Add a line after the HTTP request line (or the first Host: header):
   ```
   X-Paladin-Probe: v3
   ```
2. Save the file.

---

### G4.4 — Evidence manifest drift (WARN)

`manifest.sha256` (written by `scripts/probe.sh`) no longer matches the
evidence files: a listed file changed after capture, or is missing.

**Fix:**

1. **Hash mismatch** — the evidence file was edited after capture. NEVER
   update the manifest to match the edited file (that launders tampering).
   Instead re-capture via `probe.sh send`/`diff`, or restore the original
   file from version control, then re-run `probe.sh verify`.
2. **Missing file** — restore from version control or re-run the probe that
   produced it. If neither is possible, delete the stale manifest line and
   note the loss in the finding's `## Evidence` body section.
3. Re-run the grader — a clean run emits `PASS G4.4`.

---

## G5.x — Config & Surface

### G5.3 — config.yaml missing schema_version or skill_version

**Fix:**

1. Open `.red-team/config.yaml`.
2. Add at the top (after any comment lines, below `---` if present):
   ```yaml
   schema_version: 2
   skill_version: paladin-probe@v2
   ```
3. Save.

---

### G5.4 — Probe-date divergence across reports

**Fix:**

1. Read `surface.md` and `threat-model.md`.
2. For each file, locate any `probe_date`, `generated`, or `Date:` line that carries an independent date value.
3. Replace the entire line with: `**Date:** See [REPORT.md](REPORT.md)`
4. Remove any other embedded date references in those files.
5. Do **not** touch the date line in `REPORT.md` — that is the single source of truth.

---

### G5.1 (semantic) — Threat-model row context mismatch (WARN)

The WARN names findings whose table-row contexts in `threat-model.md` share
fewer than 2 key tokens with the finding's frontmatter `title`. This catches
wrong-ID associations (e.g. RT-006 "path-to-regexp ReDoS" next to a CORS row).

**Fix:**

1. For each WARNed `RT-NNN`, find every table row that references the ID.
2. Rewrite the row's threat-description cells so they contain ≥2 tokens from
   the finding title (lowercased, ≥4 chars, ignoring stopwords like
   `the/and/via/post/route`). Do NOT paste the title verbatim — restate the
   threat naturally (e.g. "CORS wildcard origin on /unauth/" for a finding
   titled "CORS Wildcard Origin on All Routes").
3. Re-run the grader — the WARN must disappear.

---

### G5.2 — REPORT.md summary reconciliation (FAIL)

**Fix:**

1. If counts diverge: edit the `## Summary` table cells in `REPORT.md` so the
   `Open` column counts `status: Open` + `confidence: High-verified`,
   `Static-Only` counts `status: Open` + `confidence: High-static`, and
   `Fixed` counts `status: Fixed/Remediated`, per severity.
2. If titles diverge: copy the exact `title` from each finding's frontmatter
   into the matching row of the per-severity table.
3. If coverage fails: add the missing finding rows under the correct
   `### <Severity>` section, or remove unknown IDs.
4. If header fields are missing (WARN): add `**Probe Date:**`,
   `**Target:**`, `**Skill Version:**`, `**Method:**` lines above `## Summary`.
5. Re-run the grader.

---

### G5.6 — surface.md missing content structure (FAIL)

**Fix:** Rewrite `.red-team/surface.md` so it lists every endpoint found in
the codebase route declarations (or other surface units: GraphQL operations,
cron jobs, queue consumers). For each entry include `method`, `path`, `auth`
(Required/Optional/None) and the handler `file:line`. Keep the `**Probe
date:**` line matching `REPORT.md`'s `Probe Date`. The grader requires: a
top-level `#` heading, at least one table row or path list line, and ≥1
recognizable `/path` reference.

---

### G5.8 — Attack-chain integrity (WARN)

Evaluated only when chains exist (a `chains/CH-*.md` doc or any finding with a
`chain:` key). The WARN names either a `chain:` value with no matching
`chains/CH-NNN.md`, or a chain doc whose `links:` name an RT-id that doesn't
exist in `findings/`.

**Fix:**

1. **Missing chain doc** — either write the missing `chains/CH-NNN.md`
   (format in [attack-chains.md](attack-chains.md)), or remove the stale
   `chain:` key from the finding's frontmatter.
2. **Unknown RT-id in links** — fix the typo to the real finding id, or remove
   the id from `links:`. A link to a finding you only *planned* is a step-row
   without evidence, not a link. Never leave a dangling RT-id anywhere (G2.1
   regexes RT-NNN ids in REPORT.md).

---

### G5.7 — Threat-model missing finding categories (WARN)

**Fix:** Edit `threat-model.md` so every `category` value used in
`findings/*.md` frontmatter appears as text in the file (case-insensitive).
Do NOT add rows for categories with no findings — only ensure existing rows
use the same category vocabulary as the findings (e.g. "Dependency Audit",
not "Dependency"; "Resource Exhaustion", not "DoS").
