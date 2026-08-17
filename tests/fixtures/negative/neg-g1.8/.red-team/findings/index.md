# Red Team — Sample Fixture

This directory is a synthetic fixture for the paladin-probe self-audit grader.
It is the GOLD-STANDARD all-passing fixture: the grader must report
**0 FAIL / 0 WARN** on it. For the deliberately-broken teaching fixture see
`tests/fixtures/sample-broken/`.

## Finding index

| Finding | Status | Severity | Confidence  | G1 G2 G3 G4 G5 |
|---|---|---|---|---|
| RT-001 | False Positive | N/A | Verified | PASS all |
| RT-002 | Open | High | High-verified | PASS all |
| RT-003 | Open | Medium | High-static | PASS all |
| RT-004 | False Positive | N/A | Verified | PASS all |
| RT-005 | Open | High | High-static | WARN G1.8 (dup of RT-002) |

## Cross-artifacts

- `traceability.json` — schema_version=2, covers all 4 findings, AC/DP arrays
  match remediation-requirements.md (PASS G2.6)
- `exports/findings.csv` — covers all 4 findings (PASS G3.1)
- `exports/findings.sarif` — 4 results with `properties.standards` (PASS G3.2)
- `exports/vex.json` — 4 statements, statuses match Open/confidence mapping,
  `cve` reserved for CVE ids only (PASS G3.3/G3.4/G3.5)
- `evidence/` — RT-001 has SKIPPED.md, RT-002 has request+response capture,
  RT-004 has SKIPPED.md (FP review) (PASS G4.x)
- `REPORT.md` — severity-grouped summary tables, titles match finding
  frontmatter exactly (PASS G5.2)
- `threat-model.md` — STRIDE tables referencing RT-002/RT-003 with matching
  title tokens, covers all finding categories (PASS G5.1/G5.7)
- `surface.md` — endpoint table with probe date matching REPORT.md (PASS G5.4/G5.6)

## Sanity-check commands

```bash
python3 tests/grader.py tests/fixtures/sample-red-team --verbose
# Expect: 0 FAIL, 0 WARN
```
