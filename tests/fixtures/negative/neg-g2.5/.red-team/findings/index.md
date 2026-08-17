# Red Team — Sample Fixture

This directory is a synthetic fixture for the paladin-probe self-audit grader.

## Finding index

| Finding | Status | Severity | Confidence        | G1 G2 G3 G4 G5 |
|---|---|---|---|---|
| RT-001 | False Positive | N/A | Verified | PASS G1.4 |
| RT-002 | Open | High | High-verified | PASS all G1 |
| RT-003 | Open | Medium | (missing) | FAIL G1.1 |
| RT-004 | False Positive | Critical | Verified | FAIL G1.4 |

## Cross-artifacts

- `traceability.json` — schema_version=2, covers all 4 findings (PASS G2.2)
- `exports/findings.csv` — covers all 4 findings (PASS G3.1)
- `exports/findings.sarif` — 4 results (PASS G3.2)
- `exports/vex.json` — 4 statements (PASS G3.3)
- `evidence/` — RT-001 has SKIPPED.md, RT-002+RT-003 have evidence files, RT-004 is empty (FAIL G4.2)
