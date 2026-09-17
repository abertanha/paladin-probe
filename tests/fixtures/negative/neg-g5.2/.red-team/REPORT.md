# Red Team Report — Sample Fixture

**Probe Date:** 2026-07-29
**Target:** https://app.example.com (staging)
**Skill Version:** paladin-probe@v3
**Method:** Live probes + code analysis

## Summary

| Severity | Open | Static-Only (Pending Verification) | Fixed |
|----------|------|-----------------------------------|-------|
| Critical | 0    | 0                                 | 0     |
| High     | 0    | 0                                 | 0     |
| Medium   | 0    | 1                                 | 0     |
| Low      | 0    | 0                                 | 0     |

### High

| ID | Title | CWE | Route |
|----|-------|-----|-------|
| RT-002 | Missing rate limiting on /auth endpoints | CWE-770 | /auth/login, /auth/token |

### Medium

| ID | Title | CWE | Route |
|----|-------|-----|-------|
| RT-003 | Debug endpoints enabled in production | CWE-489 | /debug/pprof, /debug/vars |

## False Positives

- **RT-001** — API key leaked in logs (CWE-532)
- **RT-004** — SQL injection via username field (CWE-89)

## Remediation

See [remediation-requirements.md](remediation-requirements.md) for detailed
functional and non-functional requirements per finding.

## Exports

- [CSV](exports/findings.csv)
- [SARIF](exports/findings.sarif)
- [VEX](exports/vex.json)
