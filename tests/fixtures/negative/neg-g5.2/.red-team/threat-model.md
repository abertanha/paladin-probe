# Threat Model — Sample Fixture

**Date:** See [REPORT.md](REPORT.md)

This document catalogs threats for the sample application.

## Open Findings

### RT-002 — Missing rate limiting on /auth endpoints

| Category | Threat | Risk | Finding |
|----------|--------|------|---------|
| Config Hardening | Brute force login — no rate limiting on /auth endpoints | High | RT-002 |
| Config Hardening | Token harvesting via /auth/token without rate limiting | High | RT-002 |

### RT-003 — Debug endpoints enabled in production

| Category | Threat | Risk | Finding |
|----------|--------|------|---------|
| Config Hardening | Debug endpoints /debug/pprof and /debug/vars exposed in production | Medium | RT-003 |
| Config Hardening | DoS vector via debug endpoints in production | Medium | RT-003 |

## False Positives

- **RT-001** — API key leaked in logs: Observed in log review, secrets exposure review — not reproducible.
- **RT-004** — SQL injection via username field: input validation review — parameterized queries confirmed in code, injection not present.
