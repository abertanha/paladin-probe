# Threat Model — Sample Fixture

**Date:** See [REPORT.md](REPORT.md)

This document catalogs threats for the sample application.

## Open Findings

### RT-002 — Missing rate limiting on /auth endpoints

| Category | Threat | Risk | Finding |
|----------|--------|------|---------|
| Security Misconfiguration | Brute force login — no rate limiting on /auth endpoints | High | RT-002 |
| Security Misconfiguration | Token harvesting via /auth/token without rate limiting | High | RT-002 |

### RT-005 — Rate limiting missing on /auth/token endpoints

| Category | Threat | Risk | Finding |
|----------|--------|------|---------|
| Security Misconfiguration | Token harvesting — missing rate limiting on /auth/token endpoints | High | RT-005 |

### RT-003 — Debug endpoints enabled in production

| Category | Threat | Risk | Finding |
|----------|--------|------|---------|
| Security Misconfiguration | Debug endpoints /debug/pprof and /debug/vars exposed in production | Medium | RT-003 |
| Security Misconfiguration | DoS vector via debug endpoints in production | Medium | RT-003 |

## False Positives

- **RT-001** — API key leaked in logs: Observed in log review, information disclosure review only, not reproducible.
- **RT-004** — SQL injection via username field: Parameterized queries confirmed in code, injection not present.
