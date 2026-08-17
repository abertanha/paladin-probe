# Threat Model — Sample Fixture

**Date:** See [REPORT.md](REPORT.md)

This document catalogs threats for the sample application.

## Open Findings

### RT-002 — Missing rate limiting on /auth endpoints

| Category | Threat | Risk | Finding |
|----------|--------|------|---------|
| Security Misconfiguration | CORS wildcard permits arbitrary cross-origin requests | High | RT-002 |
| Security Misconfiguration | Missing Content-Security-Policy header on all responses | High | RT-002 |

### RT-003 — Debug endpoints enabled in production

| Category | Threat | Risk | Finding |
|----------|--------|------|---------|
| Security Misconfiguration | Debug endpoints /debug/pprof and /debug/vars exposed in production | Medium | RT-003 |
| Security Misconfiguration | DoS vector via debug endpoints in production | Medium | RT-003 |

## False Positives

- **RT-001** — API key leaked in logs: Observed in log review, information disclosure review only, not reproducible.
- **RT-004** — SQL injection via username field: Parameterized queries confirmed in code, injection not present.
