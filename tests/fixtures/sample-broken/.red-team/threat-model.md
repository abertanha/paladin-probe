# Threat Model — Sample Fixture

This document catalogs threats for the sample application.

## Findings Coverage

The following Open findings are addressed:

- **RT-002** — Missing rate limiting on /auth endpoints
  - Threat: Brute force login
  - Mitigation: Implement rate limiting at the API gateway
- **RT-003** — Debug endpoints enabled in production
  - Threat: Information disclosure, DoS
  - Mitigation: Disable debug endpoints in production

## False Positives

- **RT-001** — API key leaked in logs: Observed in log review but not reproducible.
- **RT-004** — SQL injection via username field: Parameterized queries confirmed in code.
