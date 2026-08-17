# Remediation Requirements — Sample Fixture

## RT-002: Missing rate limiting on /auth endpoints
**Priority:** High
**Status:** Open

### Acceptance criteria
- AC-001-1: /auth/login rejects requests exceeding 10/min/IP

### Decision Points
- DP-001-1: Gateway-level vs application-level rate limiting
