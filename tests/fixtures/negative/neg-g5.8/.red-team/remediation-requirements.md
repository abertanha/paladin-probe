# Remediation Requirements — Sample Fixture

## RT-002: Missing rate limiting on /auth endpoints
**Priority:** High
**Status:** Open

### Acceptance Criteria
- AC-001-1: /auth/login rejects requests exceeding 10/min/IP

### Decision Points
- DP-001-1: Gateway-level vs application-level rate limiting

## RT-003: Debug endpoints enabled in production
**Priority:** Medium
**Status:** Open

### Acceptance Criteria
- AC-003-1: /debug/pprof and /debug/vars return 404 in production builds

### Decision Points
- DP-003-1: Feature-flag gating vs build-time removal
