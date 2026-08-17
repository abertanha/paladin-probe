# Findings Format, Verification & Requirements

## Verification Protocol

Before any finding is written, the agent MUST run this verification pipeline
to eliminate false positives.

### Step 1: Read the Handler

Read the full handler function, not just the route definition. Look for:

- Input validation: `if (!body.amount)`, `z.parse(body)`, `validate(schema)`
- Authorization checks: `requireAdmin`, `user.role === 'admin'`
- State guards: `if (order.status !== 'pending')`, `stateMachine.can('pay')`
- DB constraints: `@Unique`, `@Check`, foreign key enforcement
- Business logic: `if (quantity > MAX)`, `if (balance < amount)`

### Step 2: Trace Compensating Controls

Check for controls outside the handler:

- **Middleware**: does a parent router or middleware stack validate/auth?
- **DB layer**: are there DB-level constraints that prevent the abuse?
- **Type system**: does TypeScript/compiled type enforcement prevent the attack?
- **ORM layer**: does the ORM sanitize or parameterize queries?
- **Proxy/CDN**: does a reverse proxy add rate limiting, WAF rules?

### Step 3: Classify Confidence

| Confidence | Criteria | Action |
|------------|----------|--------|
| **High-verified** | Code confirms vulnerable path is reachable, no compensating control found, AND vulnerability was confirmed via live probe (curl request sent, response captured as evidence). | Write finding + requirements. This finding counts toward "Open" totals in SUMMARY. |
| **High-static** | Code confirms vulnerable path is reachable. No compensating control found. BUT no live-probe evidence captured — vulnerability is inferred from source, not confirmed at runtime. | Write finding + requirements. This finding appears in a separate "Static-Only (Pending Verification)" line in REPORT.md, NOT in the main "Open" count. |
| **Medium** | Pattern matches but partial guard exists (e.g., validates some fields but not all). Or code is ambiguous and needs human judgment. | Log to `.red-team/suspicious.md` for manual review |
| **Low** | Pattern matches but compensating control likely blocks it. Or finding was inferred from route list without reading handler. | Discard silently |

**Confidence ceiling**: static-only analysis (no live probe) caps confidence at
**High-static**. Only live-probe-confirmed findings can be **High-verified**.
Critical severity requires High-verified confidence.

### Step 3.5: Skeptic Pass (mandatory for High-verified / High-static)

Before writing the finding, spawn a fresh-context hostile reviewer with ONLY
the claim (never your reasoning). It hunts for the killing compensating
control and returns `VERDICT: upheld|weakened|killed`:

- `upheld` → write as classified
- `weakened` → write with severity −1 level and confidence capped at High-static
- `killed` → no finding; fingerprint into `.red-team/fp-history.yaml`
  (`discarded_by: skeptic`) + one line in `suspicious.md`

Record in the finding: flat key `skeptic_review: <verdict|skipped-no-harness>`
plus a `## Skeptic Review` body section (verdict, decisive artifact, rationale).
No subagent harness available → `skeptic_review: skipped-no-harness` and the
body section must name ≥3 concrete artifact paths checked and found absent.
Full prompt template and calibration rules:
[skeptic-review.md](skeptic-review.md).

**Important**: if you haven't read the handler code, confidence is automatically
Low. Always read the handler before classifying.

### Business Logic Specifics

Business logic probes are especially prone to false positives because the
"vulnerability" depends on domain rules, not just code patterns.

**Before reporting a business logic finding, verify:**

1. Does the handler actually accept the manipulated value? (read `req.body` handling)
2. Is there a server-side recalculation that overrides the client value?
3. Is there a DB constraint that prevents the invalid state?
4. Are there integration tests for this exact scenario?

### EPSS — Second Prioritization Axis

After classifying confidence, check EPSS (Exploit Prediction Scoring System)
for any finding that involves a CVE:

| EPSS Score | Meaning | Action |
|------------|---------|--------|
| > 0.9 | Almost certain to be exploited | Auto-boost to Critical severity |
| 0.5 - 0.9 | Highly likely | Consider one-level severity boost |
| 0.1 - 0.5 | Possible | Keep severity as-is |
| < 0.1 | Unlikely | Consider lowering priority |
| null | No CVE (logic/config flaw) | Use confidence + severity as-is |

EPSS measures real-world exploitation probability, not theoretical severity.
A CVSS 7 finding with EPSS 0.95 may be more urgent than CVSS 9 with EPSS 0.01.

### Diff-Aware Scanning

When the skill triggers from a PR (auto-suggest mode), scope the analysis to
the diff's blast radius instead of rebuilding the full threat model:

1. Identify which files changed in the diff
2. Map changed files to components in the attack surface
3. Only threat-model those components + their immediate dependencies
4. Only probe the affected routes + configs + deps

This prevents generating noise from pre-existing vulnerabilities unrelated to
the change being reviewed.

> **Re-verification is the mirror case:** when re-running against changed
> code, derive findings fresh BEFORE opening prior findings/REPORT/threat-model,
> then diff (New/Confirmed/Healed/Regressed/Escalated). See SKILL.md
> "Fresh-Derive-Then-Diff".

### False Positive History

Maintain `.red-team/fp-history.yaml` to avoid reprocessing known false
positives on subsequent scans:

```yaml
patterns:
  - id: fp-001
    fingerprint: "auth_missing_middleware_router_level"
    confidence: Low
    reason: "Route has auth middleware at parent router level, not inline"
    discarded_at: 2026-07-02
    discarded_by: automated
  - id: fp-002
    fingerprint: "mass_assignment_body_spread_no_validation"
    confidence: Medium
    reason: "TypeScript type checker strips unknown fields at compile time"
    discarded_at: 2026-07-02
    discarded_by: manual_review
```

Before writing any finding, generate a fingerprint of the pattern and check
against FP history. If matched:
- **Low** match → skip silently
- **Medium** match → skip but note in session log
- If user explicitly confirms a false positive → add to FP history

---

## Finding Schema

Each finding is written to `.red-team/findings/YYYY-MM-DD_rt-NNN.md`.

```yaml
---
schema_version: 2               # Schema version for forward compatibility
id: RT-003
title: Missing rate limiting on /api/login
category: Config Hardening     # Authentication Abuse | Authorization Abuse | Business Logic | Input Validation | SSRF | Insecure Deserialization | Secrets Exposure | Resource Exhaustion | Config Hardening | Dependency Audit
severity: High                  # Critical | High | Medium | Low | Info | N/A (FP only)
cwe: CWE-770                    # CWE identifier
blast_radius: Single credential compromised via brute-force
location: src/routes/auth.ts:12-18
detection_difficulty: Easy      # Easy | Hard | Undetectable
status: Open                    # Open | Fixed | Accepted | False Positive | Remediated | Regressed | Duplicate
  # IMPORTANT: False Positive and Duplicate findings MUST have severity: N/A
confidence: High-verified       # High-verified | High-static | Medium | Low
kev_listed: false               # In CISA Known Exploited Vulnerabilities?
epss_score: null                # EPSS exploitation probability (0-1), null if N/A
exploited_in_wild: false        # Known active exploitation in the wild
target_version:
  git_sha: a1b2c3d4e5f6...     # Resolved at scan time
  dirty: false                  # Uncommitted changes at scan time?
skill_version: paladin-probe@v3
skeptic_review: upheld           # optional flat key: upheld | weakened | killed | skipped-no-harness (see Step 3.5)
evidence:                       # Present only if live-probe confirmed
  captured_at: 2026-07-28T12:34:56Z
  captured_by: probe-wrapper
  request: .red-team/evidence/RT-003/2026-07-28T12-34-56Z-request.http
  response_status: 200
  response_excerpt: "HTTP 200 OK — no rate-limit headers present"
  capture_method: probe-wrapper   # probe-wrapper | instrumented-log | instrumented-db | instrumented-test | agent-bash-curl (legacy) | replay | manual
standards:                      # Compliance framework mappings — MAX 5 ROWS
  - framework: OWASP-Top-2025
    requirement_id: A02
  - framework: OWASP-WSTG
    requirement_id: WSTG-4.2.2
  - framework: OWASP-ASVS
    requirement_id: V1.1.1
  - framework: OWASP-API-2023
    requirement_id: API4
  - framework: CWE
    requirement_id: CWE-770
---
```

> **Token discipline:** tier the frontmatter by severity — Tier 1 keys always;
> Tier 2 (`blast_radius`, `detection_difficulty`, `target_version`) for Open
> High/Medium only; Tier 3 (`kev_listed`, `epss_score`, `exploited_in_wild`)
> for CVE-bearing High+ only. Low/Medium without a CVE MUST omit Tier 3 keys;
> FP/Duplicate MUST omit Tier 2 keys. See SKILL.md "Finding Format — Frontmatter tiers".

## Reproduction

1. Send 1000 POST /api/login in parallel
2. All return HTTP 200 (no 429, no rate-limit headers)

## Impact

Attacker can brute-force credentials at high speed with no throttling.
Combined with a weak password policy, this enables credential stuffing.

## Evidence

- Request log: [captured during probe session]
- Headers returned: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After` — all absent

### Standards Field Rules

**Closed vocabulary for `framework:`** — only these values are valid:

| Framework | Purpose | `requirement_id:` pattern | Example |
|-----------|---------|--------------------------|---------|
| `CWE` | Common Weakness Enumeration | `^CWE-\d+$` | CWE-770 |
| `OWASP-Top-2025` | OWASP Top 10 2025 | `^A\d{2}$` | A02 |
| `OWASP-WSTG` | OWASP Web Security Testing Guide | `^WSTG-\d+(\.\d+){0,2}$` | WSTG-4.2.2 |
| `OWASP-ASVS` | OWASP Application Security Verification Standard | `^V\d+\.\d+\.\d+$` | V1.1.1 |
| `OWASP-API-2023` | OWASP API Security Top 10 | `^API\d+$` | API4 |
| `NIST-800-53` | NIST SP 800-53 controls | `^[A-Z]+-\d+$` | AC-2 |
| `PCI-DSS` | PCI Data Security Standard | `^req-\d+(\.\d+)*$` | req-6.4 |

**5-row cap**: Max 5 `standards:` entries per finding. Selection priority:
1. **CWE** — always present (required for SARIF ruleId)
2. **OWASP-Top-2025** — always present when category has a mapping
3. **OWASP-WSTG** — always present when category has a mapping; pick most specific
4. **OWASP-ASVS** — added if a slot remains
5. **OWASP-API-2023** — added on API-endpoint findings if a slot remains
Drop NIST-800-53 and PCI-DSS first when the cap is reached. See `references/owasp-coverage-matrix.md` for per-category mapping.

**Empty `standards: []`** means the finding is unmapped — agent MUST populate before setting status to Open. When writing a comparison finding (e.g., comparing ASVS vs API-2023 for the same category), include both.

### Post-Write Checklist

Before marking the finding as complete, the agent MUST verify:

- [ ] `standards:` contains at least one `CWE` entry
- [ ] `standards:` contains at least one `OWASP-Top-2025` entry (when category is mapped)
- [ ] `standards:` contains at least one `OWASP-WSTG` entry (when category is mapped)
- [ ] All `framework:` values match the closed vocabulary
- [ ] All `requirement_id:` values match the per-framework regex pattern
- [ ] Total `standards:` entries ≤ 5
- [ ] Selection priority order: CWE → Top-10 → WSTG → ASVS → API-2023
- [ ] Empty `standards: []` is a flag — populate before marking Open
- [ ] `False Positive` findings have `severity: N/A` (not Critical/High/Medium/Low/Info)
- [ ] `High-verified` findings include a populated `evidence:` block in frontmatter
- [ ] High-verified/High-static findings carry `skeptic_review:` with a verdict
      (or `skipped-no-harness` + a ≥3-artifact-path trace in `## Skeptic Review`)
- [ ] If `evidence/RT-NNN/` exists but is empty, write `evidence/RT-NNN/SKIPPED.md` explaining why

Live-probe evidence is captured by `scripts/probe.sh` (execute it, never read it)
into `.red-team/evidence/<RT-NNN>/<timestamp>-request.http` and
`<timestamp>-response.http`, hashed into `manifest.sha256`. Differential probes
additionally write `<timestamp>-diff.txt`, and instrumented captures
(`probe.sh capture --kind serverlog|dbstate|test-oracle`) write
`<timestamp>-<kind>.instrumented.md` — all manifest-hashed. These raw captures
serve as auditable proof of reproduction; the frontmatter `evidence:` block
references the key capture. Set `capture_method: probe-wrapper` (default)
unless the evidence came from another source in the vocabulary above.

Instrumented confirmation (log line, DB state, or test-oracle output proving
the effect) qualifies for `confidence: High-verified` — cite the
`.instrumented.md` file, with or without an `.http` pair:

```yaml
evidence:
  captured_at: 2026-07-28T12:41:03Z
  captured_by: probe-wrapper
  request: .red-team/evidence/RT-007/2026-07-28T12-40-58Z-request.http   # the blind probe itself
  response_status: 200
  response_excerpt: "HTTP 200 — {\"status\": \"fetched\"} (blind: no URL echo)"
  instrumented: .red-team/evidence/RT-007/2026-07-28T12-41-03Z-serverlog.instrumented.md
  capture_method: instrumented-log
```

`instrumented:` is optional — include it when the decisive artifact is the
instrumented file rather than the response. The `capture_method` value tracks
the kind: serverlog → `instrumented-log`, dbstate → `instrumented-db`,
test-oracle → `instrumented-test`.

## Functional Requirements

- FR-003-1: Login endpoint MUST rate-limit requests per source IP
- FR-003-2: Endpoint MUST return HTTP 429 after exceeding the limit
- FR-003-3: Rate limit MUST reset after a defined cooling period

## Non-Functional Requirements

- NFR-003-1: Rate limit window and threshold MUST be configurable via environment variables
- NFR-003-2: Response MUST include standard rate-limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After)
- NFR-003-3: Rate limiting MUST NOT apply to health-check or monitoring endpoints

## Acceptance Criteria

- AC-003-1: GIVEN 100 parallel POST /api/login FROM same IP
             WHEN all responses received
             THEN at least 95 return HTTP 429
- AC-003-2: GIVEN a rate-limited IP
             WHEN waiting the cooling period
             THEN the next request returns the normal response (200 or 401)

## Decision Points

Each finding should include a `decision_points` section that explicitly lists
open choices the implementer needs to resolve. This eliminates ambiguity for
consuming dev skills.

### Decision Point Schema

```yaml
decision_points:
  - id: DP-003-1
    question: What is the rate limit threshold per IP?
    type: value                  # value | choice | convention
    context: >
      OWASP recommends 5 requests per 15 minutes for login endpoints.
      Project conventions and existing limits should guide the default.
    bounds: [5, 1000]            # only for type: value
  - id: DP-003-2
    question: What HTTP behavior on rate limit exceeded?
    type: choice
    context: >
      Project's existing error responses use JSON error bodies
      (see src/middleware/error-handler.ts).
    options:
      - "429 + Retry-After header + JSON body"
      - "429 + Retry-After header only"
  - id: DP-003-3
    question: Which env vars control the rate limit configuration?
    type: convention
    context: >
      Project uses APP_ prefix for env vars (see .env.example).
      Follow the same convention for naming.
    options:
      - APP_RATE_LIMIT_MAX
      - APP_RATE_LIMIT_WINDOW_MS
```

### Decision Point Types

| Type | When | Fields |
|------|------|--------|
| `value` | A numeric threshold or duration needs choosing | `bounds`, optional `unit` |
| `choice` | Two or more mutually exclusive approaches | `options` list |
| `convention` | Naming or pattern that must match project style | `options` or reference to conventions |

### Context Extraction

Decision points should reference discovered project conventions when possible:

- **Env var naming**: If `.env.example` shows `APP_*` pattern, recommend `APP_RATE_LIMIT_MAX`
- **Error format**: If error handler returns `{"error": "...", "code": NNN}`, recommend JSON body
- **Middleware style**: If existing middleware is async functions, recommend same pattern
- **Domain terms**: If project says "organization" not "tenant", use "organization"

---

## Requirements Consolidation

After the probe session, all findings with confidence `High-verified` or
`High-static` are consolidated into `.red-team/remediation-requirements.md`.
`High-verified` findings appear at the top of each severity group, followed by
`High-static` findings clearly labeled as "(Static — pending live verification)".

### Format

```markdown
# Security Remediation Requirements

Generated: 2026-07-02
Session: /probe pentest

---

## RT-003: Missing rate limiting on /api/login
Priority: High
KEV Listed: No | EPSS: N/A | Exploited in Wild: No
Location: src/routes/auth.ts:12-18

### Functional
- FR-003-1: Login endpoint MUST rate-limit per source IP
- FR-003-2: Must return HTTP 429 after exceeding threshold
- FR-003-3: Rate limit MUST reset after cooling period

### Non-Functional
- NFR-003-1: Configurable window/threshold via env vars
- NFR-003-2: Standard rate-limit headers in response
- NFR-003-3: Health endpoints excluded from rate limiting

### Acceptance Criteria
- AC-003-1: 100 parallel requests → ≥95 return 429
- AC-003-2: After cooling → request succeeds

### Decision Points
- DP-003-1: Threshold bound [5, 1000] — pick or accept default
- DP-003-2: Window bound [1m, 60m] — pick or accept default
- DP-003-3: Block behavior — 429 + Retry-After + JSON body (recommended)
- DP-003-4: Env var convention — APP_RATE_LIMIT_MAX, APP_RATE_LIMIT_WINDOW_MS

---

## RT-007: JWT accepts 'none' algorithm
Priority: Critical
KEV Listed: No | EPSS: N/A | Exploited in Wild: No
Location: src/middleware/auth.ts:22

### Functional
- FR-007-1: JWT verification MUST reject tokens with alg: "none"
- FR-007-2: Token MUST be verified against RS256 public key

### Non-Functional
- NFR-007-1: Algorithm must be explicitly whitelisted, not inferred from token header

### Acceptance Criteria
- AC-007-1: Token with {"alg": "none", "sub": "admin"} → server returns 401
- AC-007-2: Token signed with HS256 when RS256 expected → server returns 401
```

---

## Suspicious Items (Medium Confidence)

Items below High confidence are logged to `.red-team/suspicious.md`:

```yaml
items:
  - title: Possible mass assignment on /api/users
    location: src/routes/users.ts:45
    confidence: Medium
    reason: Body spread used (...req.body) but no admin field in schema.
             However, TypeScript type check may prevent this at compile time.
    manual_review: Check if validation middleware strips unknown fields
```

These are never reported as findings — they require human judgment.
