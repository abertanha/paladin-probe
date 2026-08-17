---
name: paladin-probe
description: >
  Experimental red-team skill for adversarial application security testing.
  Probes for business logic abuse, auth bypass, input validation flaws, config
  hardening gaps, and dependency vulnerabilities. Outputs security requirements
  for dev skills to implement — does not write code or tests.
allowed-tools: Read, Bash, Grep, Glob, Write, Edit, Task
---

# Paladin Probe — Experimental Red-Team Skill

Adversarial testing for application security. Answers "how can I break this?"
— not "does this work?" — by thinking like an attacker who knows the codebase.
Output is security requirements grounded in project conventions, not code.
Dev skills handle implementation.

## Trigger Modes

| Trigger | Mode | Behavior |
|---------|------|----------|
| `/probe pentest` | Pentest | Full scan: surface mapping → probe every category → report |
| `/probe quick <path>` | Pentest | Scan single path for deps + config + input flaws |
| `/probe model` | Either | Generate STRIDE threat model only |
| `/probe report` | Either | Consolidate all findings into requirements spec |
| `/probe re-verify` | Either | Re-run probes for Fixed/Regressed findings against current code |
| `/probe verify-all` | Either | Re-derive all findings from scratch, then diff against priors |
| `/probe chain [asset]` | Chain | Multi-stage exploitation chains from prior findings (≥2 findings in ≥2 categories) |
| `/probe export` | Either | Regenerate CSV/SARIF/VEX exports from current findings |

Auto-suggest: when PR touches auth, deps, or security config, suggest `/probe quick`.

## Workflow

```
RECON      MODEL      PROBE       VERIFY       CONTEXT       REPORT
──────────────────────────────────────────────────────────────────────────
routes     STRIDE     auth        read code    discover      findings/
deps       per        logic       trace        docs          requirements.md
configs    endpoint   input       controls     extract       decision_points
schemas    risk       config      classify     conventions
auth       score      deps        confidence   ask user
gates
```

Effort (`config.yaml: effort`, default `standard`) scales hypotheses per
endpoint, chain depth, and revisit policy — see "Effort knob" under Flat
Config Schema.

## Onboarding (first activation)

1. Ask: environment (dev/staging/prod?), skip-list (`skip_routes`), intensity (dry-run/cautious/aggressive), effort (standard/deep/exhaustive)
2. Auto-detect: package manager, test framework, web framework, auth strategy
3. Present consent checklist before starting:
   - [ ] Live HTTP requests allowed? (required for High-verified confidence)
   - [ ] Destructive tests allowed? (state-mutating POST/PUT/DELETE)
   - [ ] Routes to probe: [`list all detected routes`]
   - [ ] Routes to skip: [`from user input`]
   - [ ] Environment: [`dev | staging | prod`]
   - [ ] OOB callbacks allowed? (for blind SSRF/XXE/SQLi confirmation)
   - [ ] Instrumented reads allowed? (server logs, read-only DB, test-suite
     oracle — granted via `log_access` / `db_read_access` / `test_suite_oracle`
     config keys; absent = denied)
   - [ ] Abort on 5xx? (slams brakes if target misbehaves)
   - If live requests are denied, confidence caps at **High-static** automatically
4. Save config to `.red-team/config.yaml`

Before the first live request, show the user the wrapper's resolved consent
state (`bash scripts/probe.sh check` prints it) and the planned probe count:
> "Live probe about to send [N] requests to [target URL] — consent: live=[true/false],
> mutating=[yes/no], skip_routes=[list]. Confirm or abort."

## Verification Protocol

Before any finding is written, the agent must verify it. This prevents false
positives by ensuring the vulnerable path is actually reachable.

### Pipeline

```
PROBE DETECTS SOMETHING SUSPICIOUS
        │
        ▼
  1. READ THE HANDLER CODE IN FULL
     - Not just the route — the entire handler function
     - Look for: validation guards, DB constraints, state checks
        │
        ▼
  2. TRACE COMPENSATING CONTROLS
     - Middleware that validates input upstream?
     - DB-level constraints (UNIQUE, CHECK, FK)?
     - State machine preventing the transition?
     - Tests covering this exact edge case?
        │
        ▼
   3. CLASSIFY CONFIDENCE
      High-verified: code confirms vuln + live-probe evidence captured
      High-static:   code confirms vuln, no compensating control, no live evidence
      Medium:        pattern matches but partial guard exists
      Low:           pattern matches but likely handled
         │
         ▼
   3.5 SKEPTIC PASS (fresh-context subagent)
      High-verified/High-static only — before writing. A hostile reviewer
      with ONLY the claim hunts for the killing compensating control.
      upheld   → write as classified
      weakened → severity −1, confidence capped at High-static
      killed   → no finding; fingerprint into fp-history.yaml
      (see references/skeptic-review.md — prompt template + recording rules)
         │
         ▼
   4. OUTPUT
      High-verified  → Write finding, counts toward "Open" total
      High-static    → Write finding, listed as "Static-Only (Pending Verification)"
      Medium         → Add to "Suspicious" section in report, not a finding
      Low            → Skip entirely
```

### When to Skip vs. Report

| Confidence | Action |
|------------|--------|
| High-verified | Write finding + requirements. Appears in "Open" count in REPORT.md summary. |
| High-static | Write finding + requirements. Appears in "Static-Only (Pending Verification)" line — NOT in main "Open" count. |
| Medium | Log in `.red-team/suspicious.md` for manual review — no finding |
| Low | Discard silently |

**Confidence ceiling**: Static-only analysis (no live probe) caps at **High-static**.
Only live-probe execution can produce **High-verified**. Critical severity requires
High-verified confidence.

**Skeptic gate**: No `High-verified` or `High-static` finding is written until a
fresh-context skeptic subagent has tried to kill it — see
[references/skeptic-review.md](references/skeptic-review.md) for the prompt
template, verdict semantics, and recording rules.

## Flat Config Schema

All `.red-team/config.yaml` files MUST include at the top:

```yaml
schema_version: 2
skill_version: paladin-probe@v3
```

The grader (check G5.3) validates both fields exist. `schema_version` tracks the
config schema itself; `skill_version` identifies which skill version wrote the
config.

### Effort knob

Optional config key (absent = `standard`; no schema implication — G5.3 ignores it):

```yaml
effort: deep                   # standard | deep | exhaustive
```

| Dimension | standard | deep | exhaustive |
|-----------|----------|------|------------|
| Hypotheses per endpoint | 3 | 6 | 10 |
| Chain depth (`/probe chain`) | 2 | 4 | 6 |
| Revisit policy | none | re-probe High-static findings after the grader loop | + re-scan Fixed findings for regressions |
| Reference loading | adjacent categories only | any reference a live hypothesis enters (log each) | any, plus re-read on surface change |
| Skeptic pass | per finding | per finding | per finding, re-run on verdict conflicts |

Higher effort buys depth, not speed: it scales how many hypotheses you generate
per endpoint and how far chains are pursued — the two levers that actually
exercise multi-step reasoning. `standard` is the default; do not select
`exhaustive` without consent for the extra request volume it implies.
`probe.sh check` prints the resolved level.

## Live Probe Protocol (Wrapper-Driven)

Live probes are executed through `scripts/probe.sh` — a wrapper that mechanically
enforces consent, throttling, and evidence capture, so agent turns go to analysis,
not ceremony. Invoke it via Bash; parse its one-line stdout.

> **Treat `probe.sh` like `tests/grader.py` — execute it, never read it.**

### When to run

Run live probe **only** after:
1. Static RECON → MODEL → PROBE → VERIFY pipeline has completed
2. At least one `High-static` finding exists that needs runtime confirmation
3. User has explicitly granted consent (see Onboarding consent checklist)
4. Target is confirmed reachable and responding

### The wrapper enforces

Never re-implement these by hand — hand-rolled `curl` bypassing the wrapper is a
protocol violation:

- **Consent gates** — refuses before any send: `consent.live_requests` not true
  (exit 2), URL matches `skip_routes` (exit 3), mutating verb while
  `consent.destructive_tests: false` (exit 4). No flag overrides these.
- **Traceability** — injects non-overridable `X-Paladin-Probe: v3` and
  `User-Agent: paladin-probe/v3` on every request.
- **Idempotency** — auto-generates `X-Paladin-Probe-Idempotency` on mutating
  verbs (or reuses `--idempotency-key` across retries of one probe).
- **Throttle** — per-host minimum gap from `throttle_seconds` (default 1s).
- **429 backoff** — sleeps 2/4/8s, max 3 retries, then aborts the endpoint (exit 5).
- **5xx circuit breaker** — >30% 5xx over ≥4 requests in any rolling 60s aborts
  the session, writes `.red-team/sessions/<date>_abort.md`, and refuses the host
  for 10 minutes (exit 7).
- **Evidence capture** — writes `evidence/<RT-NNN>/<ts>-request.http` (full
  headers + first 4096B body) and `<ts>-response.http` (status + headers +
  first 1000B body), hashes both into `manifest.sha256`. Same-second sends get
  collision-proof suffixes.

Exit codes: 0 ok · 2/3/4 consent · 5 429-exhausted · 6 transport · 7 breaker ·
8 usage · 9 evidence-write · 10 manifest drift. Full options: `probe.sh --help`.

### The agent does

```bash
scripts/probe.sh check                                  # resolved consent, no network
scripts/probe.sh send --rt RT-003 --method GET --url U  # one consented request
scripts/probe.sh diff --rt RT-003 --method GET \
  --url 'https://t/api/{{page}}' --var page=admin --var-base page=profile
scripts/probe.sh capture --rt RT-003 --kind serverlog -- 'tail -n 200 /var/log/app/api.log'
scripts/probe.sh verify                                 # recheck all manifests
```

- **Choose what to probe** — the wrapper has no opinion.
- **`diff` = differential oracle.** Sends a baseline (with `--var-base` values,
  unknown `{{KEY}}` tokens stripped so it is always sendable) then a follow-up
  (with `--var` values), normalizes volatile headers (Date, Set-Cookie, ETag,
  Server, Content-Length, …), and writes `<ts>-diff.txt`. `delta=identical`
  where you expected divergence is a **negative result** — record it in the
  finding; do not discard it.
- **Before trusting any prior evidence**, run `verify` (exit 10 = tampering).
- **Before any mutating request**, check for cleanup templates in the relevant
  `references/<category>.md` — the wrapper can't know cleanup semantics.

### Instrumented evidence (capture)

Some hypotheses can't be closed by an HTTP pair alone — the response is blind
(SSRF, XXE), the effect is in state (a mutating request's DB rows), or the
oracle already exists (the project's own test suite). `probe.sh capture` runs
a consented read-only command and records its output as evidence:

```bash
scripts/probe.sh capture --rt RT-007 --kind serverlog -- \
  'tail -n 200 /var/log/app/api.log | grep -i outbound'
scripts/probe.sh capture --rt RT-004 --kind dbstate -- \
  'psql "$APP_DB_DSN" -c "select * from audit_log order by id desc limit 5"'
scripts/probe.sh capture --rt RT-009 --kind test-oracle -- 'make test-security'
```

- **Kind-gated consent** (absent key = denied): `log_access: {method, target}`
  for serverlog, `db_read_access: {kind, dsn_env}` for dbstate (env-var NAME
  only — the wrapper never reads the DSN value), `test_suite_oracle:
  {command}` for test-oracle. The command must reference the consented
  target/env name (or match the consented command exactly for test-oracle).
- **When:** serverlog after a blind probe (did the SSRF fetch actually fire?),
  dbstate after a mutating request (did the row land / get rolled back?),
  test-oracle as an independent check of a control.
- Output: `evidence/<RT>/<ts>-<kind>.instrumented.md` — provenance header
  (command, consent ref, exit code), secrets masked, hashed into the manifest.
  A failing oracle command is a recorded result, not a capture failure.
- **Instrumented confirmation qualifies for High-verified**: the evidence
  block cites the `.http` pair and/or the `.instrumented.md` file with
  `capture_method: instrumented-log | instrumented-db | instrumented-test`.
  The Critical-requires-High-verified rule is unchanged.

**SKIPPED.md rule:** If a probe category is intentionally skipped (e.g., consent
denied, target unreachable, no applicable endpoints), the agent MUST write
`evidence/RT-NNN/SKIPPED.md` explaining why. Empty evidence directories are
flagged by the grader (G4.2). (Not wrapper-enforced — skipping is a decision.)

### Post-probe

After all live probes complete:
- Update each finding's frontmatter `evidence:` block with the captured data
  (`capture_method: probe-wrapper` by default)
- Promote confidence from `High-static` to `High-verified` (if confirmed)
- Demote to `Closed (FP — compensating control demonstrated)` (if control blocked)
- Regenerate REPORT.md with the new "Static-Only (Pending Verification)" separation
- Regenerate exports (CSV, SARIF, VEX) **only if** a finding's frontmatter `status` or `confidence` was changed — appending re-verification notes alone does not trigger regen

## Context Discovery

Before writing requirements, ground them in project conventions. This reduces
ambiguity for dev skills consuming the findings.

### Discovery sources

Scan for:
- `.specs/` — project specs, architecture, conventions (from spec-driven skill)
- `.business-logic/` — domain rules (from domain-druid skill)
- `docs/` — project documentation
- `README.md`, `CONTRIBUTING.md`
- `src/middleware/` — existing middleware patterns
- `src/config/`, `.env.example` — env var naming conventions

### Ask the user

If no docs found, ask once per session:

> "I found no project documentation files. Do you have any docs or convention
> guides I should reference when writing requirements?"

If user provides paths, read them and extract:
- Domain vocabulary (e.g., "tenant" vs "organization", "order" vs "purchase")
- Env var naming patterns (e.g., `APP_*`, `REACT_APP_*`, `ORG_*_VAR`)
- Configuration format (env, yaml, toml, json)
- Existing error response format (e.g., `{"error": "...", "code": NNN}`)
- Existing middleware patterns (e.g., async middleware, decorator, interceptor)

## Probe Categories

### Authentication Abuse (AuthN)
- Missing authentication on protected routes
- Token manipulation (JWT alg none, weak secret, expired but accepted)
- Session fixation, CSRF gaps, session prediction
- Password reset logic flaws
- For authorization flaws → see Authorization Abuse below

### Authorization Abuse (AuthZ)
- IDOR — accessing other users' resources by ID
- BFLA — accessing privileged functions as regular user
- Role escalation via JWT, body, headers, cookies
- Excessive data exposure (sensitive fields in responses)
- Mass assignment (overwriting protected fields)
- See [references/authorization-abuse.md](references/authorization-abuse.md)

### Business Logic
- Workflow bypass (skip steps, reorder)
- Race conditions (TOCTOU between check and action)
- Negative/massive values (discounts, quantities, transfers)
- Idempotency violations (repeat action produces different result)
- Limit/quote bypass (pagination, rate limits, max quantities)

### Input Validation
- Injection: SQL, NoSQL, command, SSTI, LDAP, XPath
- Path traversal (../, encoded variants)
- Prototype pollution (JS)
- Type coercion (string→number edge cases, NaN, Infinity)

### SSRF
- Cloud metadata endpoint access (169.254.169.254, etc.)
- Internal network probing via URL-fetch endpoints
- DNS rebinding, URL parsing tricks, protocol smuggling
- See [references/ssrf.md](references/ssrf.md)

### Insecure Deserialization
- Python: pickle, joblib, dill
- PHP: unserialize with gadget chains
- Java: readObject, XStream, Jackson
- Node.js: node-serialize, eval patterns
- Ruby: YAML.load, Marshal.load
- See [references/insecure-deserialization.md](references/insecure-deserialization.md)

### Secrets Exposure
- Hardcoded API keys, tokens, passwords in source
- .env files and secrets in git history
- Source map leaks exposing internal logic
- Bundle inspection for embedded credentials
- See [references/secrets-exposure.md](references/secrets-exposure.md)

### Resource Exhaustion
- ReDoS (catastrophic regex backtracking)
- Large payloads, zip bombs, deep nesting
- Unbounded pagination, expensive queries
- Connection exhaustion, slow loris
- See [references/resource-exhaustion.md](references/resource-exhaustion.md)

### Config Hardening
- CORS misconfiguration (origin reflection, wildcard with credentials)
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Debug/health endpoints exposed in production
- Rate limiting gaps
- Error message information leakage (stack traces, SQL queries)
- Weak cryptography (MD5 hashing, Math.random(), hardcoded keys)
- IaC / cloud config (public S3, permissive IAM, open security groups)

### Dependency Audit
- Tier 1: Native tools (npm audit, cargo audit, pip-audit, etc.)
- Tier 2: OSV.dev API fallback (cross-ecosystem batch query)
- Tier 3: CISA KEV enrichment (auto-boost severity for actively exploited)
- Tier 4: NVD enrichment only (CVSS/CWE for specific CVE)
- EPSS prioritization (real-world exploitation probability)
- See [references/dependency-audit.md](references/dependency-audit.md)

> **Category vocabulary is canonical.** The exact category names above
> (e.g. "Dependency Audit", "Resource Exhaustion", "Config Hardening") flow
> verbatim into each finding's `category:` frontmatter AND into the
> `threat-model.md` table rows. The grader (G5.7) warns when a finding
> category never appears in the threat model; ad-hoc variants ("Dependency",
> "DoS") trigger it.

## Finding Format

```yaml
---
schema_version: 2               # Schema version for forward compatibility
id: RT-003
title: Missing rate limiting on /api/login
category: Config Hardening
severity: High
cwe: CWE-770
blast_radius: Single credential compromised via brute-force
location: src/routes/auth.ts:12-18
detection_difficulty: Easy
status: Open                    # Open | Fixed | Remediated | Regressed | Accepted | False Positive | Duplicate
confidence: High-verified       # High-verified | High-static | Medium | Low
kev_listed: false
epss_score: null
exploited_in_wild: false
target_version:
  git_sha: a1b2c3d4e5f6...
  dirty: false
skill_version: paladin-probe@v3
evidence:
  captured_at: 2026-07-28T12:34:56Z
  captured_by: probe-wrapper
  request: .red-team/evidence/RT-003/2026-07-28T12-34-56Z-request.http
  response_status: 200
  response_excerpt: "HTTP 200 OK — no rate-limit headers present"
  capture_method: probe-wrapper
standards:
  - framework: OWASP-ASVS
    requirement_id: V3.5.1
  - framework: OWASP-API-2023
    requirement_id: API4
functional_requirements:
  - Login endpoint MUST rate-limit requests per source IP
  - Endpoint MUST return HTTP 429 after exceeding the limit
  - Rate limit MUST reset after a defined cooling period
non_functional_requirements:
  - Rate limit window and threshold MUST be configurable via env vars
  - Response MUST include standard rate-limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After)
  - Rate limiting MUST NOT apply to health-check or monitoring endpoints
decision_points:
  - id: DP-003-1
    question: What is the rate limit threshold per IP?
    type: value
    context: >
      OWASP recommends 5 requests per 15 minutes for login endpoints.
      Project conventions and existing limits should guide the default.
    bounds: [5, 1000] requests per window
  - id: DP-003-2
    question: What is the cooling window duration?
    type: value
    context: >
      Must align with existing timeout conventions in the project.
      Shorter windows are stricter but may frustrate legitimate users.
    bounds: [1 minute, 60 minutes]
  - id: DP-003-3
    question: What HTTP behavior on rate limit exceeded?
    type: choice
    context: >
      Project's existing error responses use JSON error bodies
      (see src/middleware/error-handler.ts).
    options:
      - "429 + Retry-After header + JSON body"
      - "429 + Retry-After header only"
  - id: DP-003-4
    question: Which env vars control the rate limit configuration?
    type: convention
    context: >
      Project uses APP_ prefix for env vars (see .env.example).
      Follow the same convention for naming.
    options:
      - APP_RATE_LIMIT_MAX
      - APP_RATE_LIMIT_WINDOW_MS
acceptance_criteria:
  - 100 parallel POST /api/login from same IP → ≥95 return 429
  - After cooling period expires, next request returns normal status
```

### Frontmatter tiers (token discipline)

Emit frontmatter keys by severity tier — do not copy the full example above
into every finding:

- **Tier 1 (ALWAYS):** `schema_version`, `id`, `title`, `category`, `severity`,
  `cwe`, `location`, `status`, `confidence`, `skill_version`, `standards`,
  `evidence` (when live-probe confirmed), plus the requirements block
  (`functional_requirements` / `non_functional_requirements` /
  `decision_points` / `acceptance_criteria`) when the finding is
  High-verified or High-static.
- **Tier 2 (Open findings only, severity High or Medium):** `blast_radius`,
  `detection_difficulty`, `target_version`.
- **Tier 3 (CVE-bearing findings only, severity High or above):** `kev_listed`, `epss_score`, `exploited_in_wild`.

**Rule:** Do not emit Tier 3 keys for Low/Medium findings without a CVE. Do not
emit Tier 2 keys for `False Positive` or `Duplicate` findings — they are `N/A`
severity, so those keys are meaningless. The grader's G1.1 required-key set is
exactly the Tier 1 core, so a lean frontmatter can never fail G1.1.

## Requirements Generation

Instead of writing code or regression tests, each finding with confidence
`High-verified` or `High-static` produces structured requirements. `High-verified`
findings appear at the top of each severity group in `remediation-requirements.md`,
followed by `High-static` findings labeled "(Static — pending live verification)".
These are consolidated into `.red-team/remediation-requirements.md` — a spec that
dev skills consume.

### Requirements consolidation

```
.red-team/
├── remediation-requirements.md    # All findings as requirements
├── suspicious.md                   # Medium-confidence items (manual review)
├── surface.md                      # Attack surface
├── threat-model.md                 # STRIDE model
├── evidence/                       # Wrapper-captured artifacts (manifest-hashed)
│   └── RT-NNN/
│       ├── <timestamp>-request.http
│       ├── <timestamp>-response.http
│       ├── <timestamp>-diff.txt                # probe.sh diff (differential oracle)
│       ├── <timestamp>-<kind>.instrumented.md  # probe.sh capture
│       └── SKIPPED.md                          # if the probe was intentionally skipped
├── chains/                         # /probe chain artifacts
│   └── CH-NNN.md
├── findings/                       # Full detail per finding
│   ├── YYYY-MM-DD_rt-NNN.md
│   └── index.md
└── sessions/
    └── YYYY-MM-DD_topic.md
```

> **Date source of truth:** `REPORT.md` is the canonical probe-date artifact.
> `surface.md` and `threat-model.md` MUST NOT carry independent probe-date lines.
> They reference REPORT.md via `**Date:** See [REPORT.md](REPORT.md)`.
> This prevents date drift across reports on re-verification. The grader (G5.4)
> warns if dates diverge across the three files.

### Remediation Requirements Format

```markdown
# Security Remediation Requirements

## RT-003: Missing rate limiting on /api/login
Priority: High
Confidence: High-verified
Evidence: `.red-team/evidence/RT-003/2026-07-28T12-34-56-response.http`

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
```

### REPORT.md Format

`REPORT.md` is the canonical probe-date artifact and the human-facing summary.
The grader (G5.2) validates it against the findings — the format below is REQUIRED:

```markdown
# Paladin Probe Report — <project short name>

**Probe Date:** YYYY-MM-DD
**Target:** <url or "local">
**Skill Version:** paladin-probe@v3
**Method:** <one line: "Read-only + code analysis" | "Live probes + code analysis" | ...> (effort: <standard|deep|exhaustive>)

## Summary

| Severity | Open | Static-Only (Pending Verification) | Fixed |
|----------|------|-----------------------------------|-------|
| Critical | <N>  | <N>                               | <N>   |
| High     | <N>  | <N>                               | <N>   |
| Medium   | <N>  | <N>                               | <N>   |
| Low      | <N>  | <N>                               | <N>   |

### Critical

| ID | Title | CWE | Route |
|----|-------|-----|-------|
| RT-001 | <title> | CWE-NNN | <route or "n/a"> |

### High
... (same row schema)

### Medium
...

### Low
...

## Remediation

See [remediation-requirements.md](remediation-requirements.md) for detailed
functional and non-functional requirements per finding.

## Exports

- [CSV](exports/findings.csv)
- [SARIF](exports/findings.sarif)
- [VEX](exports/vex.json)
```

Rules:

1. **Header block is required** — `Probe Date`, `Target`, `Skill Version`, `Method`
   (one line each). Missing fields trigger a G5.2 WARN.
2. **Summary table is required**, with a `Severity` header row. Column layout is
   auto-detected from the header row (`Open`, `Static-Only...`, `Fixed`) — keep the
   column names recognizable.
3. **Column semantics**: `Open` counts findings with `status: Open` +
   `confidence: High-verified`; `Static-Only` counts `status: Open` +
   `confidence: High-static`; `Fixed` counts `status: Fixed/Remediated`.
   `Duplicate` findings are excluded from all counts. G5.2 FAILs on any count
   divergence.
4. **Per-severity `### <Critical|High|Medium|Low>` sections are required** when
   findings exist at that severity. Each holds a `| ID | Title | CWE | Route |`
   table, one row per Open/Fixed/Remediated finding. FP findings may be listed or
   omitted — not enforced.
5. **Title column MUST exactly match** the finding's frontmatter `title`. G5.2
   FAILs on any divergence.
6. **Coverage**: every Open/Fixed/Remediated finding ID MUST appear in exactly one
   severity table row; unknown IDs in REPORT tables are flagged.

## Cross-Skill Integration (Phase D)

Phase D implements bidirectional traceability between paladin-probe and other
opencode skills. See [references/cross-skill-contract.md](references/cross-skill-contract.md)
for the full contract specification — file paths, ID binding rules, traceability
index format, and re-verification protocol.

### Integration Table

| Skill | Input (paladin-probe reads) | Output (paladin-probe writes) | Protocol |
|-------|------------------------------|-------------------------------|----------|
| **tdd** | `.red-team/verification/RT-NNN-passed-*.md` | `.red-team/remediation-requirements.md` | tdd creates tests mapping to RT-AC-IDs. When tests pass, tdd writes verification file. Paladin-probe reads it and re-verifies the finding. |
| **domain-druid** | `.business-logic/rules.yaml` | `.red-team/domain-rule-discoveries.yaml` | Paladin-probe reads business rules as logic-abuse probe targets. New implicit rules discovered during probes are written back for domain-druid to formalize. |
| **observability-driven-development** | `.thoughts/odd/trace-naming.yaml` | `.red-team/span-assertions.yaml` | Paladin-probe checks span naming conventions for sensitive data leakage. Writes assertions ODD can embed in telemetry to prove controls work. |

### Data Flow

```
tdd                            paladin-probe                          domain-druid
 │                                  │                                      │
 │  read                            │                                      │
 │  remediation-requirements.md     │  read business rules                 │
 │  ───────────────────────────>    │  ────────────────────────────────>   │
 │                                  │                                      │
 │  create tests matching RT-NNN    │  write domain rule discoveries       │
 │                                  │  <────────────────────────────────   │
 │  write verification/             │                                      │
 │  RT-NNN-passed.md                │  read verification file              │
 │  ───────────────────────────>    │  ────────────────────────────>        │
 │                                  │                                      │
 │                                  │  re-verify finding                   │
 │                                  │  update status + traceability.json   │
 │                                  │                                      │
 │                                  │  write span-assertions.yaml          │
 │                                  │  ──────────────────────>             │
 │                                               ODD                       │
```

### ID Binding

| Prefix | Owner | Example | Bound To |
|--------|-------|---------|----------|
| `RT-NNN` | paladin-probe | RT-003 | Finding |
| `FR-NNN-N` | paladin-probe | FR-003-1 | Functional requirement |
| `AC-NNN-N` | paladin-probe | AC-003-1 | Acceptance criterion |
| `DP-NNN-N` | paladin-probe | DP-003-1 | Decision point |
| `DR-NNN` | paladin-probe | DR-001 | Domain rule discovery |

tdd test names MUST include the AC-ID they test. Example: `test("RT-003-AC-1: 100 parallel requests → ≥95 return 429")`.

### Status Transitions on Re-Verify

```
Open ──re-verify──► Fixed (all criteria met)
                   Regressed (vulnerability persists)
                   Partial (some criteria met, update requirements)

Fixed ──re-verify──► Fixed (no change)
                    Regressed (fix regressed)

Regressed ──re-verify──► Fixed (fix re-applied)
                        Regressed (still broken, escalate priority)
```

### Fresh-Derive-Then-Diff (anti-anchoring)

On session-wide re-verification (`/probe re-verify` without an RT-id,
`/probe verify-all`), derive findings BEFORE looking at prior conclusions —
otherwise you rationalize the old list instead of auditing it.

1. **Derive blind.** Run RECON → MODEL → PROBE → VERIFY on the current code
   WITHOUT opening prior `findings/`, `REPORT.md`, or `threat-model.md`.
   Allowed: `config.yaml` and `surface.md` (they define scope, not
   conclusions). Mechanically: do not Read the prior artifacts until step 3.
2. **Grade the fresh pass.** Skeptic gate + self-audit loop on the fresh
   findings as if they were the only ones.
3. **Diff against priors.** Re-open the priors and reconcile each side:

   | Disposition | Meaning | Action |
   |-------------|---------|--------|
   | New | fresh finding, no prior | Write under a new RT-id |
   | Confirmed | prior finding re-derived | Keep; record re-verified date |
   | Healed | prior Open NOT re-derived | Investigate the fix; if real → `status: Fixed` |
   | Regressed | prior Fixed re-derived | `status: Regressed`, escalate priority |
   | Escalated | same finding, worse severity/category | Update; record what changed |

4. **Non-re-derivable priors.** A prior finding the fresh pass cannot produce
   (depended on a runtime condition, a rotated credential, a probe consent
   now denied) → flag in the session log for human review. Never silently
   deleted, never silently kept Open.

Rationale: prior-artifact anchoring is the strongest false-negative force in
re-verification — reading "RT-003 was found" stops the search for RT-003's
cause. Derive first, diff second, and the diff is honest.

## Compliance Exports (Phase E)

Three standardized export formats generated from `.red-team/findings/` for external tooling.

### Formats

| Format | File | Schema | Consumption |
|--------|------|--------|-------------|
| CSV | `exports/findings.csv` | Flat table | Spreadsheets, dashboards, Excel |
| SARIF 2.1.0 | `exports/findings.sarif` | OASIS SARIF | GitHub Code Scanning, VS Code, CI gate |
| OpenVEX 0.2.0 | `exports/vex.json` | OpenVEX | SBOM integration, GRC platforms |

### OpenVEX Status Mapping

When generating VEX statements, map from the finding's `status` + `confidence` to
the OpenVEX `status` field:

| Finding Status | Finding Confidence | VEX Status |
|---|---|---|
| Open | High-verified | `known_affected` |
| Open | High-static | `under_investigation` |
| Open | Medium | `under_investigation` |
| False Positive | any | `not_affected` |
| Fixed / Remediated | any | `fixed` |
| Accepted | any | `not_affected` |
| Regressed | any | `known_affected` |

**Rule:** All Open VEX statuses other than `known_affected` (i.e. `under_investigation`)
MUST carry a `justification` field explaining why the finding isn't yet confirmed
affected. `not_affected` MUST carry a `justification` from the OpenVEX v0.2
vocabulary.

### VEX `cve` vs `aliases` Rule

The `vulnerability.cve` field is reserved for CVE identifiers only. CWE identifiers
MUST appear in `vulnerability.aliases` prefixed with `CWE:` — e.g. `"CWE:CWE-770"`.
The grader (G3.4) rejects any VEX file where `cve` contains a CWE id.

### Generation

Exports are regenerated automatically by the agent **every time a finding is
added, modified, or removed** — not just on explicit `/probe export`. Each finding
in `.red-team/findings/` is parsed and mapped to all three formats:

- **CSV** — one row per finding with id, title, category, severity, CWE, status, confidence, location
- **SARIF** — one `rule` per CWE + one `result` per finding; levels: error (High), warning (Medium), note (Low), none (FP)
- **OpenVEX** — one `statement` per finding; status: `fixed`, `under_investigation`, `not_affected`

### Regeneration

Run `/probe export` to regenerate all three formats after any finding change.

### Grader invocation protocol

The grader is an execution tool, NOT reading material. Follow these rules to
avoid burning context on implementation detail:

1. **Never read `tests/grader.py` source.** Its internals change with every fix
   cycle and are irrelevant to fixing artifacts.
2. **Invoke via Bash only**, never by reading the file:

   ```bash
   python3 tests/grader.py <path-to-.red-team/> --verbose   # include PASS lines
   ```

3. **Parse only `FAIL` and `WARN` lines** from the output (e.g. `FAIL G5.2`,
   `WARN G5.1`). Each names a check ID — route that ID to
   `references/grader-fixes.md` (see its Usage note) and read only the matching
   section. Ignore `PASS` lines after the first full pass.
4. **Same rule for `scripts/probe.sh`** — execute it via Bash, never read its
   source. Its one-line stdout and exit codes are the whole contract.

## Self-Audit Loop (Grade → Fix → Re-Grade)

After every `/probe pentest` or `/probe re-verify` session, the agent MUST run
the self-audit grader to validate structural integrity before declaring the
session complete.

### Loop

```
1. RUN grader.py <target>            # Grade all G1–G5 checks (see protocol above)
2. ROUTE each FAIL/WARN ID          # Read only matching grader-fixes.md sections
3. APPLY fixes                       # Fix each issue deterministically
4. RE-RUN grader.py <target>         # Verify fix
5. REPEAT steps 2–4 until all PASS and all WARN resolved   # Max 3 iterations
6. If any FAIL remains after 3 iters → warn user, do not block
   WARNs are auto-fix candidates — resolve them at the same priority as FAILs
```

### When to run

- After writing the last finding in a `/probe pentest` session
- After any re-verification that changes finding status
- Manually: `python3 tests/grader.py <path-to-.red-team/>`

### Grading scope

| Group | What it checks |
|-------|---------------|
| G1 | Finding frontmatter integrity (required keys, schema_version, FP/Duplicate severity, confidence/evidence consistency, duplicate detection WARN, canonical category vocabulary WARN, skeptic-review completeness WARN) |
| G2 | Cross-artifact consistency (index/report/ID alignment, traceability.json completeness & schema version, AC/DP arrays match remediation, heading casing) |
| G3 | Export closure (CSV/SARIF/VEX row counts, VEX status mapping, VEX cve vs aliases rule, export freshness vs findings) |
| G4 | Evidence cleanliness (High-verified evidence = `.http` pair or instrumented capture, non-empty evidence dirs, X-Paladin-Probe header presence, manifest.sha256 integrity WARN) |
| G5 | Surface hygiene (threat-model coverage + semantic row context, REPORT.md count/title reconciliation, config.yaml schema fields, probe-date consistency, surface.md content, threat-model category coverage, attack-chain integrity WARN) |

### Fix-routine reference

All fix procedures are documented in `references/grader-fixes.md`. The agent MUST
consult this file before modifying any artifact — do not guess the fix.

## OWASP Standards Alignment (Phase F)

The skill maps all findings to OWASP standards for compliance traceability. The
`standards:` field in each finding uses a closed vocabulary with per-framework
regex validation (see `references/findings-format.md`).

### Standards Used

| Framework | Purpose | ID Format |
|-----------|---------|-----------|
| `OWASP-Top-2025` | OWASP Top 10 2025 risk categories | `A01`–`A10` |
| `OWASP-WSTG` | Web Security Testing Guide sections | `WSTG-4.N.N` |
| `OWASP-ASVS` | Application Security Verification Standard | `V.N.N.N` |
| `OWASP-API-2023` | API Security Top 10 | `API1`–`API10` |
| `CWE` | Common Weakness Enumeration | `CWE-NNN` |

### Selection Rules

Max 5 rows per finding. Priority: CWE → OWASP-Top-2025 → OWASP-WSTG →
OWASP-ASVS → OWASP-API-2023. See `references/owasp-coverage-matrix.md` for the
canonical per-category crosswalk.

### Per-Category Set

**Stack profile (write once, early):** after the initial repo/scope scan
identifies the target stack, the agent MUST record it in `.red-team/config.yaml`
under the optional key `stack_profile:` — it is informational only (the grader
G5.3 validates just `schema_version` / `skill_version`), and it drives the
reference-loading decisions below:

```yaml
stack_profile:
  languages: [Go]
  frameworks: [chi, PostgreSQL]
  components: [K8s, S3, GitHub Actions]
```

**Loading discipline (MUST):**

- MUST read `references/owasp-coverage-matrix.md` and `references/findings-format.md`
  before writing the first finding.
- MUST read `references/cross-skill-contract.md` before Phase D integration.
- MUST read `references/secrets-exposure.md` in every session (git history scan
  is cheap and high-signal).
- MUST read ONLY the reference matching the category currently being probed.
- MUST NOT pre-load references for categories outside the detected stack/scope.
- MUST NOT read the same reference twice in one session; re-read only if the
  probe surface changes.
- **Exception (the only one):** during `/probe chain` pursuit, load ANY
  reference a live hypothesis enters — log every off-discipline load in
  `sessions/<date>_chain.md` (see [references/attack-chains.md](references/attack-chains.md)).

| Reference | Load status | Load when |
|------|-------------|-----------|
| `references/owasp-coverage-matrix.md` | ALWAYS | Before writing the first finding (canonical CWE/OWASP crosswalk) |
| `references/findings-format.md` | ALWAYS | Before writing findings + requirements |
| `references/cross-skill-contract.md` | ALWAYS | Phase D integration — traceability, re-verify protocol, file contracts |
| `references/secrets-exposure.md` | ALWAYS | Every session — scanning for secrets in code/git/bundles |
| `references/grader-fixes.md` | ROUTED | Only the sections matching FAIL/WARN check IDs (see its Usage note) |
| `references/skeptic-review.md` | CONDITIONAL | Once, before writing the first High-verified/High-static finding — skeptic prompt template + verdict protocol |
| `references/attack-chains.md` | CONDITIONAL | `/probe chain` sessions — tree-driven multi-stage exploitation, heuristics catalog, CH-NNN artifact |
| `references/attack-surface-mapping.md` | CONDITIONAL | Only if the surface is unknown after repo scan (RECON start) |
| `references/threat-modeling.md` | CONDITIONAL | Only if STRIDE modeling for this target is non-obvious |
| `references/xxe.md` | CONDITIONAL | Only when probing XML — classic, blind, XInclude, SVG/DOCX/SAML, SSRF, DoS |
| `references/auth-abuse.md` | CONDITIONAL | Only when probing authentication (AuthN) |
| `references/authorization-abuse.md` | CONDITIONAL | Only when probing authorization (AuthZ, IDOR, BFLA) |
| `references/business-logic-abuse.md` | CONDITIONAL | Only when probing business logic |
| `references/ci-cd.md` | CONDITIONAL | Only when CI/CD pipeline is in scope — injection, secret exposure, artifact poisoning, RBAC |
| `references/client-side.md` | CONDITIONAL | Only when probing DOM, CSP, postMessage, client storage |
| `references/cloud-native.md` | CONDITIONAL | Only when K8s/cloud infra in scope — RBAC, pod escape, sidecar bypass, metadata abuse |
| `references/http-attacks.md` | CONDITIONAL | Only when probing smuggling, cache poisoning, open redirect |
| `references/federated-auth.md` | CONDITIONAL | Only when SAML, OAuth2, OIDC, Supabase Auth in scope |
| `references/graphql.md` | CONDITIONAL | Only when a GraphQL endpoint is identified — introspection, injection, batching, DoS, CSRF |
| `references/input-validation.md` | CONDITIONAL | Only when probing input boundaries beyond standard fuzzing |
| `references/llm-ai.md` | CONDITIONAL | Only when LLM/AI features in scope — prompt injection, jailbreaking, RAG poisoning, tool abuse, extraction |
| `references/ssrf.md` | CONDITIONAL | Only when probing server-side request forgery |
| `references/insecure-deserialization.md` | CONDITIONAL | Only when deserialization vectors are identified |
| `references/session-mgmt.md` | CONDITIONAL | Only when testing session management — cookie flags, fixation, hijacking, JWT, logout, timeout |
| `references/resource-exhaustion.md` | CONDITIONAL | Only when testing DoS, ReDoS, pagination abuse |
| `references/config-hardening.md` | CONDITIONAL | Only when auditing config, crypto, IaC/cloud |
| `references/crypto.md` | CONDITIONAL | Only when testing cryptographic failures — TLS, weak algos, padding oracle, JWT confusion, RNG |
| `references/dependency-audit.md` | CONDITIONAL | Only when scanning deps with tiered approach |
| `references/error-handling.md` | CONDITIONAL | Only when probing error handling — stack traces, verbose errors, sentinel oracles; do NOT pre-load |
| `references/identity-mgmt.md` | CONDITIONAL | Only when testing identity management — enumeration, registration abuse, deprovisioning |
| `references/logging-alerting.md` | CONDITIONAL | Only when testing logging/alerting — audit gaps, log injection, tampering, leakage |

Payloads at `payloads/`:
- `injection-payloads.txt` — injection + SSRF payloads
- `business-logic-scenarios.md` — domain-specific abuse + resource exhaustion scenarios
- `fuzz-cases.json` — boundary + type confusion inputs
