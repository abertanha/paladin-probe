---
name: paladin-probe
description: "Paladin-Probe is an experimental red-team skill for adversarial application-security testing. Use /probe pentest to run a full scan (recon, STRIDE threat model, per-category probe, requirements report), /probe quick for a single-path scan, and /probe model, /probe report, /probe re-verify, /probe verify-all, /probe chain, or /probe export for focused work. Probes business-logic abuse, authentication and authorization bypass, input validation, SSRF, deserialization, secrets exposure, resource exhaustion, config hardening, and dependency audit. Auto-suggests on PRs touching auth, sessions, dependencies, secrets, or CORS. Writes security requirements; does not write code or tests."
allowed-tools: Read, Bash, Grep, Glob, Write, Edit, Task
---

# Paladin Probe — Experimental Red-Team Skill

Adversarial application-security testing — "how can I break this?", not
"does this work?". Output: security requirements for dev skills. Never
writes code or tests.

## Trigger Modes

| Trigger | Mode | Behavior |
|---------|------|----------|
| `/probe pentest` | Pentest | Full scan: surface → probe every category → report |
| `/probe quick <path>` | Pentest | Single path: deps + config + input flaws |
| `/probe model` | Either | STRIDE threat model only |
| `/probe report` | Either | Consolidate findings into requirements |
| `/probe re-verify` | Either | Re-probe Fixed/Regressed findings against current code |
| `/probe verify-all` | Either | Re-derive all findings, diff against priors |
| `/probe chain [asset]` | Chain | Multi-stage chains (≥2 findings in ≥2 categories) |
| `/probe export` | Either | Regenerate CSV/SARIF/VEX from current findings |

Auto-suggest: PR touching auth, deps, security config → suggest `/probe quick`.

## Workflow

```
RECON (routes/deps/configs/schemas) → MODEL (STRIDE per endpoint) → PROBE
(auth/logic/input/config/deps) → VERIFY (trace, controls, confidence) →
CONTEXT (docs, conventions) → REPORT (findings/ + requirements.md)
```

**Done-when.** A stage is complete only when its gate is structurally met:
- **RECON:** `surface.md` lists every endpoint, each with a STRIDE row in `threat-model.md`.
- **MODEL:** every `surface.md` entry → exactly one `threat-model.md` row (STRIDE per element) with a risk score.
- **CATEGORY:** every hypothesis classified and archived (finding, `suspicious.md`, or silent discard); no speculative bullet survives.

Effort scales hypotheses/chain depth via `config.yaml: effort` — see "Effort knob".

## Onboarding (first activation)

Ask environment, skip-list (`skip_routes`), intensity, effort; auto-detect stack
(package manager, web framework, auth). Consent checklist — live requests
(required for High-verified), destructive tests, routes, OOB callbacks,
instrumented reads (`log_access`/`db_read_access`/`test_suite_oracle`; absent =
denied), abort-on-5xx. Live requests denied → **High-static** ceiling. Save
`.red-team/config.yaml`; if no project docs found, ask once per session for
convention sources. Before the first live request, show `scripts/probe.sh check`
output + probe count; confirm or abort.

## Verification Protocol

Before any finding: read the full handler, trace compensating controls
(middleware, DB constraints, state machine, tests), then classify.

| Confidence | Criteria | Action |
|------------|----------|--------|
| High-verified | Code confirms + live-probe evidence | Finding + requirements; "Open" |
| High-static | Code confirms, no control, no live evidence | Finding + requirements; "Static-Only" |
| Medium | Partial guard / ambiguous | `suspicious.md` — no finding |
| Low | Likely handled | Discard silently |

**Ceiling:** static-only caps at **High-static**; only live probes reach High-verified; **Critical requires High-verified**; handler unread → Low. **Skeptic gate:** every High finding must survive a fresh-context hostile subagent — [references/skeptic-review.md](references/skeptic-review.md).

## Flat Config Schema

All `.red-team/config.yaml` MUST include `schema_version: 2` + `skill_version: paladin-probe@v3` (G5.3); version floats with `VERSION` (single source). G5.9 FAILs on drift incl. `chains/*.md` / `exports/vex.json`.

### Effort knob

Optional key (absent = `standard`): `effort: deep`.

| Dimension | standard | deep | exhaustive |
|-----------|----------|------|------------|
| Hypotheses per endpoint | 3 | 6 | 10 |
| Chain depth | 2 | 4 | 6 |
| Revisit policy | none | re-probe High-static after grader loop | + re-scan Fixed findings |
| Reference loading | adjacent only | any a live hypothesis enters (log each) | any, + re-read on surface change |
| Skeptic pass | per finding | per finding | per finding, re-run on conflicts |

`scripts/probe.sh check` is the **official config-get** — query it, never read `config.yaml` by hand. `python3 tests/grader.py state <root> [--json]` is a read-only snapshot (counts, findings, chains, manifests, aborted hosts, last probe date; derived from disk, never writes).

## Live Probe Protocol

Live probes run through `scripts/probe.sh` — it mechanically enforces consent
gates, traceability, throttling, and evidence capture. **Execute it via Bash
like the grader; never read it.** Never hand-roll `curl` bypassing it.

### The wrapper enforces

- Consent gates: `consent.live_requests` false (exit 2), URL in `skip_routes`
  (exit 3), mutating verb without `consent.destructive_tests` (exit 4); no flag
  overrides.
- Traceability: non-overridable `X-Paladin-Probe` + `User-Agent:
  paladin-probe/<version>`; idempotency key on mutating verbs.
- Throttle: per-host gap from `throttle_seconds` (default 1s); 429 backoff
  2/4/8s ×3 then abort endpoint (exit 5).
- Circuit breaker: >30% 5xx over ≥4 req/60s → abort session, write
  `sessions/<date>_abort.md`, refuse host 10 min (exit 7).
- Evidence: `evidence/<RT-NNN>/<ts>-{request,response}.http`, hashed into
  `manifest.sha256`.

Exit codes: 0 ok · 2/3/4 consent · 5 429 · 6 transport · 7 breaker · 8 usage ·
9 evidence-write · 10 manifest drift. Full options: `probe.sh --help`.

### The agent does

```bash
scripts/probe.sh check
scripts/probe.sh send --rt RT-003 --method GET --url U
scripts/probe.sh diff --rt RT-003 --method GET --url 'https://t/api/{{page}}' \
  --var page=admin --var-base page=profile
scripts/probe.sh capture --rt RT-003 --kind serverlog -- 'tail -n 200 /var/log/app/api.log'
scripts/probe.sh verify
scripts/probe.sh checkpoint --write --phase probe:authz --summary "..." --next "..."
```

- **diff** = differential oracle (`--var-base` baseline, `--var` follow-up,
  headers normalized) → `<ts>-diff.txt`; a `delta=identical` where you expected
  divergence is a **negative result** — record it.
- **capture** = instrumented evidence; kind-gated (absent = denied) ·
  qualifies for **High-verified**.
- **Before trusting prior evidence**, run `verify` (exit 10 = tampering).
- **SKIPPED.md rule:** an intentionally-unprobed category MUST carry
  `evidence/RT-NNN/SKIPPED.md` (G4.2 flags empty dirs).
- Before mutating requests, check cleanup templates in the category reference.

### Post-probe

Update `evidence:`; promote High-static → High-verified (confirmed) or close FP (control demonstrated); regenerate REPORT.md and exports **only if** a finding's `status`/`confidence` changed.

## Probe Categories

- **Authentication Abuse (AuthN)** — missing auth, JWT manipulation, session fixation/CSRF/prediction, reset flaws.
- **Authorization Abuse (AuthZ)** — IDOR, BFLA, escalation, mass assignment, excessive exposure · [ref](references/authorization-abuse.md).
- **Business Logic** — workflow bypass, TOCTOU races, negative/massive values, idempotency, quota bypass.
- **Input Validation** — SQL/NoSQL/cmd/SSTI/LDAP/XPath injection, traversal, prototype pollution, coercion.
- **SSRF** — metadata endpoint, internal probing, DNS rebinding, smuggling · [ref](references/ssrf.md).
- **Insecure Deserialization** — pickle/unserialize/readObject/node-serialize/YAML.load chains · [ref](references/insecure-deserialization.md).
- **Secrets Exposure** — hardcoded keys, .env/git history, source maps, bundles · [ref](references/secrets-exposure.md).
- **Resource Exhaustion** — ReDoS, zip bombs, unbounded pagination, slow loris · [ref](references/resource-exhaustion.md).
- **Config Hardening** — CORS, missing headers, debug endpoints, rate limits, leakage, weak crypto, IaC/cloud · [ref](references/config-hardening.md).
- **Dependency Audit** — native audit, OSV.dev, KEV, EPSS · [ref](references/dependency-audit.md).

> **Vocabulary is canonical:** these names flow verbatim into `category:` and
> `threat-model.md` rows; G5.7 warns on ad-hoc variants and missing categories.

## Finding Format, Requirements & Exports

All artifact formats — finding schema, frontmatter tiers, evidence rules,
requirements consolidation, REPORT.md format, OpenVEX mapping + `cve`-vs-
`aliases` rule, CSV/SARIF/VEX generation — live in
[references/findings-format.md](references/findings-format.md). **Do not redefine
them here.** Date source of truth = REPORT.md; surface/threat-model link via
`**Date:** See <REPORT.md>` (G5.4).

## Cross-Skill Integration (Phase D)

Traceability with tdd, domain-druid, and ODD lives in
[references/cross-skill-contract.md](references/cross-skill-contract.md) — file
paths, ID binding, status transitions, the fresh-derive protocol. Consult
before Phase D integration.

## Grader Invocation Protocol

The grader is an execution tool, NOT reading material.

1. **Never read `tests/grader.py` source** — irrelevant to fixing artifacts.
2. **Invoke via Bash only:** `python3 tests/grader.py <path-to-.red-team/> [--verbose]`.
3. **Parse only `FAIL`/`WARN` lines** (e.g. `FAIL G5.2`); route each check ID to
   the section in `references/grader-fixes.md`; ignore `PASS` after the first pass.
4. **Same rule for `scripts/probe.sh`** — one-line stdout + exit codes.

## Self-Audit Loop (Grade → Fix → Re-Grade)

After every `/probe pentest` or `/probe re-verify` session: run the grader, route
each FAIL/WARN to `references/grader-fixes.md`, fix, re-grade until all
PASS/WARNs resolved (max 3 iterations); a remaining FAIL after 3 → warn the
user, do not block. Groups: G1 finding integrity · G2 cross-artifact · G3 export
closure · G4 evidence cleanliness · G5 surface hygiene. Never guess a fix.

## Session Handoff, Resume & Context Budget

At each phase boundary, write a **checkpoint** (mechanical snapshot + narrative handoff) so a fresh session resumes without re-reading the tree:

```bash
scripts/probe.sh checkpoint --write --phase recon --summary "..." \
  --next "..." --decided-open DP-001 --context-pct 40
scripts/probe.sh checkpoint --read
```

One file per boundary (`sessions/<date>_checkpoint-<phase>.md`); rewriting a
phase leaves others intact. Counts from disk, not memory; `session_id` reuses
the latest checkpoint's id unless `--session-id` is given — a new id re-copies
`consent_snapshot` from `config.yaml`, the same id keeps it frozen.

### Resume gate (anti-anchoring)

On resume, read **only** `config.yaml`, `surface.md`, and session checkpoints —
scope, not conclusions. Do NOT open `findings/`, `REPORT.md`, `threat-model.md`
before the first target. Run mechanically (both must exit 0):

```bash
scripts/probe.sh verify           # manifests intact (exit 10 = tampering)
python3 tests/grader.py state <root>
```

Then continue from `next_planned_steps`. **Never re-derive by default on
resume** — `/probe verify-all` is the only deliberate re-derivation.

### Abort recovery

A circuit-breaker abort leaves `sessions/<date>_abort.md` and a
`.probe-state/<host>.aborted` marker. Resume reads the abort record, lists
aborted hosts via `scripts/probe.sh check` (`aborted_hosts=`) or `state --json`,
and plans around them — **never resend to a host with an active breaker marker.**

### Context budget

Spend ≤ ~15% of the orchestrator's context on RECON/MODEL/planning. For
`deep`/`exhaustive`, run PROBE in a **fresh subagent per category**: give it
only `surface.md`, `threat-model.md`, and Loading Discipline; it returns
classified findings (+ evidence paths). Subagents are a documented contract.

## OWASP Standards Alignment (Phase F)

Closed `standards:` vocabulary, regexes, 5-row cap, and selection priority live
in `references/findings-format.md`; the canonical per-category crosswalk and the
informational `stack_profile:` key live in `references/owasp-coverage-matrix.md`.
Use both before the first finding.

### Loading Discipline (disclosure map)

- MUST read `references/owasp-coverage-matrix.md` + `references/findings-format.md`
  before the first finding; `references/cross-skill-contract.md` before Phase D.
- MUST read `references/secrets-exposure.md` in every session (cheap, high-signal).
- MUST read ONLY the reference matching the category being probed; MUST NOT
  pre-load outside the detected stack/scope, nor re-read one twice in a session.
- **Exception (the only one):** during `/probe chain` load ANY reference a live
  hypothesis enters — log every off-discipline load in `sessions/<date>_chain.md`.

| Reference | Load status | Load when |
|------|-------------|-----------|
| `references/owasp-coverage-matrix.md` | ALWAYS | Before the first finding (CWE/OWASP crosswalk) |
| `references/findings-format.md` | ALWAYS | Before writing findings + requirements |
| `references/cross-skill-contract.md` | ALWAYS | Phase D integration — traceability, re-verify protocol |
| `references/secrets-exposure.md` | ALWAYS | Every session — secrets in code/git/bundles |
| `references/grader-fixes.md` | ROUTED | Only sections matching FAIL/WARN check IDs |
| `references/skeptic-review.md` | CONDITIONAL | Once, before the first High-verified/High-static finding |
| `references/attack-chains.md` | CONDITIONAL | `/probe chain` sessions — CH-NNN artifact |
| `references/attack-surface-mapping.md` | CONDITIONAL | Only if surface unknown after repo scan (RECON) |
| `references/threat-modeling.md` | CONDITIONAL | Only if STRIDE modeling is non-obvious |
| `references/xxe.md` | CONDITIONAL | Only when probing XML — blind, XInclude, SVG/DOCX/SAML |
| `references/auth-abuse.md` | CONDITIONAL | Only when probing authentication (AuthN) |
| `references/authorization-abuse.md` | CONDITIONAL | Only when probing authorization (AuthZ, IDOR, BFLA) |
| `references/business-logic-abuse.md` | CONDITIONAL | Only when probing business logic |
| `references/ci-cd.md` | CONDITIONAL | Only when CI/CD pipeline in scope |
| `references/client-side.md` | CONDITIONAL | Only when probing DOM, CSP, postMessage, storage |
| `references/cloud-native.md` | CONDITIONAL | Only when K8s/cloud infra in scope |
| `references/http-attacks.md` | CONDITIONAL | Only when probing smuggling, poisoning, redirect |
| `references/federated-auth.md` | CONDITIONAL | Only when SAML, OAuth2, OIDC, Supabase Auth in scope |
| `references/graphql.md` | CONDITIONAL | Only when a GraphQL endpoint is identified |
| `references/input-validation.md` | CONDITIONAL | Only when probing input boundaries beyond fuzzing |
| `references/llm-ai.md` | CONDITIONAL | Only when LLM/AI features in scope |
| `references/ssrf.md` | CONDITIONAL | Only when probing server-side request forgery |
| `references/insecure-deserialization.md` | CONDITIONAL | Only when deserialization vectors identified |
| `references/session-mgmt.md` | CONDITIONAL | Only when testing session management |
| `references/resource-exhaustion.md` | CONDITIONAL | Only when testing DoS, ReDoS, pagination abuse |
| `references/config-hardening.md` | CONDITIONAL | Only when auditing config, crypto, IaC/cloud |
| `references/crypto.md` | CONDITIONAL | Only when testing cryptographic failures |
| `references/dependency-audit.md` | CONDITIONAL | Only when scanning deps with the tiered approach |
| `references/error-handling.md` | CONDITIONAL | Only when probing error handling — do NOT pre-load |
| `references/identity-mgmt.md` | CONDITIONAL | Only when testing identity management |
| `references/logging-alerting.md` | CONDITIONAL | Only when testing logging/alerting |

Payloads: `payloads/injection-payloads.txt`, `payloads/business-logic-scenarios.md`,
`payloads/fuzz-cases.json`.