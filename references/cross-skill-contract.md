# Cross-Skill Integration Contract

**Purpose:** Defines the data exchange contracts, file protocols, and bidirectional traceability between paladin-probe and other opencode skills.

**Schema version:** 2  
**Skill version:** paladin-probe@v3

---

## Table of Contents

1. [Contract Overview](#1-contract-overview)
2. [Output Contracts (Paladin-Probe → Others)](#2-output-contracts-paladin-probe--others)
3. [Input Contracts (Others → Paladin-Probe)](#3-input-contracts-others--paladin-probe)
4. [Bidirectional Traceability](#4-bidirectional-traceability)
5. [Re-Verification Protocol](#5-re-verification-protocol)
6. [File Path Map](#6-file-path-map)
7. [YAML Fingerprint Tables](#7-yaml-fingerprint-tables)

---

## 1. Contract Overview

| Direction | Source Skill | Target Skill | Data |
|-----------|-------------|--------------|------|
| Output | paladin-probe | tdd | Remediation requirements with RT-NNN IDs, acceptance criteria, decision points |
| Output | paladin-probe | domain-druid | New domain rules discovered via logic-abuse probes |
| Output | paladin-probe | ODD | Security span assertions for telemetry |
| Input | paladin-probe | domain-druid | Business logic rules (probe targets) |
| Input | paladin-probe | tdd | Test-passed signals (re-verify trigger) |
| Input | paladin-probe | ODD | Span attribute conventions (leakage check) |

### Live Protocol Diagram

```
tdd                     paladin-probe               domain-druid
 │                          │                           │
 │  read                    │                           │
 │  remediation-            │                           │
 │  requirements.md         │                           │
 │  ───────────────>        │                           │
 │                          │                           │
 │  create tests            │                           │
 │  matching RT-NNN         │  read business rules      │
 │                          │  ─────────────────────>   │
 │                          │                           │
 │  write                   │  write domain rules       │
 │  verification/           │  <─────────────────────   │
 │  RT-NNN-passed.md        │                           │
 │  ───────────────>        │                           │
 │                          │                           │
 │                          │  re-verify finding        │
 │                          │  (on test pass signal)    │
 │                          │                           │
 │                          │  update RT-NNN status     │
 │                          │  or promote confidence    │
```

---

## 2. Output Contracts (Paladin-Probe → Others)

### 2.1 Remediation Requirements (→ tdd)

File: `.red-team/remediation-requirements.md`

Each finding produces a section with:

```markdown
## RT-NNN: Title
Confidence: High-verified | High-static
Priority: Critical | High | Medium | Low

### Functional Requirements
- FR-NNN-{N}: MUST/MUST NOT statement

### Non-Functional Requirements
- NFR-NNN-{N}: SHOULD/SHOULD NOT statement

### Acceptance Criteria
- AC-NNN-{N}: Testable outcome description

### Decision Points
- DP-NNN-{N}: Open question for implementer with bounds/options
```

**Consumption by tdd:** tdd reads this file and creates one or more test cases per acceptance criterion. Test names MUST include the RT-NNN ID:

```
test("RT-003-AC-1: 100 parallel requests → ≥95 return 429")
test("RT-003-AC-2: After cooling period → request succeeds")
```

### 2.2 Domain Rule Discoveries (→ domain-druid)

File: `.red-team/domain-rule-discoveries.yaml`

When a logic-abuse probe finds behavior that feels like an implicit domain rule:

```yaml
discovered_rules:
  - id: DR-001
    source_finding: RT-004
    description: "Discount cannot exceed 50% of base price"
    evidence: "PATCH /api/orders/1 with discount=0.6 → accepted → total reduced by 60%"
    suggested_location: ".business-logic/rules.yaml"
    rule_type: validation
```

**Consumption by domain-druid:** domain-druid reads this file and proposes formalizing the rule into `.business-logic/rules.yaml`.

### 2.3 Security Span Assertions (→ ODD)

File: `.red-team/span-assertions.yaml`

For findings where telemetry should prove the control is working:

```yaml
span_assertions:
  - finding: RT-003
    span_name: "POST /api/login"
    assertions:
      - attribute: "http.status_code"
        condition: "eq 429"
        context: "rate limit exceeded"
      - attribute: "rate_limit.remaining"
        condition: "eq 0"
        context: "rate limit hit"
  - finding: RT-001
    span_name: "POST /api/login"
    assertions:
      - attribute: "auth.success"
        condition: "eq false"
        context: "invalid credentials"
      - attribute: "auth.attempts"
        condition: "increment"
        context: "brute force tracking"
```

**Consumption by ODD:** ODD reads this file and adds telemetry assertions to existing spans.

---

## 3. Input Contracts (Others → Paladin-Probe)

### 3.1 Business Logic Rules (domain-druid → paladin-probe)

File: `.business-logic/rules.yaml`

Paladin-probe reads this before logic-abuse probes:

```yaml
rules:
  - id: BL-001
    description: "Order total cannot be negative"
    type: validation
    target: api/orders/:id
  - id: BL-002
    description: "Users cannot delete their own admin role"
    type: authorization
    target: api/users/:id/role
```

**Expectation:** Paladin-probe uses these to target logic-abuse probes (attempt to violate each rule).

### 3.2 Test Passed Signals (tdd → paladin-probe)

Directory: `.red-team/verification/`

When tdd completes a test that matches a finding's AC, it writes:

File: `.red-team/verification/RT-NNN-passed-{timestamp}.md`

```yaml
---
skill_version: tdd@v1
finding_id: RT-003
acceptance_criteria:
  - AC-003-1: passed
  - AC-003-2: passed
passed_at: 2026-07-28T12:34:56Z
branch: fix-rt-003-rate-limit
---
```

**Expectation:** Paladin-probe scans this directory. When a new passed file appears:
1. Read the corresponding finding
2. If status is `Open` → run re-verification protocol
3. If finding is confirmed fixed → update status to `Fixed`, adjust remediation-requirements.md

### 3.3 Span Naming Conventions (ODD → paladin-probe)

File: `.thoughts/odd/trace-naming.yaml`

```yaml
span_conventions:
  operation: "{http.method} {route}"
  attributes:
    - "http.status_code"
    - "error.code"
    - "auth.role"
```

**Expectation:** Paladin-probe uses these conventions when testing for sensitive data in span attributes.

---

## 4. Bidirectional Traceability

### 4.1 ID Binding Rules

| Skill | ID Prefix | Example | Bound To |
|-------|-----------|---------|----------|
| paladin-probe | `RT-NNN` | RT-003 | Finding |
| paladin-probe | `FR-NNN-N` | FR-003-1 | Functional requirement |
| paladin-probe | `NFR-NNN-N` | NFR-003-2 | Non-functional requirement |
| paladin-probe | `AC-NNN-N` | AC-003-1 | Acceptance criterion |
| paladin-probe | `DP-NNN-N` | DP-003-1 | Decision point |
| paladin-probe | `DR-NNN` | DR-001 | Domain rule discovery |
| tdd | any test name | `RT-003-AC-1` | Acceptance criterion |
| domain-druid | `BL-NNN` | BL-001 | Business logic rule |

### 4.2 Traceability Index

File: `.red-team/traceability.json`

**Generation source:** The traceability index MUST be regenerated from the actual
finding files in `.red-team/findings/` every time a finding is added, removed, or
changed — NOT maintained manually. The agent reads each finding's frontmatter `id`,
`title`, `status`, and `standards`, then reconciles FR/AC/DP IDs from
`remediation-requirements.md` sections. This guarantees the index is always in
sync with the findings on disk. The grader (G2.2) validates this automatically.

```json
{
  "schema_version": 2,
  "findings": {
    "RT-003": {
      "title": "Missing rate limiting on /api/login",
      "requirements": ["FR-003-1", "FR-003-2", "NFR-003-1"],
      "acceptance_criteria": ["AC-003-1", "AC-003-2"],
      "decision_points": ["DP-003-1", "DP-003-2", "DP-003-3", "DP-003-4"],
      "domain_rules": [],
      "tests": {
        "passed": ["tdd@2026-07-28T12-34-56"],
        "failed": []
      },
      "status": "Open"
    }
  },
  "last_updated": "2026-07-28T12:00:00Z"
}
```

### 4.3 Naming Conventions

- Test files: `RT-NNN-passed-{timestamp}.md` or `RT-NNN-failed-{timestamp}.md`
- Test descriptions: `"RT-NNN-AC-N: description"` — must match AC-ID
- Branch names: `fix-rt-NNN-short-description` (convention, not enforced)

---

## 5. Re-Verification Protocol

### Trigger

Re-verification starts when:
1. New file appears in `.red-team/verification/RT-NNN-passed-*.md`
2. User explicitly runs `/probe re-verify RT-NNN`
3. User runs `/probe verify-all` (all Open findings)

### Pipeline

```
TRIGGER
   │
   ▼
0. (Session-wide triggers only — /probe re-verify without an RT-id,
   /probe verify-all) Derive findings fresh BEFORE reading prior artifacts:
   run RECON → MODEL → PROBE → VERIFY blind, grade the fresh pass, THEN
   diff against priors (New/Confirmed/Healed/Regressed/Escalated). See
   SKILL.md "Fresh-Derive-Then-Diff". Targeted RT-NNN triggers skip this
   and start at 1.
   │
   ▼
1. Read finding RT-NNN — get location, requirements, acceptance_criteria
   │
   ▼
2. Read current source code at finding's `location`
   │
   ▼
3. Run targeted probe (static code review)
   - Check if compensating control now exists
   - Check if vulnerability is still present
   │
   ▼
4. If live probe allowed:
   - Run the original probe payload
   - Capture evidence
   - If blocked → confirm fix
   - If still vulnerable → update finding (regressed)
   │
   ▼
5. Update status
   - Fixed → move to `.red-team/findings/archived/RT-NNN.md`
   - Regressed → update status, bump severity if worse
   - Improved (partial fix) → update requirements

   ▼
6. Update traceability.json
   - Add test pass record
   - Update finding status
```

### Status Transitions

```
Open  ──re-verify──►  Fixed
                     Regressed
                     Partial (update requirements)

Fixed  ──re-verify──►  Fixed (no change)
                     Regressed (fix regressed)

Regressed ──re-verify──►  Fixed
                         Regressed (still broken, escalate)
```

### File Protocol

After re-verification, update:

```
.red-team/
├── findings/
│   ├── RT-NNN.md                      # Updated status
│   └── archived/
│       └── RT-NNN-fixed-{timestamp}.md  # If closed
├── verification/
│   ├── RT-NNN-passed-{timestamp}.md    # From tdd
│   └── RT-NNN-reverified-{timestamp}.md # From paladin-probe
├── traceability.json                    # Updated status
└── remediation-requirements.md         # Updated confidence/priority
```

---

## 6. File Path Map

### Paladin-Probe Owns

| Path | Description |
|------|-------------|
| `.red-team/` | Root directory for all artifacts |
| `.red-team/findings/` | Individual finding files |
| `.red-team/findings/index.md` | Finding index |
| `.red-team/findings/archived/` | Fixed / closed findings |
| `.red-team/evidence/RT-NNN/` | Live-probe evidence |
| `.red-team/remediation-requirements.md` | Requirements spec for tdd |
| `.red-team/domain-rule-discoveries.yaml` | New rules for domain-druid |
| `.red-team/span-assertions.yaml` | Span assertions for ODD |
| `.red-team/traceability.json` | Bidirectional trace index |
| `.red-team/suspicious.md` | Medium-confidence items |
| `.red-team/surface.md` | Attack surface map |
| `.red-team/threat-model.md` | STRIDE threat model |
| `.red-team/config.yaml` | Session config/consent |
| `.red-team/sessions/` | Session logs |

### Paladin-Probe Reads

| Path | Source | Purpose |
|------|--------|---------|
| `.business-logic/rules.yaml` | domain-druid | Logic-abuse probe targets |
| `.thoughts/odd/trace-naming.yaml` | ODD | Span naming conventions |
| `.red-team/verification/RT-NNN-*.md` | tdd | Re-verification triggers |
| `.specs/` | Any | Project conventions for requirements |
| `docs/` | Any | Documentation context |

### tdd Owns

| Path | Description |
|------|-------------|
| `.red-team/verification/RT-NNN-{passed,failed}-*.md` | Test results |

### domain-druid Owns

| Path | Description |
|------|-------------|
| `.business-logic/rules.yaml` | Formal business logic rules |
| `.red-team/domain-rule-discoveries.yaml` (reads) | Proposed new rules |

### ODD Owns

| Path | Description |
|------|-------------|
| `.thoughts/odd/trace-naming.yaml` | Span naming conventions |
| `.red-team/span-assertions.yaml` (reads) | Security span assertions |

---

## 7. YAML Fingerprint Tables

```yaml
traceability_file_present:
  probe: 'cat .red-team/traceability.json'
  detection: valid JSON with findings array and status

verification_file_present:
  probe: 'ls .red-team/verification/'
  detection: contains RT-NNN-passed-*.md or RT-NNN-failed-*.md

remediation_requirements_present:
  probe: 'cat .red-team/remediation-requirements.md'
  detection: valid markdown with RT-NNN sections

domain_rules_bound:
  probe: 'cat .business-logic/rules.yaml'
  detection: rules exist and can be mapped to probe targets
  action: >-
    paladin-probe reads rules, probes each for logic abuse,
    writes any violations as findings with BL-ID references

test_name_convention:
  probe: 'grep -r "RT-NNN-AC" tests/'
  detection: test names follow RT-NNN-AC-N naming convention

reverify_trigger:
  probe: 'inotifywait on .red-team/verification/ or file poll'
  detection: new verification file detected
  action: >-
    paladin-probe reads finding, re-runs static analysis,
    optionally runs live probe, updates finding status

bidirectional_id:
  probe: 'grep decision_points .red-team/findings/RT-NNN.md'
  detection: decision_point IDs exist and are echoed in remediation-requirements.md
```
