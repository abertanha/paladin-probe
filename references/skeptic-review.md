# Skeptic Review (Adversarial Pre-Write Gate)

Same-context self-review rationalizes. A fresh-context hostile reviewer with
**no access to your reasoning** either kills the finding or makes it survive
contact. This gate runs before every High-verified / High-static finding is
written, in every mode.

## When

Mandatory after the Verification Pipeline classifies a finding as
`High-verified` or `High-static`, **before** the finding file is written.
Medium/Low findings skip the gate (they are not written as findings).

## Invoking the skeptic

Spawn a subagent (Claude Code: `Task`/Agent tool; opencode: `Task`) with
**fresh context**. The prompt must contain ONLY the claim and the repo root —
never your search history, your reasoning, or the words "I already checked".
Leading the skeptic re-imports your confirmation bias.

### Prompt template (copy verbatim, fill the brackets)

```
You are a hostile security reviewer. Your ONLY job is to REFUTE the claim
below by finding a compensating control that prevents it. You get no context
on how this claim was derived — judge only what the claim says and what the
code shows.

CLAIM
- Title: [title]
- Category: [canonical category]
- CWE: [CWE-NNN]
- Location: [path:line-range]
- Claim: [one paragraph: the vulnerable path, the abuse, and the impact]

Repo root: [absolute path]

Hunt for the killing control, in this order:
1. Validation/sanitization upstream of the location (middleware, filters,
   base handlers, route decorators)
2. Type-system or compile-time enforcement (schema parsing, generics, locked
   dependencies that patch the vector)
3. Data-layer constraints (UNIQUE / CHECK / FK, triggers, migrations)
4. Framework defaults that neutralize the vector (parameterized ORM queries,
   auto-escaping templates, built-in CSRF/session hardening)
5. Infrastructure layer (reverse proxy, WAF rules, network policy, platform
   sandbox)
6. Tests that pin exactly this behavior (a test asserting the "vulnerable"
   behavior is intended is a kill; a test asserting the safe behavior is a kill)

Rules:
- Tools: Read, Grep, Glob only. Do not execute anything, do not send requests.
- Be efficient: at most 15 tool calls.
- If you cannot find a control, say so plainly — do not invent one.

Return EXACTLY this format:
VERDICT: upheld | weakened | killed
DECISIVE ARTIFACT: [path:line of the single strongest artifact; "none" if upheld]
RATIONALE: [at most 5 sentences]
```

### Verdict semantics

| Verdict | Meaning | Action |
|---------|---------|--------|
| `upheld` | No control found, or the control found does not stop this claim | Write the finding as classified |
| `weakened` | A control partially mitigates or reduces reachability/impact | Write with severity **−1 level** AND confidence capped at `High-static` |
| `killed` | A control fully prevents the claimed abuse | **Do not write.** Fingerprint it (below) |

## Recording the verdict

Two artifacts, both required:

1. **Flat frontmatter key** (single line, optional, never replaces a required key):

   ```yaml
   skeptic_review: upheld    # upheld | weakened | killed | skipped-no-harness
   ```

2. **Body section** in the finding file:

   ```markdown
   ## Skeptic Review

   Verdict: upheld
   Decisive artifact: none
   Rationale: [the skeptic's ≤5-sentence rationale, verbatim]
   ```

## `killed` → fingerprint

Do not silently discard a killed finding — it becomes history so future scans
skip it fast (see findings-format.md "False Positive History"):

1. Append a fingerprint entry to `.red-team/fp-history.yaml` with
   `discarded_by: skeptic` and the decisive artifact in `reason`.
2. Add one line to `.red-team/suspicious.md` (if present) noting the killed
   claim and its decisive artifact — a human may want to audit the skeptic.

## Fallback: no subagent harness

If the runtime has no subagent capability, the gate degrades — it never
silently disappears:

- Record `skeptic_review: skipped-no-harness` in frontmatter.
- The finding body's `## Skeptic Review` section must instead contain a
  compensating-controls trace naming **≥3 concrete artifact paths**
  (`path:line` for each control class checked and found absent), written as if
  arguing for the defense.

## Calibration notes

- The skeptic is a **control hunter**, not a severity critic. "The impact
  seems low" is not a verdict; a control that blocks the path is.
- If the skeptic's decisive artifact is wrong (you can read the code and see
  the control does not apply), re-spawn once with the claim sharpened to
  address it, and record the second verdict. Two conflicting verdicts →
  treat as `weakened` and flag for human review in `suspicious.md`.
- Live-probe evidence outranks the skeptic: a captured `.http` pair showing
  the abuse succeeding beats a `weakened` verdict (the control demonstrably
  did not prevent it). Record the probe and the verdict, note the override.
