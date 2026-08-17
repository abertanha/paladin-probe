# Attack Chains (Multi-Stage Exploitation)

Single findings answer "what is broken?" Chains answer "what does breaking
this let me break next?" — the difference between a config report and an
incident narrative. Chain pursuit is deliberately open-ended reasoning under
mechanical evidence discipline: think in stages, prove every link.

## When

`/probe chain [asset]` runs when any of:

- A prior `.red-team/` exists with **≥2 findings across ≥2 categories** — the
  raw material for chains
- Explicitly requested
- Auto-suggested at the end of a pentest when that condition holds

Pick the **top-N assets** by threat-model risk (N=3; effort-scaled:
standard 3 · deep 4 · exhaustive 5).

## Method — attack trees as driver, not decoration

The attack-tree format (see [threat-modeling.md](threat-modeling.md)) is
promoted from a report artifact to the **working driver** of the probe:

1. **Root = attacker goal** for the asset ("exfiltrate tenant PII",
   "reach cloud metadata", "execute arbitrary code").
2. **Every node is a testable hypothesis**, tagged:
   - `[static]` — refutable by reading code (`auth bypassed at X`)
   - `[live]` — refutable by a probe (`probe.sh diff --var role=admin`)
   - `[chained]` — depends on the parent link holding first
3. **Traverse depth-first to the effort cap** (chain depth: standard 2 ·
   deep 4 · exhaustive 6). At each node: test the hypothesis; if it holds,
   descend; if it fails, log the dead end (one line — why it failed, what
   control blocked it) and backtrack to the next sibling.
4. **Dead ends are results.** A pruned branch with a named control is
   negative evidence — keep it in the chain doc.

## Heuristics catalog

Start from these shapes when the findings fit; invent others when they don't.

| Shape | Typical stages | Closure evidence per link |
|-------|----------------|---------------------------|
| SSRF → metadata → creds → BFLA | URL-fetch reachability → 169.254.169.254 read → credential extraction → privileged action as the service identity | probe capture of metadata response; captured use of the cred (never exfiltrate — verify, e.g. `sts get-caller-identity` equivalent) |
| IDOR → PII → cred-reuse → ATO | object access → field exposure → password/seed reuse elsewhere → takeover | probe diff showing foreign object body; code trace of cred reuse path |
| Upload → traversal → RCE | upload accepted → path controlled → file lands in executable path → execution | request/response pair per step; code trace of the path join |
| Blind injection → OOB → exfil | injection sink → observable callback (consent permitting) → data flow out | OOB callback log or time-based diff; captured response pair |
| Secret → pivot → persistence | secret in repo/config/bundle → it grants access elsewhere → access survives rotation | secret location trace; the access it grants demonstrated; rotation path read |

## Discipline

- **Every link carries closure evidence**: a code trace (`path:line`) or a
  probe.sh capture. A link without either is a hypothesis, not a finding.
- **Chain severity ≤ weakest confirmed link.** A metadata-read chain whose
  cred-use link is unproven is capped at the SSRF's severity.
- **Status by confirmed-link count**: `Hypothesis` (0 confirmed) ·
  `Partial` (some) · `Confirmed` (all).
- **Loading-discipline exception — the only one:** during chain pursuit, load
  ANY reference a hypothesis enters, even outside the probed category. Log
  every off-discipline load in `sessions/YYYY-MM-DD_chain.md` (one line:
  reference + why).
- **Safety:** mutating chain probes go through `probe.sh send` like any other
  (idempotency, cleanup templates checked first). A chain **dies** at any link
  whose target matches `skip_routes` — record it as a dead end, do not route
  around the consent boundary.
- **No exploitation beyond proof.** Extracting a credential to prove it works
  stops at verification (use-against-own-session), never exfiltration or
  persistence against the target.

## Artifact

`.red-team/chains/CH-NNN.md`:

```markdown
---
id: CH-001
goal: Reach cloud metadata credentials from the public URL-preview feature
asset: url-preview service
status: Partial          # Hypothesis | Partial | Confirmed
depth: 3
skill_version: paladin-probe@v3
links: [RT-011, RT-012, RT-999]   # RT-ids of member findings, in chain order
---

## Steps

| # | Hypothesis | Tag | Result | Evidence |
|---|-----------|-----|--------|----------|
| 1 | /api/preview fetches arbitrary URLs | [live] | holds — 200, body echoed | RT-011 |
| 2 | 169.254.169.254 reachable through it | [live] | holds — metadata body | RT-012 |
| 3 | Extracted role cred can call privileged API | [chained] | untested — consent for cred use pending | — |

## Dead ends

- Direct IPv6 metadata access — resolver rejects link-local; control: egress
  proxy allowlist (`infra/egress.yaml:22`)
```

Member findings carry the flat optional key `chain: CH-001`.

## Reporting

REPORT.md may add an optional section (real RT-ids only — the grader's G2.1
regexes RT-NNN anywhere in REPORT.md):

```markdown
## Attack Chains

| Chain | Goal | Status | Links |
|-------|------|--------|-------|
| CH-001 | URL-preview → cloud metadata creds | Partial | RT-011, RT-012 |
```
