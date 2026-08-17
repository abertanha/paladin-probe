# Dependency Audit

Check third-party dependencies for known vulnerabilities, outdated versions,
and supply-chain risks. Uses a tiered approach — prefer native tools, fall back
to APIs, enrich with CISA KEV and EPSS for prioritization.

## Tiered Approach

```
Tier 1: Native ecosystem tool (preferred)
  npm audit | cargo audit | pip-audit | bundle audit | govulncheck
  → fast, offline, authoritative for that ecosystem
  → already maps packages+versions to vulnerabilities

Tier 2: OSV.dev API (fallback / cross-ecosystem)
  POST https://api.osv.dev/v1/querybatch
  → batch query by Package URL (purl), no auth required
  → aggregates GHSA + PyPA + npm advisory + RustSec + others

Tier 3: CISA KEV enrichment
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  → if a CVE is listed here, it is being exploited in the wild
  → auto-boost severity to Critical regardless of CVSS score

Tier 4: NVD enrichment (only for specific CVE detail)
  https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-xxxxx
  → get CVSS vector, CWE, references for a specific CVE
  → NOT for primary search — use Tier 1 or Tier 2 for that
```

## Detection by Ecosystem

### Native Tools

```bash
# Node.js — npm audit
npm audit --json                 # Known vulns + severity + fix version
npm outdated --json              # Outdated packages

# Node.js — yarn
yarn audit --json                # Known vulns

# Rust
cargo audit                      # Known vulns (requires cargo-audit)
cargo outdated                   # Outdated (requires cargo-outdated)

# Python
pip-audit                        # Known vulns (requires pip-audit)
pip list --outdated --format=json # Outdated

# Go
govulncheck ./...                # Known vulns (requires govulncheck)

# Ruby
bundle audit                     # Known vulns (requires bundler-audit)
bundle outdated                  # Outdated
```

### OSV.dev API (Fallback)

```bash
# Batch query by purl
curl -X POST https://api.osv.dev/v1/querybatch \
  -H "Content-Type: application/json" \
  -d '{
    "queries": [
      {"package": {"purl": "pkg:npm/lodash@4.17.15"}},
      {"package": {"purl": "pkg:pypi/django@3.2.0"}},
      {"package": {"purl": "pkg:cargo/openssl@0.10.30"}}
    ]
  }'

# Single query
curl -X POST https://api.osv.dev/v1/query \
  -H "Content-Type: application/json" \
  -d '{"package": {"purl": "pkg:npm/lodash@4.17.15"}}'
```

### CISA KEV (Enrichment)

```bash
# Fetch the full KEV catalog
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  | jq '.vulnerabilities[] | select(.cveID == "CVE-2023-xxxxx")'

# Or check if a specific CVE is listed
# If found → mark finding as kev_listed: true, auto-boost severity to Critical
```

### NVD (Enrichment only)

```bash
# Get CVSS + CWE for a specific CVE
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-xxxxx" \
  | jq '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData'
```

## EPSS Prioritization

After finding a CVE, look up its EPSS score to gauge real-world exploitation
probability:

```bash
curl -s https://api.first.org/data/v1/epss?cve=CVE-2023-xxxxx \
  | jq '.data[0]'
```

| EPSS Score | Meaning | Action |
|------------|---------|--------|
| > 0.9 | Almost certain to be exploited | Auto-Critical |
| 0.5 - 0.9 | Highly likely | Consider severity boost |
| 0.1 - 0.5 | Possible | Keep as-is |
| < 0.1 | Unlikely | Consider lowering priority |

## Outdated Packages

- Compare installed version to latest semver
- Flag packages past EOL (AngularJS, jQuery < 3, Express < 4, Python < 3.9)
- Flag packages unmaintained (> 2 years without commits)

## Supply Chain Risks

- Typo-squatting: names similar to popular packages (`uril` vs `url`, `cnpm` vs `npm`)
- Suspicious maintainer: single maintainer, new package with sudden adoption
- Install scripts: packages with postinstall/preinstall — higher risk surface
- Network calls: packages that make external requests during install

## Finding Format

```yaml
schema_version: 2
id: RT-050
title: lodash prototype pollution (CVE-2020-8203)
category: Dependency Audit
severity: High
cwe: CWE-1321
location: package-lock.json (lodash@4.17.15)
blast_radius: Server-side object pollution via merged user input
status: Open
confidence: High-static
skeptic_review: upheld
skill_version: paladin-probe@v3
kev_listed: false
epss_score: 0.87
exploited_in_wild: false
functional_requirements:
  - Upgrade lodash to version >= 4.17.21
  - Remove direct dependency if no longer used
acceptance_criteria:
  - npm audit no longer reports CVE-2020-8203
  - All lodash imports continue to work after upgrade
```

## Audit Workflow

```
1. Detect lock file (package-lock.json, Cargo.lock, etc.)
2. Run native tool → parse output for vulns + outdated
3. For each vuln found:
   a. Check CISA KEV → flag kev_listed
   b. Check EPSS → score the finding
   c. If no native tool available for this ecosystem:
      → Fall back to OSV.dev batch query by purl
4. Report each finding with enriched priority
```
