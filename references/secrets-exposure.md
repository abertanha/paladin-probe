# Secrets Exposure

Check for secrets, credentials, and sensitive data that should not be in the
codebase, build artifacts, or git history.

## Probe Patterns

### Hardcoded Secrets in Code

| Pattern | Look For |
|---------|----------|
| API keys | `api_key`, `apikey`, `api-secret`, `sk-...` (Stripe), `AIza...` (Google) |
| Tokens | `token=`, `bearer`, `ghp_...` (GitHub PAT), `xoxp-` (Slack) |
| Passwords | `password=`, `passwd`, `pwd=`, `PGPASSWORD` |
| Connection strings | `mongodb://user:pass@`, `mysql://user:pass@`, `postgres://` |
| Private keys | `-----BEGIN PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY-----` |
| JWT secrets | `jwt_secret`, `JWT_SECRET`, `signing_key` |
| Cloud credentials | `aws_access_key_id`, `AZURE_CLIENT_SECRET`, `GCP_SERVICE_ACCOUNT` |

### Committed .env Files

- `.env` in git history (even if deleted in latest commit)
- `.env.example` with real values instead of placeholders
- `.env.*` files committed (`.env.production`, `.env.staging`)
- Environment variable dumps in README or docs

### Git History Leaks

- Secrets removed in a later commit but still in git history
- `git log -S "password="` to find past commits containing secrets
- `git reflog` for secrets in dropped commits
- Squashed commits still containing secrets in the merge commit parent

### Source Map Leaks (Client-Side)

- Production source maps exposed in `/static/js/*.map`
- Source maps reveal: API endpoints, internal logic, embedded API keys
- Check: `curl https://example.com/static/js/main.abc123.js.map`
- Check: Does `https://example.com/robots.txt` disallow source maps?

### Bundle Inspection

- Minified JS bundles containing embedded secrets (API keys, service URLs)
- Check: `grep -r "sk_live\|pk_live\|ghp_" dist/`
- Check: hardcoded internal IPs or service names in bundles

## Detection Commands

```bash
# Search for hardcoded secrets (use tools if available)
grep -rn "password\s*=" src/ --include="*.{js,ts,py,rs,go,java,rb}"
grep -rn "api_key\s*=" src/ --include="*.{js,ts,py,rs,go,java,rb}"

# Check git history for secrets (slow on large repos)
git log --all --diff-filter=A --pretty=format:"%h %s" -S "sk_live"
git log --all -p -S "password=postgres"

# Check if source maps are exposed
curl -sI https://example.com/static/js/main.js.map | head -5

# Check for .env in git history
git log --all --full-history -- "*.env"

# Use git-secrets if available (major slowdown on large repos)
trufflehog --regex --entropy=False .
```

## Finding Format Example

```yaml
id: RT-030
title: AWS access key hardcoded in src/config/aws.ts
category: Secrets Exposure
severity: Critical
cwe: CWE-798
blast_radius: Full AWS account compromise via leaked access key
location: src/config/aws.ts:5
detection_difficulty: Easy
confidence: High
kev_listed: false
epss_score: null
functional_requirements:
  - Remove hardcoded AWS credentials from source code
  - Use IAM roles or environment-specific secret storage
  - Rotate the exposed key immediately
non_functional_requirements:
  - Add pre-commit hook to scan for secrets before commit
  - Add secret scanning to CI pipeline
acceptance_criteria:
  - src/config/aws.ts contains no credential strings
  - git log no longer contains the exposed key in any commit
```
