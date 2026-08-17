# Config Hardening

Audit security configuration for gaps that reduce attack cost.

## Probe Patterns

### CORS
- Origin reflection: send `Origin: https://evil.com`, check if `Access-Control-Allow-Origin: https://evil.com`
- Wildcard: check for `Access-Control-Allow-Origin: *` when `credentials: true`
- Null origin: send `Origin: null` (sandboxed iframe), check if accepted
- Preflight bypass: send direct request without OPTIONS

### Security Headers
Check for presence and values of:

| Header | Required Value | Risk if Missing |
|--------|---------------|-----------------|
| Content-Security-Policy | Restrictive policy | XSS |
| Strict-Transport-Security | max-age ≥ 31536000 | SSL stripping |
| X-Frame-Options | DENY or SAMEORIGIN | Clickjacking |
| X-Content-Type-Options | nosniff | MIME-type confusion |
| Referrer-Policy | no-referrer or same-origin | Referer leakage |
| Permissions-Policy | Restricted feature set | Feature abuse |
| Cache-Control | no-store for sensitive pages | Sensitive data in cache |

### Debug Endpoints
- `/debug`, `/health`, `/metrics`, `/status`, `/info`, `/api-docs`
- `/__internal`, `/.env`, `/config`, `/admin`
- Check if exposed in production
- Check if authenticated

### Rate Limiting
- Send burst of requests, note threshold
- Test per-IP vs per-user vs per-route limiting
- Test header-based bypass (X-Forwarded-For spoofing)
- Test distributed bypass (rotate IPs, rotate sessions)
- Test reset behavior: does counter reset on certain actions?

### Error Handling
- Send malformed input, check for stack traces
- Send valid request to invalid route, check 404 message
- Trigger 500 error, check for full exception dump
- Check if error messages reveal: SQL queries, file paths, internal IPs, dependency versions

### Cookie Security
- Missing `HttpOnly` on session cookie
- Missing `Secure` flag (cookie sent over HTTP)
- Missing `SameSite` (CSRF)
- Cookie `Domain` too broad (`.example.com` instead of `app.example.com`)
- Cookie `Path` too broad (`/` instead of `/app`)
- Persistent session cookies (no `Max-Age` or `Expires`)

### Weak Cryptography
- Password hashing: MD5, SHA1, SHA256 without salt → should use bcrypt/argon2/scrypt
- Hardcoded IV or encryption key in source code
- Token generation using `Math.random()` or `rand()` (predictable)
- JWT signed with weak secret (< 256-bit)
- Missing TLS between services (internal HTTP calls with sensitive data)
- Self-signed certificates in production
- Outdated TLS version (TLS 1.0, 1.1 → should be 1.2+)
- Insecure cipher / mode (DES, RC4, ECB mode for structured data)

### IaC / Cloud Configuration
- S3 bucket publicly writable or readable without auth
- IAM role with excessive permissions (wildcard `*` actions)
- Security group allowing `0.0.0.0/0` on SSH (22), RDP (3389), or database ports
- Kubernetes pod with `privileged: true` or host network access
- Database publicly accessible (not in VPC)
- Unencrypted EBS volumes or RDS instances
- Cloud storage without versioning or MFA delete
- Terraform/CloudFormation secrets in plaintext in `.tf` / `.yaml` files

## Checklist

```
[ ] CORS does not reflect origin
[ ] CORS does not use wildcard with credentials
[ ] CSP is set and restrictive
[ ] HSTS is set with long max-age
[ ] No debug/health endpoints in production
[ ] Rate limiting present on auth endpoints
[ ] Error messages do not leak internals
[ ] Cookies have HttpOnly + Secure + SameSite
[ ] No stack traces returned to client
[ ] Passwords hashed with bcrypt/argon2/scrypt (not MD5/SHA1)
[ ] No Math.random() used for security tokens
[ ] S3 buckets not publicly writable
[ ] No 0.0.0.0/0 on SSH/database ports
[ ] TLS 1.2+ enforced between services
```
