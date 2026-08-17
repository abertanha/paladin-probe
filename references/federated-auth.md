# Federated Authentication Abuse

Probes for vulnerabilities in SAML, OAuth2, OIDC, and third-party identity
provider integration. Use when the target uses Supabase Auth, Auth0, Cognito,
Firebase, Keycloak, Okta, or custom SAML/OAuth flows.

---

## SAML

### Core Attack Classes

| Class | Mechanism | Impact |
|-------|-----------|--------|
| Signature wrapping (XSW) | Embed attacker's Response inside a valid SignedInfo block | Forge arbitrary authentication |
| XML signature exclusion | Remove `<ds:Signature>` element | AuthZ bypass (no signature = accepted) |
| Comment injection | `<!-- comment -->` in assertion breaks XML parser comparison | Bypass signature validation |
| Certificate confusion | Use self-signed certificate, app trusts any cert | Forge assertions |
| Recipient check bypass | Modify `AssertionConsumerServiceURL` to attacker endpoint | Steal valid assertions |
| Replay | Reuse captured assertion before expiry | Session reuse without credentials |

### SAML Signature Wrapping (XSW-1 to XSW-9)

| Variant | Description |
|---------|-------------|
| XSW-1 | Move `<Signature>` element to parent, add malicious child |
| XSW-2 | Clone `<Signature>` and embed in attacker block |
| XSW-3 | Use `ID` reference confusion |
| XSW-4 | Exploit `xsi:type` to bypass schema validation |
| XSW-5 | Add duplicate elements — one signed, one malicious |
| XSW-6 | Exploit SOAP envelope structure |
| XSW-7 | Malicious namespace prefix injection |
| XSW-8 | Exploit base64 vs string comparison mismatch |
| XSW-9 | Use XML canonicalization differences |

### Detection Signals

```yaml
detect_saml_abuse:
  - signal: "AssertionConsumerServiceURL not validated against registered ACS"
    pattern: "/acs", "/saml/callback" without URL allowlist check
    severity: Critical
  - signal: "XML signature not required or not verified"
    pattern: "validateAssertion" without "checkSignature", "validateSignature"
    severity: Critical
  - signal: "SAML response accepted without issue/audience restriction"
    pattern: "Issuer" and "Audience" not verified against tenant
    severity: High
  - signal: "SAML response not checked for replay"
    pattern: "AssertionID" stored in Redis check absent; no expiry enforcement
    severity: High
```

---

## OAuth2

### Attack Pattern: redirect_uri Hijack

| Variant | Payload | Effect |
|---------|---------|--------|
| Path traversal | `redirect_uri=https://app.com/../callback` | Bypass exact match check |
| Subdomain | `redirect_uri=https://evil.app.com/` | Subdomain on trusted domain |
| Open redirect chain | `redirect_uri=https://app.com/redirect?to=evil.com` | Chain through app's own open redirect |
| State parameter | `redirect_uri=https://app.com/?state=evil` | Accept arbitrary redirect via state |
| Fragment | `redirect_uri=https://app.com/callback#evil` | Fragment ignored by regex |
| Non-standard port | `redirect_uri=https://app.com:12345/callback` | Port not expected but passes prefix match |
| Unencoded | `redirect_uri=https://app.com/callback?domain=evil.com` | Query param injection |

### Attack Pattern: CSRF via state Parameter

If `state` parameter is missing, static, or predictable:

```http
# Attacker crafts malicious OAuth link
https://app.com/login/oauth?provider=google&state=attacker_fixed

# Victim clicks and logs in — attacker controls the state
# If app uses state for session binding, attacker binds their session to victim's
```

### Attack Pattern: PKCE Downgrade

If the OAuth client supports both S256 (code_challenge_method=S256) and plain:

```http
# Attacker intercepts auth code, sends token exchange without code_verifier
POST /oauth/token
grant_type=authorization_code
code=AUTH_CODE
code_verifier=                              # empty — accepted if no PKCE enforcement
```

### Attack Pattern: Refresh Token Theft

| Scenario | Risk |
|----------|------|
| Refresh token returned in URL fragment | Leaked via Referer header |
| Refresh token not bound to client_id | Can be used from any device |
| Refresh token never expires | Infinite session hijack window |
| Refresh token rotation disabled | Stolen token remains valid after use |

### Detection Signals

```yaml
detect_oauth_abuse:
  - signal: "redirect_uri not validated"
    pattern: "redirect_uri" accepted from query without allowlist check
    severity: Critical
  - signal: "state parameter missing or static"
    pattern: "state" not generated per-request; "state=12345" hardcoded
    severity: High
  - signal: "PKCE not enforced"
    pattern: "code_challenge_method" not S256, "code_verifier" optional
    severity: High
  - signal: "refresh token not rotated"
    pattern: old refresh token still valid after use of new one
    severity: Medium
```

---

## OIDC (OpenID Connect)

### OIDC-Specific Attacks

| Attack | Mechanism | Impact |
|--------|-----------|--------|
| `request_uri` SSRF | OIDC `request_uri` parameter fetched by IdP | SSRF to internal services |
| Discovery doc tampering | MITM replaces `.well-known/openid-configuration` | Directs auth to attacker's IdP |
| `id_token` leak | Token in URL fragment transmitted via Referer | Session hijack via Referer log |
| `nonce` reuse | Token replayed with same nonce within window | Replay attack |
| `acr` downgrade | Request `authentication_context_class_reference` as `urn:mace:incommon:iaq:bronze` instead of `silver` | Weaker auth method accepted |

### OIDC Request URI SSRF

```http
GET /authorize?
  response_type=code
  &client_id=APP
  &redirect_uri=https://app.com/callback
  &scope=openid
  &request_uri=http://169.254.169.254/latest/meta-data/
```

If the IdP fetches the `request_uri` without validation, this is an SSRF vector.

### Detection Signals

```yaml
detect_oidc_abuse:
  - signal: "request_uri parameter accepted"
    pattern: "request_uri" in authorize endpoint
    severity: High (SSRF vector)
  - signal: "id_token in URL without nonce"
    pattern: "response_mode=fragment" and no "nonce" check on token
    severity: Medium
  - signal: "discovery endpoint from user input"
    pattern: "issuer" URL from unvalidated config
    severity: High
```

---

## Supabase Auth (SSR) Specifics

Supabase Auth SSR uses cookie-based session management with OAuth providers.

### Supabase-Specific Checks

| Check | Vulnerable Pattern | Signal |
|-------|-------------------|--------|
| PKCE enforcement | `getSession` accepts code without code_verifier | No PKCE for custom OAuth |
| Cookie merge race | Multiple session cookies from different providers | Cookie merge on redirect can confuse session |
| OAuth redirect validation | `redirectTo` param accepts any URL | Open redirect via `/auth/v1/callback` |
| Email + OAuth conflict | Same email via email+password and OAuth provider | Account takeover via credential confusion |
| Magic link interception | `otp` param in URL leaked via Referer | Session hijack via Referer logs |

### Detection Signals for Supabase

```yaml
detect_supabase_auth:
  - signal: "redirectTo not validated"
    pattern: "options.emailRedirectTo" from user input
    severity: High
  - signal: "session cookie not httpOnly"
    pattern: "supabase-auth-token" cookie without HttpOnly
    severity: High
  - signal: "getSession after signIn without code_verifier check"
    pattern: "await supabase.auth.getSession()" immediately after redirect
    severity: Medium (requires code exchange trace)
```

---

## Common Federation Weaknesses (All Providers)

| Issue | Impact | Detection |
|-------|--------|-----------|
| Email domain as identity proof | Account takeover | No email verification before login |
| JWT alg confusion (`alg: none`, `alg: HS256` with public key) | Token forgery | Check JWT library config |
| Multiple IdP binding on same email | Cross-IdP account merge | Check sign-up handler |
| Sign-up disabled but OAuth first party | Orphan accounts | Check social-only sign-up routes |
| No `aud` claim validation | Token reuse across services | Check Token validation code |
| No `azp` / `authorized_party` check | Token issued to app A used at app B | Check OIDC token handler |

---

## Response Signal Table

| Signal | Likely Vuln |
|--------|-------------|
| SAML ACS URL from user input | Assertion consumer redirect hijack |
| SAML signature verification absent | Forge assertion |
| OAuth `state` parameter missing | CSRF on OAuth callback |
| OAuth `redirect_uri` accepts arbitrary URL | Auth code interception |
| OIDC `request_uri` accepted | IdP-initiated SSRF |
| Supabase `redirectTo` from query | Open redirect via auth callback |
| JWT `alg` set to `none` | JWT forgery |
| Multiple IdP for same email, no merge check | Account takeover |
| Refresh token with no rotation | Token theft → persistent access |
| SameSite=None on auth cookie with OAuth | CSRF on OAuth flow |

---

## Probe Strategy

1. Identify all OAuth providers (Google, GitHub, Supabase, etc.) from login UI and config
2. Read SAML/OAuth/OIDC handler code for redirect validation, state/nonce generation, PKCE enforcement
3. Check JWT library configuration: is `alg` whitelisted? Is `aud` validated? Is public key pinned?
4. Test redirect_uri acceptance by sending authorize request with modified redirect_uri (requires live probe with consent)
5. Check SAML ACS URL validation and certificate trust store
6. Check Supabase Auth cookie flags and merge logic in middleware
7. If OOB callbacks allowed, test `request_uri` SSRF for OIDC IdP
