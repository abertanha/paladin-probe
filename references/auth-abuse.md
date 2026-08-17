# Authentication Abuse (AuthN)

Probe authentication mechanisms for bypasses, missing auth, and token
manipulation. For authorization flaws (IDOR, role escalation, BFLA), see
[authorization-abuse.md](authorization-abuse.md).

## Probe Patterns

### Missing Authentication
- Hit every protected endpoint without credentials
- Check route registration: are new routes accidentally public?
- Check middleware ordering: does auth middleware run after the handler?

### Token Manipulation
- JWT alg: change `RS256` to `none` or `HS256` (use public key as HMAC secret)
- JWT expiry: set `exp` to far future, remove `exp` entirely
- JWT payload: modify claims, re-encode without verification
- Weak secret: bruteforce with common passwords
- Replay: use old token after logout/password change

### Session Attacks
- Session fixation: can attacker set victim's session ID?
- Session prediction: are session IDs sequential/timestamp-based?
- Concurrent sessions: does login invalidate old sessions?
- Session termination: does logout actually invalidate server-side?

### Password Reset Flows
- Token in URL → leaked via Referer header?
- Token predictable (timestamp, sequential, short)?
- Token sent to old email after email change?
- Rate limit on reset attempts?
- Can attacker enumerate valid emails via reset endpoint?

## JWT-Specific Checks

```
alg: none        → { "alg": "none" }          → server accepts unsigned
alg: HS256       → { "alg": "HS256" }         → if RS256 expected, try public key as secret
kid: path trav.  → { "kid": "../../etc/passwd" } → file read via key ID
kid: SQLi        → { "kid": "' OR 1=1 --" }   → SQL injection via key ID
sub: escalation  → { "sub": "admin" }         → impersonate admin
exp: missing     → remove exp                 → never expires
iss: none        → { "iss": "" }              → bypass issuer validation
```

## Integration with Attack Surface Map

Cross-reference surface.md routes with auth middleware:

```yaml
# Flag any route where:
# - auth middleware is missing but similar routes have it
# - auth middleware exists but only checks token existence, not validity
# - admin routes lack role-check middleware
# - middleware is applied at router level but specific route overrides it
```
