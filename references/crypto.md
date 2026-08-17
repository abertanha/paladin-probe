# Cryptographic Failures Reference

**Purpose:** Comprehensive reference for testing cryptographic weaknesses — TLS misconfiguration, weak algorithms, padding oracle, key management, RNG flaws, JWT alg confusion, and unencrypted channels.

**OWASP crosswalk:** A04 (Cryptographic Failures), WSTG-4.9.x, ASVS V6.x, CWE-295, CWE-326, CWE-327, CWE-338

**Schema version:** 1
**Skill version:** paladin-probe@v2

---

## Table of Contents

1. [Attack Surface](#1-attack-surface)
2. [TLS / Transport Layer Misconfiguration](#2-tls--transport-layer-misconfiguration)
3. [Weak Algorithms](#3-weak-algorithms)
4. [Padding Oracle](#4-padding-oracle)
5. [Key Management](#5-key-management)
6. [RNG Weakness](#6-rng-weakness)
7. [JWT / JOSE Algorithm Confusion](#7-jwt--jose-algorithm-confusion)
8. [Unencrypted Channels](#8-unencrypted-channels)
9. [Prevention](#9-prevention)
10. [Real-World CVEs](#10-real-world-cves)
11. [Tooling](#11-tooling)
12. [Testing Methodology](#12-testing-methodology)
13. [Payload Quick Reference](#13-payload-quick-reference)
14. [YAML Fingerprint Tables](#14-yaml-fingerprint-tables)

---

## 1. Attack Surface

### Where Crypto Vectors Hide

| Surface | Vector | Risk |
|---------|--------|------|
| HTTPS | Weak cipher, old TLS, missing HSTS | Eavesdropping, MITM |
| JWT | alg: none, HS256→RS256 confusion | Token forgery |
| Password storage | MD5, SHA-1, unsalted | Credential theft |
| Session tokens | Math.random(), UUID v1 | Token prediction |
| Encryption at rest | AES-ECB, hardcoded key | Data decryption |
| Key exchange | Static DH params, no PFS | Key recovery |
| Certificate validation | Self-signed, expired | MITM |
| IV/counter reuse | AES-GCM, ChaCha20 nonce reuse | Plaintext recovery |
| Secret storage | Hardcoded keys in source, env | Credential theft |

### TLS Surface Probe

```bash
# Scan TLS configuration
nmap --script ssl-enum-ciphers -p 443 target.com
openssl s_client -connect target.com:443 -tls1_2
openssl s_client -connect target.com:443 -tls1_3
```

---

## 2. TLS / Transport Layer Misconfiguration

### Weak Ciphers

```bash
# Check for weak ciphers
nmap --script ssl-enum-ciphers -p 443 target.com | grep -E "DES|RC4|3DES|MD5|NULL|EXPORT|LOW"
```

Dangerous ciphers:
- `TLS_RSA_WITH_RC4_128_SHA` (RC4)
- `TLS_RSA_WITH_3DES_EDE_CBC_SHA` (3DES)
- `TLS_RSA_WITH_DES_CBC_SHA` (DES)
- Any `NULL` cipher (no encryption)
- Any `EXPORT` cipher (40-bit)

### Old TLS Versions

```bash
openssl s_client -connect target.com:443 -tls1
openssl s_client -connect target.com:443 -tls1_1
```

TLS 1.0 / 1.1 are deprecated (PCI-DSS, NIST). Allow TLS 1.2+ only.

### Missing HSTS

```bash
curl -sI https://target.com | grep -i strict-transport-security
# No header -> first HTTP request is vulnerable to downgrade
```

### Certificate Issues

```bash
# Check certificate validity
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -text

# Check for self-signed
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -issuer

# Check for expired
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -dates
```

### Detection Signals

- Weak ciphers accepted (RC4, DES, 3DES)
- TLS 1.0 / 1.1 accepted
- Missing HSTS header
- Expired or self-signed certificate
- Missing OCSP stapling

---

## 3. Weak Algorithms

### Hash Algorithms — Password Storage

| Algorithm | Status | Risk |
|-----------|--------|------|
| MD5 | Broken | Collision possible |
| SHA-1 | Broken | Collision (SHAttered) |
| SHA-256 | Acceptable | OK for verification, not storage |
| bcrypt | Recommended | Adaptive, built-in salt |
| argon2 | Recommended | Memory-hard, resists GPU |
| scrypt | Recommended | Memory-hard |
| PBKDF2 | Acceptable | CPU-hard, weaker than bcrypt/scrypt |

### Symmetric Encryption

| Cipher | Mode | Status | Issue |
|--------|------|--------|-------|
| AES | ECB | Broken | Same plaintext → same ciphertext |
| AES | CBC | Weakened | Padding oracle, POODLE (TLS) |
| AES | GCM | Recommended | AEAD, auth tag |
| AES | CCM | Recommended | AEAD (802.11i, Zigbee) |
| ChaCha20 | Poly1305 | Recommended | AEAD, fast in SW |
| DES | Any | Broken | 56-bit key |
| 3DES | Any | Deprecated | 112-bit effective, SWEET32 |
| RC4 | Any | Broken | Biased output |

### Asymmetric Encryption

| Algorithm | Key Size | Status | Risk |
|-----------|----------|--------|------|
| RSA | < 2048 | Broken | Factorizable |
| RSA | 2048 | Acceptable | OK for 2026+ |
| RSA | 4096+ | Recommended | Better margin |
| DSA | < 2048 | Broken | Signature forgery |
| ECDSA | P-256 | Recommended | Strong |
| ECDSA | P-384 | Recommended | Strong |
| Ed25519 | — | Recommended | Fast, constant-time |

### Detection Signals

- MD5 or SHA-1 in use (check response headers, cookies)
- Hardcoded cipher suite selection
- ECB mode in ciphertext (repeating blocks)
- RSA key < 2048 bits

---

## 4. Padding Oracle

### CBC Mode Oracle

When the server reveals whether padding is valid:

```http
POST /api/decrypt HTTP/1.1
Cookie: encrypted=ABCDEF...==
# If padding invalid -> 500 error
# If padding valid -> 200 or different error
```

Attacker iteratively decrypts each block byte-by-byte using the oracle. Tools: PadBuster, custom scripts.

### POODLE (SSLv3)

If SSL 3.0 accepted, padding oracle downgrade attack works:

```bash
openssl s_client -connect target.com:443 -ssl3
```

### Detection Signals

- Different response for modified ciphertext
- "Invalid padding" vs "Invalid MAC" error messages
- SSL 3.0 accepted
- CBC mode ciphers accepted in TLS

---

## 5. Key Management

### Hardcoded Keys

```bash
# Check source for hardcoded keys
grep -r "BEGIN RSA PRIVATE KEY" src/
grep -r "secret" src/ --include="*.ts" --include="*.py" --include="*.js"
grep -rE "[A-Za-z0-9+/]{40,}" src/  # Base64 encoded keys

# Check .env files
cat .env 2>/dev/null
```

### Key Rotation

- Same key used for encryption, signing, and authentication
- No key rotation policy
- Key embedded in binary or config file
- Key in version control

### Key Exposure

```bash
# Check if private key is accessible
curl -s https://target.com/.keys/private.pem
curl -s https://target.com/keys/
curl -s https://target.com/cert.pem
```

### IV / Nonce Reuse

- Static IV across multiple encryptions (AES-CBC)
- Nonce reset on application restart (AES-GCM/ChaCha20-Poly1305)
- Counter reuse = catastrophic for AEAD ciphers

### Detection Signals

- Key in source repository
- Same IV in multiple requests
- Key exposed via public URL
- No KMS / secrets manager usage

---

## 6. RNG Weakness

### Weak RNG Sources

| Source | Status | Risk |
|--------|--------|------|
| `Math.random()` | Weak | Predictable (V8: xorshift128+) |
| `random()` in C | Weak | Linear congruential |
| UUID v1 | Broken | Timestamp + MAC address |
| UUID v4 | Acceptable | But use crypto RNG |
| `/dev/urandom` | Strong | OK for all uses |
| `crypto.randomBytes()` | Strong | Node.js crypto RNG |
| `secrets.randbelow()` | Strong | Python secrets module |
| `SecureRandom` | Strong | Java crypto RNG |

### Token Prediction

```bash
# Grab multiple session tokens, analyze pattern
for i in $(seq 1 10); do
  curl -s -D- https://target.com/login -d 'user=test&pass=test' | grep Set-Cookie
done

# If tokens are sequential or have low entropy -> predictable
```

### Detection Signals

- `Math.random()` used for tokens, IDs, or nonces
- Sequential session IDs
- Low-entropy tokens (short length, alphanumeric only)
- Non-crypto RNG for security-critical values

---

## 7. JWT / JOSE Algorithm Confusion

### alg: none

```jwt
eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiYWRtaW4ifQ.
```

If the server accepts `alg: none` → arbitrary user impersonation.

### Algorithm Confusion (RS256 → HS256)

If the server uses RS256 (asymmetric) but accepts HS256 (symmetric) with the public key as the secret:

```jwt
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.
# Signed with the PUBLIC key as HMAC secret
```

### Weak HMAC Secret

```bash
# Brute-force weak HMAC key
hashcat -a 0 -m 16500 jwt.txt rockyou.txt
# jwt.txt = eyJhbGciOiJIUzI1NiIs...
```

### JWK / JKU Injection

If the server accepts embedded JWK:

```json
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "attacker-generated-modulus",
    "e": "AQAB"
  }
}
```

The server verifies against attacker-controlled public key.

### Detection Signals

- JWT with `alg: none` accepted
- JWT with `alg: HS256` accepted when RS256 expected
- JWT with embedded `jwk` or `jku` accepted
- Weak HMAC secret (dictionary word)
- Low-entropy issuer secret

---

## 8. Unencrypted Channels

### HTTP Mixed Content

```bash
# Check if page loads resources over HTTP
curl -s https://target.com | grep -E 'src="http://|href="http://'

# Check if API endpoint listens on HTTP
curl -s http://target.com/api/users
```

### Internal HTTP

- Internal services communicating over HTTP (not HTTPS)
- Microservices on same cluster without mTLS
- Redis/DB connections without TLS

### Cookie Without Secure Flag

```bash
# Check if session cookies lack "Secure" flag
curl -sI https://target.com | grep -i set-cookie
# If no "Secure" flag -> cookie sent over HTTP
```

### Detection Signals

- Mixed content warnings in browser
- Internal services use HTTP
- Cookies missing `Secure` flag
- Login form submitted over HTTP

---

## 9. Prevention

### TLS

- TLS 1.2 minimum, prefer TLS 1.3
- Modern cipher suites only (EECDH+AESGCM, EECDH+CHACHA20)
- Enable HSTS with `max-age=31536000; includeSubDomains`
- Valid certificate from trusted CA
- OCSP stapling

### Algorithms

- No MD5, SHA-1, DES, 3DES, RC4
- RSA ≥ 2048 bits, ECDSA P-256+
- AES-GCM or ChaCha20-Poly1305 for symmetric
- Argon2 or bcrypt for password storage

### Key Management

- Use cloud KMS or Vault
- Never hardcode keys
- Rotate keys periodically
- Unique IV/nonce per encryption

### RNG

- Always use crypto-grade RNG for security tokens
- `crypto.randomBytes` (Node), `secrets` (Python), `SecureRandom` (Java)

### JWT

- Reject `alg: none`
- Whitelist allowed algorithms (not inferred from header)
- Use asymmetric signatures (Ed25519, ECDSA P-256)
- Validate `kid` against expected set
- Reject embedded `jwk` / `jku`

---

## 10. Real-World CVEs

| CVE | Year | Product | Impact |
|-----|------|---------|--------|
| CVE-2025-30406 | 2025 | Java JWT libraries | Algorithm confusion bypass |
| CVE-2024-31497 | 2024 | PuTTY (ECDSA) | Biased nonces leak private key |
| CVE-2024-21894 | 2024 | Ivanti SSO | JWT authentication bypass |
| CVE-2024-23897 | 2024 | Jenkins CLI | Cryptographic weakness |
| CVE-2023-44487 | 2023 | HTTP/2 (multiple) | Rapid reset — TLS amplification |
| CVE-2023-35169 | 2023 | PHP 8.1 | RNG weakness in session ID generation |

---

## 11. Tooling

| Tool | Purpose |
|------|---------|
| testssl.sh | TLS/SSL configuration scanner |
| nmap ssl-enum-ciphers | Cipher suite enumeration |
| jwt_tool | JWT attack toolkit |
| jwtear | JWT exploitation |
| PadBuster | Padding oracle attack |
| hashcat | HMAC secret brute-force |
| SSLyze | TLS config analyzer |
| TLS-Attester | TLS protocol tests |

---

## 12. Testing Methodology

### Phase 1: TLS Scan

1. Check TLS version support (1.0, 1.1, 1.2, 1.3)
2. Check cipher suite support (weak ciphers)
3. Check HSTS header
4. Check certificate validity

### Phase 2: Algorithm Audit

1. Check password hashing algorithm
2. Check encryption algorithm used
3. Check JWT algorithm acceptance
4. Check JWT embedded key injection

### Phase 3: Key Management

1. Check for hardcoded keys in source
2. Check for exposed key files
3. Check IV/nonce usage pattern
4. Check key rotation evidence

### Phase 4: RNG Audit

1. Check RNG source for sessions/tokens
2. Check token predictability
3. Check UUID version in use

### Phase 5: Padding Oracle

1. Send modified ciphertext
2. Observe error differences
3. If oracle confirmed → automated decryption

---

## 13. Payload Quick Reference

```bash
# TLS scan
nmap --script ssl-enum-ciphers -p 443 target.com
openssl s_client -connect target.com:443 -tls1_2

# Weak cipher check
openssl s_client -connect target.com:443 -cipher "RC4"

# HSTS check
curl -sI https://target.com | grep -i strict-transport-security

# JWT alg: none
# eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.

# JWT algorithm confusion (HS256 with public key)
# Modify alg from RS256 to HS256, sign with public key

# Padding oracle
# Modify last byte of ciphertext block, observe error difference

# Token prediction
for i in $(seq 1 10); do
  curl -s -D- https://target.com/login -d 'user=test&pass=test' | grep Set-Cookie
done

# Hardcoded key search
grep -r "BEGIN RSA PRIVATE KEY\|secret\|\bkey\b" src/ --include="*.{ts,js,py,env}"

# Source map for key exposure
curl -s https://target.com/app.js.map | grep -i "secret\|key\|password"

# Cookie Secure flag check
curl -sI https://target.com | grep -i set-cookie

# IV reuse probe
# Register twice, compare encrypted responses
```

---

## 14. YAML Fingerprint Tables

```yaml
tls_weak_cipher:
  probe: 'openssl s_client -cipher RC4,3DES,DES'
  detection: weak cipher accepted on TLS handshake

tls_old_version:
  probe: 'openssl s_client -tls1 -tls1_1'
  detection: TLS 1.0 or 1.1 accepted

hsts_missing:
  probe: 'curl -sI https://target.com'
  detection: no Strict-Transport-Security header

jwt_alg_none:
  probe: 'JWT with {"alg":"none"} header'
  detection: server accepts unsigned JWT

jwt_alg_confusion:
  probe: 'JWT with RS256→HS256 swap, signed with public key'
  detection: server verifies against public key as HMAC secret

jwt_jwk_injection:
  probe: 'JWT with embedded jwk claim'
  detection: server accepts attacker-controlled key

hardcoded_key:
  probe: 'grep for private key patterns in source'
  detection: RSA/DSA/EC private key in source or .env

weak_rng:
  probe: 'collect 10 session tokens, analyze pattern'
  detection: tokens sequential, low entropy, or deterministic

unencrypted_channel:
  probe: 'curl http://target.com/api'
  detection: internal service accessible over HTTP

padding_oracle:
  probe: 'modify ciphertext byte, observe error difference'
  detection: different responses for valid vs invalid padding
```
