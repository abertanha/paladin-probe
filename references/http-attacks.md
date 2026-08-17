# HTTP Attacks

Probes for HTTP protocol-level vulnerabilities: request smuggling, cache
poisoning, open redirect, host-header injection, method override, and
HTTP/2 downgrade attacks.

Use when the target is behind a reverse proxy, CDN, or load balancer (nginx,
Cloudflare, AWS ELB/ALB, Vercel, HAProxy, Apache).

---

## HTTP Request Smuggling

### Attack Classes

| Class | Mechanism | Impact |
|-------|-----------|--------|
| **CL.TE** | Frontend uses Content-Length, backend uses Transfer-Encoding | Request smuggling to poison next request |
| **TE.CL** | Frontend uses Transfer-Encoding, backend uses Content-Length | Request smuggling to poison next request |
| **TE.TE** | Both use Transfer-Encoding but parse it differently (obfuscated header) | Request smuggling via parser differential |
| **H2.CL** | HTTP/2 → HTTP/1.1 downgrade, frontend sees H2 body, backend sees CL | Desync via protocol downgrade |
| **H2.TE** | HTTP/2 → HTTP/1.1 downgrade, TE header injected by attacker | Desync via TE on downgraded request |

### CL.TE — Detection

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

If smuggled, the `G` prefix prepended to next request creates an invalid HTTP request
(victim sees error or wrong response). Smuggling confirmed if subsequent visitor's
request gets a different response.

### TE.CL — Detection

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

5c
GPOST / HTTP/1.1
Host: target.com
Content-Length: 15

x=1
0

```

First request body: `5c\r\nGPOST /...x=1\r\n0\r\n\r\n` — backend reads Content-Length: 4
and takes only `5c\r\n`, rest (`GPOST /...`) treated as next request.

### TE.TE — Obfuscated Headers

| Variant | Header Line |
|---------|-------------|
| Extra comma | `Transfer-Encoding: chunked,` |
| Extra spaces | `Transfer-Encoding: chunked ` |
| Tab between | `Transfer-Encoding:\tchunked` |
| Leading whitespace | ` Transfer-Encoding: chunked` |
| Line feed | `Transfer-Encoding: chunked\r\n Transfer-Encoding: identity` |
| Custom value | `Transfer-Encoding: xchunked` |

### Impact Chains

```
Smuggling → Cache Poisoning
  Poison proxy cache so all visitors receive malicious content

Smuggling → Request Hijacking
  Steal victim's request body or headers (cookies, CSRF tokens)

Smuggling → WAF Bypass
  Smuggled request bypasses front-end WAF rules

Smuggling → Auth Bypass
  Inject admin-authenticated prefix into attacker's request
```

### Source Fingerprints

```yaml
detect_smuggling:
  - signal: "reverse proxy in front of app server"
    pattern: "nginx → uwsgi/passenger", "cloudflare → origin", "ELB → node", "Vercel → Next.js"
    severity: Medium (requires active detection to confirm)
  - signal: "Transfer-Encoding accepted from client"
    pattern: "proxy_pass" without "proxy_set_header Transfer-Encoding ''"
    severity: High (if confirmed active)
  - signal: "HTTP/2 → HTTP/1.1 downgrade"
    pattern: "h2c", "H2 upgrade", "downgrade to HTTP/1.1"
    severity: High
```

---

## Cache Poisoning

### Attack Mechanism

```
Step 1: Send request with unkeyed header (e.g., X-Forwarded-Host)
Step 2: Response includes poisoned value in URL or script src
Step 3: Proxy caches poisoned response under the keyed request
Step 4: Subsequent visitors receive poisoned (malicious) response
```

### Unkeyed Headers to Test

| Header | Impact |
|--------|--------|
| `X-Forwarded-Host` | URL/path poisoning in redirects |
| `X-Forwarded-Scheme` | Protocol-relative URL poisoning |
| `X-Original-URL` | Path overwrite on IIS/Spring |
| `X-Rewrite-URL` | Path overwrite on IIS |
| `X-HTTP-Method-Override` | Method override for cache key |
| `Origin` | CORS header reflection in cached response |
| `Accept` | Content negotiation poisoning |
| `Cookie` | Rarely keyed — user-specific cache poisoning |
| `Authorization` | Often keyed — but if missing, auth bypass |

### Cache Poisoning Types

| Type | Description | Example |
|------|-------------|---------|
| Fat GET | `GET /script.js?sessid=steal` — cache key includes query string, but response serves generic content | Cache serves generic script to all users |
| Web Cache Deception | Request `GET /account/profile/nonexistent.css` — app returns profile page (200), proxy caches as CSS | Private data cached as static asset |

### Source Fingerprints

```yaml
detect_cache_poisoning:
  - signal: "unkeyed header used in response"
    pattern: "X-Forwarded-Host" echoed in "Location" header
    severity: High
  - signal: "no Vary header on dynamic endpoints"
    pattern: "Vary: *" absent on authenticated responses
    severity: Medium
  - signal: "proxy cache without header normalization"
    pattern: "proxy_cache_key" without all input headers listed
    severity: Medium
```

---

## Open Redirect

### Detection Payloads

```
/login?redirect=https://evil.com
/login?next=https://evil.com
/login?url=https://evil.com
/login?return_to=https://evil.com
/login?redirect_uri=https://evil.com
/login?goto=https://evil.com
/login?continue=https://evil.com
/login?view=https://evil.com
/login?path=//evil.com
/login?next=///evil.com
/login?redirect=%68%74%74%70%73%3A%2F%2Fevil.com (URL encoding)
/login?redirect=https://evil.com%2f@target.com (credential confusion)
/login?redirect=https://evil.com? (protocol-relative)
/login?redirect=//evil.com (protocol-relative)
```

### Source Fingerprints

```yaml
detect_open_redirect:
  - signal: "user input in redirect destination"
    pattern: "res.redirect(input)", "res.redirect(302, input)", "window.location = input"
    severity: High
  - signal: "no URL whitelist validation"
    pattern: "res.redirect(req.query.redirect)" without "if (!ALLOWED_URLS.includes(url))"
    severity: High
```

---

## Host-Header Injection

### Attack Vectors

```http
GET / HTTP/1.1
Host: evil.com
```

| Attack | Behavior |
|--------|----------|
| Password reset poisoning | App generates reset link: `https://evil.com/reset?token=xyz` |
| Cache poisoning | Proxy caches response under `evil.com` host, serves to others |
| SSRF to internal host | App fetches from `http://evil.com` instead of internal service |
| Web cache deception | Different origin → different cache key |

### Detection

```
curl -H "Host: evil.com" https://target.com/login
Check if response contains "evil.com" in:
  - Location header (redirect)
  - Form action URL
  - Script src URL
  - Link href
  - Password reset email template (if visible)
```

### Source Fingerprints

```yaml
detect_host_header:
  - signal: "Host header used in URL generation without validation"
    pattern: "req.headers.host" in URL string, "window.location.host" in server-generated JS
    severity: High
  - signal: "password reset uses Host header"
    pattern: "resetLink = `https://${req.headers.host}/reset/${token}`"
    severity: Critical
```

---

## HTTP Method Override

### Bypass Techniques

| Header | Value | Effect |
|--------|-------|--------|
| `X-HTTP-Method-Override` | `DELETE` | Bypass GET-only restriction |
| `X-HTTP-Method` | `PUT` | Bypass method-level auth |
| `X-Method-Override` | `PATCH` | Access endpoints only listening for PATCH |
| `X-HTTP-Method-Override` | `PROPFIND` | WebDAV method injection |
| `X-Original-URL` | `/admin/delete` | Path override with safe method |
| `X-Rewrite-URL` | `/admin/delete` | Path override (IIS/Spring) |

### Source Fingerprints

```yaml
detect_method_override:
  - signal: "method override middleware enabled"
    pattern: "methodOverride(", "X-HTTP-Method-Override", "app.use(methodOverride)"
    severity: Medium (check if authz scoped to method)
  - signal: "methods not gated by role"
    pattern: "if (req.method !== 'GET')" or similar without role check on non-GET
    severity: Medium
```

---

## HTTP/2 Rapid Reset

### Attack

```
CVE-2023-44487: Rapidly open and reset HTTP/2 streams to cause DoS.

Stream 1: HEADERS + RST_STREAM
Stream 3: HEADERS + RST_STREAM
Stream 5: HEADERS + RST_STREAM
... repeat to fill server's stream table
```

### Detection Signals

```yaml
detect_h2_rapid_reset:
  - signal: "HTTP/2 server exposed to internet"
    pattern: "h2", "h2c" in ALPN, "Upgrade: h2c" header
    severity: Medium (CVE patched in Go 1.21, Node 20.6+, nginx 1.25.3+)
  - signal: "outdated HTTP/2 library"
    pattern: "golang.org/x/net v0.17-" or older; "node-fetch-native" without patch
    severity: High (if unpatched)
```

---

## Response Signal Table

| Signal | Likely Vuln |
|--------|-------------|
| Different response to smuggled prefix | Request smuggling |
| User input echoed in `Location` header | Open redirect |
| `Host:` header echoed in response URL | Host-header injection |
| Cache serves authed response as static file | Web cache deception |
| Unkeyed header changes cached response | Cache poisoning |
| Method override changes behavior | Method override bypass |
| HTTP/2 server version is vulnerable | Rapid reset DoS |

---

## Probe Strategy

1. Identify proxy/CDN/load balancer from response headers (Server, Via, X-Cache, CF-RAY)
2. Read nginx/Vercel/cloud config for proxy_pass patterns
3. Test smuggling for each class (CL.TE, TE.CL, TE.TE, H2.CL) — requires live probe with OOB confirmation
4. Test cache poisoning by injecting unkeyed headers and observing cached versus uncached responses
5. Test open redirect via all URL-param permutations
6. Test host-header injection by setting `Host: evil.com` and checking response/redirect URLs
7. Test method override on auth-gated endpoints
8. For HTTP/2, check server library version in lock file or response headers
