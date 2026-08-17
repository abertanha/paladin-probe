# Error Handling Security Reference

**Purpose:** Comprehensive reference for testing error handling — stack trace disclosure, verbose error messages, sentinel-error oracles, error-based data leak, and global error handler bypass.

**OWASP crosswalk:** A02 (Security Misconfiguration), A10 (Mishandling Exceptional Conditions), WSTG-4.8.x, ASVS V7.4.x, CWE-209, CWE-215, CWE-532

**Schema version:** 1
**Skill version:** paladin-probe@v2

---

## Table of Contents

1. [Attack Surface](#1-attack-surface)
2. [Stack Trace Disclosure](#2-stack-trace-disclosure)
3. [Verbose Error Messages](#3-verbose-error-messages)
4. [Sentinel-Error Oracles](#4-sentinel-error-oracles)
5. [Error Page XSS](#5-error-page-xss)
6. [Error-Based Data Leak](#6-error-based-data-leak)
7. [Global Error Handler Bypass](#7-global-error-handler-bypass)
8. [Prevention](#8-prevention)
9. [Real-World CVEs](#9-real-world-cves)
10. [Tooling](#10-tooling)
11. [Testing Methodology](#11-testing-methodology)
12. [Payload Quick Reference](#12-payload-quick-reference)
13. [YAML Fingerprint Tables](#13-yaml-fingerprint-tables)

---

## 1. Attack Surface

### Where Error Vectors Hide

| Surface | Vector | Risk |
|---------|--------|------|
| API JSON errors | Verbose error messages | Info disclosure |
| Server-rendered error pages | Stack traces | Source/version leak |
| Validation errors | Field-level detail | Schema enumeration |
| 4xx responses | Custom error codes | Oracle for enumeration |
| Uncaught exceptions | 500 with trace | Debug info leak |
| GraphQL errors | Error paths in response | Schema introspection via error |
| File upload errors | Path in error message | Server path disclosure |
| Database errors | SQL syntax in response | Query structure disclosure |

### Error Surface Probe

```bash
# Trigger 500 errors
curl -s https://target/api/users/NaN
curl -s -X POST https://target/api/login -d 'invalid=json'
curl -s -X DELETE https://target/api/orders/invalid-id
curl -s "https://target/api/search?q=<script>"

# Check for stack traces
curl -s https://target/api/nonexistent-endpoint
curl -s https://target/.env
curl -s https://target/WEB-INF/web.xml
```

---

## 2. Stack Trace Disclosure

### Framework Default Error Pages

```bash
# Express/Python debug mode
curl -s https://target/api/users/abc-123
# Response includes file paths, line numbers, module versions
```

### Stack Trace Content

A stack trace typically leaks:
- Server file paths (absolute paths: `/var/www/app/src/controllers/...`)
- Framework/version (`express@4.18.2`, `Django 5.0`)
- Internal function names
- Database query fragments
- Middleware chain order
- Environment variables (sometimes)

### Dev Mode in Production

```bash
curl -s https://target/__next_original_stack_trace
curl -s https://target/?debug=1
curl -s https://target/?XDEBUG_SESSION_START=1
```

### Source Map Leak

```bash
# Next.js, Webpack, Vite source maps
curl -s https://target/_next/static/chunks/pages/login-abc123.js.map
# If 200 -> full source code exposure
```

### Detection Signals

- File paths in response body
- Line numbers in error messages
- Framework/module version strings
- Internal class or function names
- Source maps accessible

---

## 3. Verbose Error Messages

### SQL Error Leak

```json
{
  "error": "ER_PARSE_ERROR: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'INVALID' at line 1"
}
```

Leaks: DB type (MySQL), query structure, table hints.

### Validation Error Schema Enumeration

```json
{
  "errors": [
    {"field": "email", "message": "Email is required"},
    {"field": "password", "message": "Password must be at least 8 characters"},
    {"field": "role", "message": "Role must be one of: user, admin, editor"}
  }
]
```

Leaks: field names, validation rules, valid enum values.

### Path Disclosure

```json
{
  "error": "File not found: /var/www/app/uploads/../../etc/passwd"
}
```

Leaks: absolute server path, file structure.

### Internal Hostname / IP Leak

```json
{
  "error": "Connection refused: db-internal-01.company.internal:5432"
}
```

Leaks: internal network topology, DB hostnames, ports.

### Detection Signals

- SQL syntax in error response
- Field names and validation rules leaked
- File paths in error messages
- Internal hostnames or IPs in errors

---

## 4. Sentinel-Error Oracles

### Definitions

A sentinel error is a deliberately different error message that the attacker uses as an oracle. The sentinel itself isn't the vulnerability — it's the tool to exploit another:

| Oracle | Probes | WSTG Ref |
|--------|--------|----------|
| Login error difference | Account enumeration | WSTG-4.3.4 |
| Price validation error | Logic abuse | WSTG-4.10.1 |
| IDOR error vs 404 | Authorization bypass | WSTG-4.5.4 |
| SQL error vs generic 500 | SQL injection | WSTG-4.7.5 |

### IDOR Oracle

```
GET /api/orders/my-order -> 200 ({"items": [...]})
GET /api/orders/other-user-order -> 404 ({"error": "Not found"})
```

Oracle: 404 means "order exists but not yours" vs "order doesn't exist". Attacker enumerates order IDs.

### SQLi Oracle (Error-Based)

```
'  -> 500 with SQL error (vulnerable)
'' -> 200 (safe)
```

### Rate Limit Oracle

```
Request 1: 200 with data
Request 50: 429 with "Rate limit exceeded"
Request 51: 429 ("Rate limit exceeded") -> limit confirmed
```

### Detection Signals

- Different HTTP status codes for different error conditions
- Custom error codes in response body (code: 1001 vs 1002)
- Different response body lengths for different error paths

---

## 5. Error Page XSS

### Reflected Error

```
https://target/error?msg=<script>alert(1)</script>
# If error page renders msg without escaping -> XSS
```

### Stack Trace XSS

```
https://target/api/users/abc<script>alert(1)</script>
# If file path in stack trace renders unescaped -> XSS
```

### Detection Signals

- Error message reflects user input
- Stack trace includes attacker-controlled input
- 404 handler renders URL path unescaped

---

## 6. Error-Based Data Leak

### Time-Based Oracle

```
' AND IF(1=1, SLEEP(5), 0) -- -> 5000ms response
' AND IF(1=2, SLEEP(5), 0) -- -> 20ms response
```

The error itself is the same (or no error), but timing differs.

### Conditional Error

```
' AND 1=CONVERT(INT, (SELECT @@version)) -- 
# If error message includes conversion result -> data leak
```

### Error Aggregation

Some frameworks aggregate errors and return them in batch:

```json
{
  "errors": [
    {"field": "items[0].price", "error": "must be positive"},
    {"field": "items[1].price", "error": "must be positive"},
    {"field": "items[2].price", "error": "must be positive"},
    {"field": "items[3].price", "error": "must be positive"}
  ]
}
```

Leaks: number of items in order (even if unauthorized to see items).

### Detection Signals

- Response time varies based on error condition
- Error response aggregates leaked data
- Conversion error returns sensitive data

---

## 7. Global Error Handler Bypass

### Route-Level Exception Swallowing

```javascript
// Global handler exists but route has its own try/catch that leaks
app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await db.findUser(req.params.id);
    res.json(user);
  } catch (e) {
    // Bypasses global handler — leaks raw error
    res.status(500).json({ error: e.message });
  }
});
```

### Middleware Error Passthrough

```javascript
// Middleware error handler that calls next(err)
// But no error-handling middleware registered after routes
app.use((err, req, res, next) => {
  // Never called if no routes call next(err)
  res.status(500).json({ error: "Internal error" });
});
```

### Async Exception Unhandled

```javascript
// Express 4 does NOT catch rejected promises automatically
app.get('/api/users/:id', async (req, res) => {
  const data = await crashFunction(); // Rejected promise
  // Unhandled -> 500 with stack trace (if no express-async-errors)
});
```

### Detection Signals

- Some routes return generic errors, others return verbose errors
- Route-level error handling differs from global pattern
- Async handler without error wrapper

---

## 8. Prevention

### Stack Traces

- Disable debug/development mode in production
- Set `NODE_ENV=production` (or equivalent)
- Register a global error handler that returns generic error for 5xx
- Never expose `__next_original_stack_trace` or similar endpoints
- Remove source maps from production builds (or gate behind auth)

### Verbose Errors

- Return same error message for all validation failures: "Invalid input"
- Log detailed errors server-side only (Sentry, console.error)
- Strip SQL errors before returning to client
- Never return file paths, hostnames, or internal IPs

### Oracles

- Use generic 401/403/404 for all authorization failures
- Vary response time artificially to normalize timing
- Use same error body for all error codes
- Avoid custom error codes that differ by condition

### Global Handler

- Wrap all async routes in a centralized error wrapper
- Use framework error-handling middleware as last middleware
- Log unhandled rejections globally
- Register error handlers after all routes

---

## 9. Real-World CVEs

| CVE | Year | Product | Impact |
|-----|------|---------|--------|
| CVE-2025-21345 | 2025 | Windows OLE | Info disclosure via error message |
| CVE-2024-47575 | 2024 | FortiManager | Stack trace disclosure via API error |
| CVE-2024-34102 | 2024 | Adobe Commerce | XXE — error-based data leak (CosmicSting) |
| CVE-2024-27198 | 2024 | JetBrains TeamCity | Auth bypass via error message oracle |
| CVE-2023-35169 | 2023 | PHP (8.1) | Info disclosure via exception handling |

---

## 10. Tooling

| Tool | Purpose |
|------|---------|
| Burp Intruder | Error oracle detection via response comparison |
| curl + jq | Scripted error analysis |
| Source Map CLI | Check source map exposure |
| Nikto | Server info disclosure checks |

---

## 11. Testing Methodology

### Phase 1: Trigger Errors

1. Send invalid data types (string for number, object for string)
2. Send expired/revoked tokens
3. Send invalid UUID/ID formats
4. Access non-existent routes
5. Trigger auth failures

### Phase 2: Analyze Leakage

1. Check for stack traces in 500 responses
2. Check for SQL error details in responses
3. Check for file paths or hostnames
4. Check for internal function names
5. Check for source map files

### Phase 3: Oracle Detection

1. Compare responses for different error conditions
2. Check for timing differences
3. Check for different HTTP status codes per condition
4. Check for custom error codes that vary

### Phase 4: Handler Consistency

1. Check if all routes return same error format
2. Check for route-level try/catch that bypasses global handler
3. Check for async error handling

---

## 12. Payload Quick Reference

```bash
# Trigger 500
curl -s https://target/api/users/NaN
curl -s https://target/api/users/undefined
curl -s "https://target/api/users/<script>"
curl -s https://target/api/orders/../../etc/passwd

# Check source maps
curl -s https://target/_next/static/chunks/pages/login-*.map
curl -s https://target/js/app.js.map
curl -s https://target/sourcemaps/

# Check framework debug modes
curl -s "https://target/?debug=true"
curl -s "https://target/?XDEBUG_SESSION_START=1"
curl -s "https://target/__next_original_stack_trace"

# SQL error probe
curl -s "https://target/api/users/1'"
curl -s "https://target/api/users/1%27"

# Error oracle comparison
curl -s -o /dev/null -w "%{http_code}" https://target/api/orders/valid-id
curl -s -o /dev/null -w "%{http_code}" https://target/api/orders/other-id
curl -s -o /dev/null -w "%{http_code}" https://target/api/orders/nonexistent-id

# Time-based oracle
time curl -s -o /dev/null "https://target/api/users/1' AND 1=1 -- "
time curl -s -o /dev/null "https://target/api/users/1' AND 1=2 -- "

# Error message comparison
curl -s -X POST https://target/login -d 'user=known&pass=wrong'
curl -s -X POST https://target/login -d 'user=unknown&pass=wrong'
```

---

## 13. YAML Fingerprint Tables

```yaml
stack_trace_disclosure:
  probe: 'GET /api/users/NaN or similar invalid input'
  detection: response contains file paths, line numbers, or framework versions

source_map_exposed:
  probe: 'GET /_next/static/chunks/pages/*.map'
  detection: source map returns 200 with source code

sql_error_leak:
  probe: "GET /api/users/1' or similar SQL probe"
  detection: SQL syntax or error details in response

error_oracle:
  probe: 'compare responses for valid vs invalid resource ID'
  detection: different HTTP status or error body for authorized, not found, forbidden

global_handler_bypass:
  probe: 'test multiple routes with invalid input'
  detection: some routes return generic error, others return verbose

verbose_validation:
  probe: "POST /api/register with invalid fields"
  detection: validation error leaks field names, rules, enum values

async_error_leak:
  probe: 'async endpoint with invalid input (Express 4)'
  detection: unhandled promise rejection returns stack trace

debug_mode_production:
  probe: 'GET /?debug=1 or /__next_original_stack_trace'
  detection: debug endpoints return detailed error info
```
