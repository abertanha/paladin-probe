# Resource Exhaustion (DoS / Algorithmic)

Test whether the application can be forced to consume excessive resources
(CPU, memory, disk, network, connections) through crafted inputs.

## Probe Patterns

### ReDoS — Regular Expression Denial of Service

Catastrophic backtracking in regex can freeze the event loop for seconds or
minutes with a carefully crafted input string.

**Evil patterns (look for in codebase):**
```regex
/(a+)+b/                  # Nested quantifiers
/([a-zA-Z]+)*\d/           # Quantifier on a quantified group
/(x+x+)+y/                 # Multiple adjacent quantifiers
/a*b*c*d*e*f*g*h*i*j*k*l*m*n*o*p*q*r*s*t*u*v*w*x*y*z+xxxxx/
```

**Test inputs:**
```text
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac
aaaaaa...aaaa (very long string of just 'a')
{"regex_test": "a".repeat(50) + "c"}
```

### Zip Bomb / Compression Bombs

Small files that expand to enormous sizes on extraction.

Tests:
- Upload a zip bomb (42 KB → 4.5 PB decompressed)
- Upload nested zip files (zip within zip within zip)
- Upload tar.gz with pathological compression ratio
- Check if the application limits decompressed size

### Large Payload Attacks

```http
# Oversized request body
POST /api/import {"data": "A".repeat(100_000_000)}

# Array with many elements
POST /api/batch {"ids": Array.from({length: 100000}, (_, i) => i)}

# Deeply nested object (stack overflow potential)
POST /api/save {"a": {"a": {"a": ... 10000 levels deep}}}

# GraphQL depth attack
query { posts { author { posts { author { posts {...} } } } } }
```

### Unbounded Loops and Pagination

```http
# No max page size
GET /api/users?limit=999999999
GET /api/users?page=100000       # Sequential DB scans

# Cursor-based pagination without cap
GET /api/users?cursor=aaaa...bbbb  # Could force deep scans

# GraphQL pagination
{ users(first: 10000) { id name email } }
```

### Connection Exhaustion

- Slow loris: send HTTP headers slowly, keep connections open
- Concurrent uploads: many simultaneous large file uploads
- WebSocket connections: open many ws:// connections without closing

### Expensive Queries and Operations

- Sort on unindexed field with large dataset
- Full-text search without limits
- `COUNT(*)` on large tables without caching
- File upload that triggers thumbnail generation for enormous images
- CSV export that generates huge files in memory

## Source Code Indicators

| Pattern | Risk |
|---------|------|
| `/(\w+\s+)+\d/` in route handler | ReDoS |
| `unzip(file)` without size limit | Zip bomb |
| `req.body` without size limit | Large payload |
| `Model.find({}).sort(...)` without pagination | Expensive query |
| `sharp(file)` or `gm(file)` on user upload | Image bomb |
| `await Promise.all(items.map(...))` with unbounded input | Resource pool exhaustion |
| `JSON.parse(data)` without depth limit | Deep nesting attack |

## Finding Format Example

```yaml
schema_version: 2
id: RT-045
title: No pagination limit on GET /api/users — one request can scan entire DB
category: Resource Exhaustion
severity: High
cwe: CWE-770
blast_radius: Database CPU/memory exhaustion for the primary read replica
location: src/routes/users.ts:15
detection_difficulty: Easy
status: Open
confidence: High-static
skeptic_review: upheld
skill_version: paladin-probe@v3
functional_requirements:
  - List endpoint MUST enforce a maximum page size (≤ 100 default)
  - Server MUST reject requests exceeding the maximum page size
  - Pagination MUST use indexed fields to avoid sequential scans
non_functional_requirements:
  - Max page size MUST be configurable via environment variable
  - Response MUST include total count or pagination cursors
acceptance_criteria:
  - GET /api/users?limit=1000000 returns 400 Bad Request
  - GET /api/users?limit=50 returns 200 with ≤ 50 records
```
