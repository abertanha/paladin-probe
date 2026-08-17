# Authorization Abuse (AuthZ)

Test authorization enforcement — whether users can access data or perform
actions they should not be allowed to. This is distinct from authentication
("who are you?") — authorization asks "are you allowed to do this?"

## Probe Patterns

### IDOR — Insecure Direct Object Reference

Accessing resources by ID that belong to other users.

```http
GET /api/orders/123    # User A's order — works
GET /api/orders/124    # Try user B's order — should fail
GET /api/orders/123?userId=456  # Try user ID override
```

Tests:
- Change object ID in URL: GET /api/invoices/{other-user-id}
- Change object ID in body: POST /api/transfer {"from": "other-account", ...}
- UUID enumeration: sample valid UUIDs, check if incrementing works
- Array/object injection: `{"ids": ["my-id", "other-id"]}`

### BFLA — Broken Function Level Authorization

Accessing admin/mod/privileged endpoints as a regular user.

```http
GET /api/admin/users          # Regular user → should 403
DELETE /api/users/123         # Regular user deleting other user → should 403
POST /api/users {"role": "admin"}  # Self-escalation via body
```

Tests:
- Hit every admin/mod route with a regular user token
- Try HTTP method escalation: GET → POST, POST → PUT, PUT → DELETE
- Check if role check happens per-route or only at router level
- Hidden endpoints: `/internal`, `/admin`, `/mod`, `/api/v2/`

### Role Escalation

Manipulating role or permission claims.

- JWT payload: `{"role": "user"}` → `{"role": "admin"}`
- Body param: `POST /api/signup {"email": "x", "role": "admin"}`
- Header override: `X-Role: admin`, `X-User-role: moderator`
- Cookie manipulation: modify session role value
- Default role: register without specifying role, check what default is granted
- Role precedence: if user has roles ["user", "admin"], which takes effect?

### Excessive Data Exposure

API returns more data than the client needs, exposing sensitive fields.

```json
// Response to GET /api/users/me
{
  "id": 1,
  "name": "User",
  "email": "user@example.com",
  "internal_notes": "...",      // Should not be exposed
  "salary": 75000,              // Should not be exposed
  "password_hash": "..."        // Critical leak
}
```

Tests:
- Inspect full response bodies for unexpected fields
- Check if filtering by fields works: `?fields=name,email` returns everything anyway
- Compare admin vs user response shape for the same endpoint
- GraphQL: introspect schema, request nested fields to check depth limiting

### Mass Assignment (aka Auto-Binding)

User-supplied data binds directly to internal objects without field allowlisting.

```http
POST /api/users {"name": "x", "role": "admin", "balance": 99999}
PUT /api/orders/123 {"total": 0.01, "status": "paid"}
```

Tests:
- Add unexpected fields to request body
- Check if model has `fillable` / `guarded` / `@Expose` annotations
- Try status transitions: `{"status": "cancelled"}` → `{"status": "shipped"}`
- Try computed fields: `{"total": 0.01}` on order where total is server-calculated

## Cross-Reference with Attack Surface Map

From `surface.md`, identify:

- Routes that accept user IDs in path or query params → potential IDOR
- Routes with shared auth middleware but different access levels → potential BFLA
- Routes that use ORM directly with user input → potential mass assignment
- Routes returning rich object graphs without field filtering → excessive data exposure

## Finding Format Example

```yaml
id: RT-020
title: IDOR on /api/invoices — user A can read user B invoices
category: Authorization
severity: Critical
cwe: CWE-639
blast_radius: All users can read all invoices (full data breach)
location: src/routes/invoices.ts:34
detection_difficulty: Easy
confidence: High
kev_listed: false
epss_score: null
functional_requirements:
  - Invoices endpoint MUST verify the requesting user owns the invoice
  - Server MUST reject requests for invoice IDs that don't belong to the user
non_functional_requirements:
  - Authorization check must happen before any data retrieval
  - User ID must come from session/token, not from request parameters
acceptance_criteria:
  - User A requesting /api/invoices/{user-B-invoice-id} returns 403
  - User A requesting /api/invoices/{own-invoice-id} returns 200
```
