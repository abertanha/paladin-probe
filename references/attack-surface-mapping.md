# Attack Surface Mapping

Run during RECON phase. Build a complete picture of what can be attacked before
deciding what to probe. This is the foundation of every subsequent phase.

---

## Static Recon (Codebase)

### Route Discovery by Framework

Read route registration patterns to enumerate all endpoints:

| Framework | Files to scan | Pattern |
|-----------|--------------|---------|
| Express / Next.js | `app/api/**/route.ts`, `routes/*.ts`, `router.*` | `router.get(`, `router.post(`, `app.get(`, `export async function GET(` |
| FastAPI | `app/routers/*.py`, `main.py` | `@router.get(`, `@app.post(`, `@api_router.include_router(` |
| Django | `urls.py` per app | `path(`, `re_path(`, `url(` |
| Spring Boot | `@RestController` classes | `@GetMapping`, `@PostMapping`, `@RequestMapping` |
| Rails | `config/routes.rb` | `get `, `post `, `resources :` |
| Gin (Go) | `router.go`, `routes/*.go` | `router.GET(`, `router.POST(`, `v1.GET(` |

### For each discovered route, extract:

1. **Handler source location** — find handler function, note file + line
2. **Middleware stack** — what runs before the handler? (auth, validation, rate-limit, CSRF)
3. **Route-level vs handler-level** — is middleware applied at route group level or per-handler?
4. **Input parameters** — route params (`:id`), query strings, body schema, headers
5. **Content type accepted** — JSON, form-data, XML, multipart, protobuf

### Route Classification

| Category | Criterion | Example |
|----------|-----------|---------|
| Public | No auth middleware | `/health`, `/login`, `/docs` |
| Authenticated | Session or bearer required | `/api/v1/partner/profiles/search` |
| Admin | Role check before handler | `/admin/users`, `/tenants/search` |
| Internal | Service-account only auth | `/api/v1/internal/ingest` |

---

## Active Recon (Runtime)

When consent allows live requests, supplement static enumeration with:

### Content Discovery

| Tool | Purpose | Command |
|------|---------|---------|
| **ffuf** | Directory/file brute-force | `ffuf -u https://target/FUZZ -w wordlist.txt -ac` |
| **feroxbuster** | Recursive content discovery | `feroxbuster -u https://target/ -w wordlist.txt` |
| **dirsearch** | Multi-extension brute-force | `dirsearch -u https://target/ -e php,asp,json` |
| **katana** | JS-based URL extraction | `katana -u https://target/ -jc -kf` |

### API Surface Enumeration

| Method | Technique | Signal |
|--------|-----------|--------|
| OpenAPI/Swagger | Check `/docs`, `/api/docs`, `/openapi.json`, `/swagger.json` | Schema leak, hidden endpoints |
| GraphQL | Check `/graphql`, `/api/graphql`, send `{__typename}` | Introspection leak |
| gRPC | Check reflection endpoint, port 50051 | Service descriptor leak |
| SOAP | Check `/wsdl`, `/soap`, `?wsdl` | WSDL disclosure |

### JS Analysis

For SPAs and Next.js apps, extract endpoints from client-side bundles:

```bash
# Download JS bundle, extract endpoint strings
curl -s https://target/_next/static/chunks/pages/*.js | grep -oP '"/api/[^"]+"'
```

Or use specialized tools: `LinkFinder`, `jsmon`, `xnLinkFinder`.

### Vhost Enumeration

If the app sits behind a reverse proxy, check for hidden virtual hosts:

```bash
# Each non-matching vhost may expose a different app
ffuf -u https://target -w vhosts.txt -H "Host: FUZZ.target.com" -fs [baseline_size]
```

---

## Auth Surface Mapping

Order endpoints by privilege level to find authz gaps:

```yaml
auth_surface:
  tiers:
    - tier: 1  # Public — highest risk
      routes:
        - /login
        - /health
        - /api/docs
    - tier: 2  # Authenticated user
      routes:
        - /consulta
        - /api/v1/partner/profiles/search
    - tier: 3  # Admin
      routes:
        - /admin/partners
        - /financeiro
    - tier: 4  # Internal (service-to-service)
      routes:
        - /api/v1/internal/ingest
```

---

## Parameter Discovery

Identify all parameters each route accepts:

| Approach | Example |
|----------|---------|
| Read body schema validation | `z.object({ email: z.string().email() })` |
| Read TypeScript/Java types | `interface CreateOrderPayload { ... }` |
| Read handler destructuring | `const { email, password } = req.body` |
| Read handler raw access | `req.body.amount`, `input.get("role")` |
| Send parameter fuzzing | `ffuf -u https://target/api/endpoint?FUZZ=1 -w params.txt` |
| Tool: **arjun** | `arjun -u https://target/api/endpoint` |
| Tool: **paramspider** | `python3 paramspider.py -d target.com` |

---

## Dependency & Config Audit

### Dependency Scan Order

1. Parse lock file: `yarn.lock`, `package-lock.json`, `Cargo.lock`, `Gemfile.lock`,
   `requirements.txt`, `go.sum`, `composer.lock`
2. Count total deps, direct vs transitive
3. Check against OSV.dev for known vulns
4. Check against CISA KEV for actively exploited vulns
5. Score by EPSS probability
6. Flag typo-squatting packages (similar names to popular libs)

### Config Items to Audit

| Category | What to check |
|----------|---------------|
| CORS | `origin: *`, `credentials: true`, dynamic origin reflection |
| Security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Session | Secure/HttpOnly/SameSite cookie flags, TTL, rolling vs absolute expiry |
| Rate limiting | Bypass via `X-Forwarded-For`, per-IP vs per-user, sliding vs fixed window |
| Error handling | Global error handler vs raw stack traces, custom error codes vs system errors |
| Debug endpoints | `/debug`, `/__inspect`, `/admin/panel`, `/dev` persist in production? |
| Env vars | Required vs optional, defaults, documented in `.env.example` |

---

## Output Schema

Written to `.red-team/surface.md`:

```yaml
date: See REPORT.md  # Single source of truth — do not add probe_date here
mode: dry-run

endpoints:
  - path: /api/login
    method: POST
    handler: src/routes/auth.ts:login
    middleware: [rateLimiter, bodyParser]
    auth: public
    params: { email: string, password: string }
    content_type: application/json
  - path: /api/admin/users
    method: GET
    handler: src/routes/admin.ts:listUsers
    middleware: [authMiddleware, adminGuard]
    auth: admin
    params: { page: number, limit: number, sort: string }

surface:
  total_endpoints: 12
  public: 3
  authenticated: 5
  admin: 3
  internal: 1
  untested_params: 5      # routes without schema validation

auth:
  strategy: jwt
  token_location: Authorization: Bearer
  secret_source: env.JWT_SECRET
  expiry: 15m
  refresh: 7d
  roles: [user, moderator, admin]
  mfa_required: false

config:
  cors:
    origin: "*"
    credentials: true
    vulnerable: true        # flagged by probe
  security_headers:
    csp: missing
    hsts: present
    xfo: present
    xcto: present
    rp: missing

dependencies:
  total: 142
  direct: 85
  transitive: 57
  outdated: 3
  known_vulns: 1
  kev_listed: 0
  lock_file: yarn.lock
```

---

## Surface Update Protocol

The attack surface is the baseline snapshot for differential analysis. On each
new probe session:

1. Compare current endpoint list against previous `surface.md`
2. Flag **new endpoints** (unreviewed, may lack auth/validation)
3. Flag **removed endpoints** (may leave dangling references)
4. Flag **changed middleware stack** (auth downgraded?)
5. Flag **changed config** (CORS relaxed? rate limit removed?)
6. Flag **changed dependencies** (new vulns added, old ones patched?)

This differential is written to the session log for the probe phase to prioritize.
