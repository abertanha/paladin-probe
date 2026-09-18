# OWASP Coverage Matrix

**Purpose:** Canonical crosswalk between OWASP Top 10 2025, OWASP WSTG categories, and paladin-probe reference files. This is the single source of truth for mapping — referenced by `findings-format.md` for the `standards:` field, by `threat-modeling.md` for risk taxonomy, and by agents to look up IDs before writing findings.

**Schema version:** 1
**Skill version:** paladin-probe@v3

---

## How to Use

Before writing a finding's `standards:` block:

1. Find your probe category in the tables below
2. Look up the row that matches your specific probe (e.g., IDOR → authorization-abuse.md)
3. Copy the WSTG, Top 10 2025, ASVS, API 2023, and CWE IDs
4. Apply the 5-row cap rule (see `findings-format.md`) — always include CWE first
5. See `references/findings-format.md` for closed vocabulary and regex validation

---

## Stack profile (write once, early)

After the initial repo/scope scan identifies the target stack, the agent MUST
record it in `.red-team/config.yaml` under the optional key `stack_profile:` —
it is informational only (the grader G5.3 validates just `schema_version` /
`skill_version`), and it drives the reference-loading decisions in SKILL.md's
Loading Discipline table:

```yaml
stack_profile:
  languages: [Go]
  frameworks: [chi, PostgreSQL]
  components: [K8s, S3, GitHub Actions]
```

---

## Authentication & Identity

### auth-abuse.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| Missing auth on route | 4.4.4 | A07 | V2.1.1 | API2 | CWE-306 |
| Weak password policy | 4.4.7 | A07 | V2.1.1 | API2 | CWE-521 |
| Password reset flaws | 4.4.9 | A07 | V2.5.1 | API2 | CWE-640 |
| Remember password | 4.4.5 | A07 | V2.5.3 | API2 | CWE-200 |
| Browser cache leak | 4.4.6 | A07 | V2.1.10 | API2 | CWE-525 |
| Alternative channel | 4.4.10 | A07 | V2.1.2 | API2 | CWE-308 |
| Lockout mechanism | 4.4.3 | A07 | V2.2.1 | API2 | CWE-645 |
| Default credentials | 4.4.2 | A07 | V2.1.3 | API2 | CWE-798 |
| Credential transport | 4.4.1 | A07 | V2.1.5 | API2 | CWE-319 |

### authorization-abuse.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| IDOR | 4.5.4 | A01 | V4.1.1 | API1 | CWE-639 |
| BFLA (function-level) | 4.5.2 | A01 | V4.1.3 | API1 | CWE-862 |
| Privilege escalation | 4.5.3 | A01 | V4.1.3 | API1 | CWE-269 |
| Directory traversal | 4.5.1 | A01 | V4.1.1 | API1 | CWE-22 |

### federated-auth.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| SSO bypass | 4.4.4 | A07 | V2.5.1 | API2 | CWE-287 |
| OAuth misconfiguration | — | A07 | V2.1.2 | API2 | CWE-346 |
| SAML assertion abuse | — | A07 | V2.5.2 | API2 | CWE-347 |
| OIDC token confusion | — | A07 | V2.1.2 | API2 | CWE-290 |

### identity-mgmt.md (NEW)
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| Account enumeration | 4.3.4 | A07 | V2.1.1 | API2 | CWE-204 |
| User registration | 4.3.2 | A07 | V2.1.2 | API2 | CWE-266 |
| Account provisioning | 4.3.3 | A07 | V2.1.2 | API2 | CWE-266 |
| Role definitions | 4.3.1 | A07 | V4.1.1 | API1 | CWE-269 |
| Username policy | 4.3.5 | A07 | V2.1.1 | API2 | CWE-521 |
| Offboarding gaps | — | A07 | V2.1.3 | API2 | CWE-266 |

---

## Session Management

### session-mgmt.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| Session schema | 4.6.1 | A07 | V3.1.1 | API2 | CWE-384 |
| Cookie attributes | 4.6.2 | A02 | V3.1.4 | API2 | CWE-1004 |
| Session fixation | 4.6.3 | A07 | V3.1.3 | API2 | CWE-384 |
| Exposed variables | 4.6.4 | A07 | V3.2.1 | API2 | CWE-200 |
| CSRF | 4.6.5 | A01 | V3.3.1 | API3 | CWE-352 |
| Logout functionality | 4.6.6 | A07 | V3.2.1 | API2 | CWE-613 |
| Session timeout | 4.6.7 | A07 | V3.1.1 | API2 | CWE-613 |
| Session puzzling | 4.6.8 | A07 | V3.1.2 | API2 | CWE-384 |
| Session hijacking | 4.6.9 | A07 | V3.1.4 | API2 | CWE-200 |

---

## Input Validation

### input-validation.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| SQL injection | 4.7.5 | A05 | V5.3.1 | API1 | CWE-89 |
| NoSQL injection | 4.7.5.6 | A05 | V5.3.8 | API1 | CWE-943 |
| Command injection | 4.7.12 | A05 | V5.5.1 | API1 | CWE-78 |
| LDAP injection | 4.7.6 | A05 | V5.3.6 | API1 | CWE-90 |
| XPath injection | 4.7.9 | A05 | V5.3.6 | API1 | CWE-643 |
| SSTI | 4.7.18 | A05 | V5.5.2 | API1 | CWE-1336 |
| Path traversal | 4.5.1 | A05 | V5.4.1 | API1 | CWE-22 |
| HTTP parameter pollution | 4.7.4 | A05 | V5.1.4 | API1 | CWE-235 |
| HTTP verb tampering | 4.7.3 | A05 | V5.1.5 | API1 | CWE-444 |
| Host header injection | 4.7.17 | A02 | V5.1.4 | API1 | CWE-644 |
| Format string | 4.7.13 | A05 | V5.5.3 | API1 | CWE-134 |

### xxe.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| Classic XXE | 4.7.7 | A05 | V5.5.4 | API1 | CWE-611 |
| Blind XXE (OOB) | 4.7.7 | A05 | V5.5.4 | API1 | CWE-611 |
| XInclude bypass | — | A05 | V5.5.4 | API1 | CWE-611 |
| SVG/DOCX upload | 4.10.8 | A05 | V5.5.4 | API1 | CWE-611 |
| SSRF via XXE | — | A10 | V5.5.4 | API1 | CWE-918 |
| Billion Laughs (DoS) | — | A05 | V5.5.4 | API1 | CWE-776 |

### graphql.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| Introspection | 4.12.1 | A02 | — | API5 | CWE-200 |
| SQL/NoSQL injection | 4.12.1 | A05 | V5.3.1 | API1 | CWE-89 |
| Batching attack | 4.12.1 | A02 | — | API4 | CWE-770 |
| Deep query DoS | 4.12.1 | A02 | — | API4 | CWE-770 |
| Field suggestion | 4.12.1 | A02 | — | API5 | CWE-200 |
| CSRF/CSWSH | 4.12.1 | A01 | V3.3.1 | API3 | CWE-352 |

### ssrf.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| URL fetch SSRF | 4.7.19 | A10 | V5.5.5 | API1 | CWE-918 |
| Cloud metadata | 4.7.19 | A10 | V5.5.5 | API1 | CWE-918 |
| DNS rebinding | 4.7.19 | A10 | V5.5.5 | API1 | CWE-918 |
| Blind SSRF | 4.7.19 | A10 | V5.5.5 | API1 | CWE-918 |

---

## Business Logic

### business-logic-abuse.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| Data validation | 4.10.1 | A06 | V4.2.1 | API7 | CWE-20 |
| Request forging | 4.10.2 | A06 | V4.2.2 | API7 | CWE-345 |
| Integrity checks | 4.10.3 | A06 | V4.2.3 | API7 | CWE-354 |
| Process timing | 4.10.4 | A06 | V4.2.2 | API7 | CWE-367 |
| Function limits | 4.10.5 | A06 | V4.2.2 | API7 | CWE-770 |
| Workflow circumvention | 4.10.6 | A06 | V4.2.1 | API7 | CWE-840 |
| Application misuse | 4.10.7 | A06 | V4.2.2 | API7 | CWE-840 |
| Unexpected file upload | 4.10.8 | A06 | V5.5.4 | API7 | CWE-434 |
| Malicious file upload | 4.10.9 | A06 | V5.5.4 | API7 | CWE-434 |

---

## Config & Deployment

### config-hardening.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| CORS misconfig | 4.11.7 | A02 | V14.1.1 | API5 | CWE-942 |
| Security headers | 4.2.7 | A02 | V14.2.1 | API5 | CWE-693 |
| Rate limiting gap | — | A02 | V1.1.1 | API4 | CWE-770 |
| Stack trace exposure | 4.8.2 | A10 | V7.4.1 | API8 | CWE-209 |
| Debug endpoints | 4.2.5 | A02 | V14.1.2 | API5 | CWE-215 |
| Weak cryptography | 4.9.4 | A04 | V6.2.1 | API8 | CWE-327 |

### http-attacks.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| HTTP smuggling | 4.7.15 | A02 | V14.1.3 | API8 | CWE-444 |
| Cache poisoning | — | A02 | V14.1.3 | API8 | CWE-644 |
| Open redirect | — | A01 | V14.3.1 | API8 | CWE-601 |
| HTTP/2 downgrade | — | A02 | — | API8 | CWE-444 |

### error-handling.md (NEW)
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| Stack trace | 4.8.2 | A10 | V7.4.1 | API8 | CWE-209 |
| Verbose error | 4.8.1 | A02 | V7.4.1 | API8 | CWE-215 |
| Oracle (enumeration) | 4.3.4 | A07 | V7.4.2 | API8 | CWE-204 |
| Error XSS | — | A07 | V7.1.3 | API8 | CWE-79 |
| Handler bypass | — | A02 | V7.4.3 | API8 | CWE-755 |
| Async error leak | — | A02 | V7.4.3 | API8 | CWE-755 |

### crypto.md (NEW)
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| Weak TLS | 4.9.1 | A04 | V6.1.1 | API8 | CWE-326 |
| Padding oracle | 4.9.2 | A04 | V6.2.6 | API8 | CWE-209 |
| Unencrypted channel | 4.9.3 | A04 | V6.1.2 | API8 | CWE-319 |
| Weak encryption | 4.9.4 | A04 | V6.2.1 | API8 | CWE-327 |
| JWT alg confusion | — | A04 | V6.3.1 | API8 | CWE-347 |
| Weak RNG | — | A04 | V6.3.7 | API8 | CWE-338 |
| Hardcoded key | — | A04 | V6.4.1 | API8 | CWE-798 |

---

## Client-Side

### client-side.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| DOM XSS | 4.11.1 | A07 | V7.1.3 | API8 | CWE-79 |
| JavaScript execution | 4.11.2 | A07 | V7.1.1 | API8 | CWE-94 |
| HTML injection | 4.11.3 | A07 | V7.1.2 | API8 | CWE-80 |
| URL redirect | 4.11.4 | A01 | V14.3.1 | API8 | CWE-601 |
| CSS injection | 4.11.5 | A07 | V7.1.4 | API8 | CWE-79 |
| Resource manipulation | 4.11.6 | A07 | V7.1.5 | API8 | CWE-749 |
| CORS | 4.11.7 | A02 | V14.1.1 | API8 | CWE-942 |
| Clickjacking | 4.11.9 | A02 | V14.2.2 | API8 | CWE-1021 |
| WebSockets | 4.11.10 | A02 | V14.1.4 | API8 | CWE-1385 |
| Web Messaging | 4.11.11 | A07 | V7.1.6 | API8 | CWE-346 |
| Browser storage | 4.11.12 | A07 | V3.2.1 | API8 | CWE-312 |
| XSSI | 4.11.13 | A07 | V7.1.7 | API8 | CWE-200 |

---

## Supply Chain & Dependencies

### dependency-audit.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| npm audit | — | A03 | V14.2.6 | API8 | CWE-1395 |
| Known CVEs | — | A03 | V14.2.6 | API8 | CWE-1104 |
| Malicious package | — | A03 | V14.2.6 | API8 | CWE-1395 |

### ci-cd.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| Pipeline injection | — | A08 | V14.2.5 | API8 | CWE-444 |
| Secret exposure | — | A08 | V14.2.4 | API8 | CWE-312 |
| Artifact poisoning | — | A03 | V14.2.6 | API8 | CWE-1395 |
| CI/CD privesc | — | A08 | V4.1.3 | API1 | CWE-269 |
| Environment separation | — | A08 | V14.2.5 | API8 | CWE-841 |
| Action version pinning | — | A03 | V14.2.6 | API8 | CWE-1395 |

---

## Cloud-Native

### cloud-native.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| Container escape | — | A02 | — | — | CWE-250 |
| K8s RBAC abuse | — | A01 | V4.1.3 | API1 | CWE-269 |
| Pod misconfig | — | A02 | — | — | CWE-732 |
| Sidecar bypass | — | A02 | V14.1.5 | — | CWE-444 |
| Service mesh | — | A02 | V14.1.5 | — | CWE-344 |
| Serverless | — | A02 | — | — | CWE-250 |
| IaC flaws | — | A02 | V14.2.1 | — | CWE-732 |
| Cloud metadata | 4.7.19 | A10 | V5.5.5 | API1 | CWE-918 |

---

## Resource Exhaustion

### resource-exhaustion.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| ReDoS | — | A02 | V5.1.3 | API4 | CWE-1333 |
| Large payloads | — | A02 | V5.1.5 | API4 | CWE-770 |
| Pagination abuse | 4.10.5 | A06 | V4.2.2 | API4 | CWE-770 |
| Connection exhaustion | — | A02 | V1.1.1 | API4 | CWE-770 |

---

## Secrets & Sensitive Data

### secrets-exposure.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| Hardcoded secrets | 4.2.4 | A02 | V6.4.1 | API8 | CWE-798 |
| Git history | — | A08 | V14.2.4 | API8 | CWE-312 |
| Source maps | — | A02 | V14.2.1 | API8 | CWE-200 |
| Bundle inspection | — | A02 | V14.2.1 | API8 | CWE-200 |

---

## Insecure Deserialization

### insecure-deserialization.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| Python pickle | — | A05 | V5.5.6 | API1 | CWE-502 |
| PHP unserialize | — | A05 | V5.5.6 | API1 | CWE-502 |
| Java deserialization | — | A05 | V5.5.6 | API1 | CWE-502 |
| Node.js serialize | — | A05 | V5.5.6 | API1 | CWE-502 |
| Ruby YAML | — | A05 | V5.5.6 | API1 | CWE-502 |

---

## LLM / AI

### llm-ai.md
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| Prompt injection (direct) | — | A06 | — | — | CWE-94 |
| Prompt injection (indirect) | — | A03 | — | — | CWE-94 |
| Jailbreaking | — | A06 | — | — | — |
| Data leakage | — | A06 | V7.4.1 | — | CWE-200 |
| RAG poisoning | — | A03 | — | — | CWE-94 |
| Tool abuse | — | A08 | V14.2.6 | — | CWE-284 |
| Agent hijacking | — | A08 | V4.1.3 | — | CWE-269 |
| Model extraction | — | A06 | — | — | CWE-200 |
| API key exposure | — | A02 | V6.4.1 | API8 | CWE-798 |

---

## Logging & Alerting

### logging-alerting.md (NEW)
| Probe | WSTG | Top 10 2025 | ASVS | API 2023 | CWE |
|-------|------|-------------|------|----------|-----|
| Audit log gaps | — | A09 | V7.1.1 | API8 | CWE-778 |
| Log injection | — | A09 | V7.1.2 | — | CWE-223 |
| Log tampering | — | A09 | V7.2.1 | — | CWE-776 |
| Alerting thresholds | — | A09 | V7.3.1 | API4 | CWE-778 |
| Log data leakage | — | A09 | V7.1.4 | — | CWE-532 |
| Log transport security | — | A09 | V7.2.2 | — | CWE-319 |

---

## Reverse Lookup

### WSTG Section → Reference File

| WSTG | Title | Reference |
|------|-------|-----------|
| 4.1 | Information Gathering | `attack-surface-mapping.md` |
| 4.2 | Configuration & Deployment | `config-hardening.md` |
| 4.3 | Identity Management | `identity-mgmt.md` (NEW) |
| 4.4 | Authentication | `auth-abuse.md`, `federated-auth.md` |
| 4.5 | Authorization | `authorization-abuse.md` |
| 4.6 | Session Management | `session-mgmt.md` |
| 4.7 | Input Validation | `input-validation.md`, `xxe.md`, `graphql.md`, `ssrf.md` |
| 4.8 | Error Handling | `error-handling.md` (NEW) |
| 4.9 | Weak Cryptography | `crypto.md` (NEW) |
| 4.10 | Business Logic | `business-logic-abuse.md` |
| 4.11 | Client-Side | `client-side.md` |
| 4.12 | API Testing | `graphql.md` |
| — | A09 Security Logging & Alerting | `logging-alerting.md` (NEW) |

### OWASP Top 10 2025 → Reference File

| A0X | Title | Primary Reference(s) |
|-----|-------|---------------------|
| A01 | Broken Access Control | `authorization-abuse.md` |
| A02 | Security Misconfiguration | `config-hardening.md`, `error-handling.md`, `http-attacks.md`, `cloud-native.md` |
| A03 | Supply Chain Failures | `dependency-audit.md`, `ci-cd.md` |
| A04 | Cryptographic Failures | `crypto.md` |
| A05 | Injection | `input-validation.md`, `xxe.md`, `graphql.md`, `insecure-deserialization.md` |
| A06 | Insecure Design | `business-logic-abuse.md`, `llm-ai.md` |
| A07 | Authentication Failures | `auth-abuse.md`, `federated-auth.md`, `identity-mgmt.md`, `session-mgmt.md` |
| A08 | Data Integrity Failures | `ci-cd.md`, `secrets-exposure.md` |
| A09 | Logging & Alerting | `logging-alerting.md` |
| A10 | Mishandling Exceptional Conditions | `error-handling.md`, `ssrf.md` |

### Application Security (no WSTG/Top 10)

| Category | Reference |
|----------|-----------|
| Threat modeling | `threat-modeling.md` (STRIDE) |
| Attack surface mapping | `attack-surface-mapping.md` |
| Resource exhaustion | `resource-exhaustion.md` |
| Dependency audit | `dependency-audit.md` |
| Findings format | `findings-format.md` |
| Cross-skill contract | `cross-skill-contract.md` |
| Self-audit grader fix routines | `grader-fixes.md` |
