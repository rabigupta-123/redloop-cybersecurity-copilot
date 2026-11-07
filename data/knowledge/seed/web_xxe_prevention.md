---
title: "XML External Entity (XXE) Injection & Parser Hardening"
tags: ["web", "xxe", "xml", "owasp", "cwe611"]
source: "OWASP Top 10 A05:2021 / CWE-611 / W3C XML 1.0"
---

# XML External Entity (XXE) Injection & Parser Hardening
## Source & Authority
OWASP Top 10:2021 A05; Common Weakness Enumeration CWE-611; W3C XML 1.0 Recommendation.

## Vulnerability Mechanics
When an XML parser processes untrusted input containing external entity declarations (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`), the parser resolves the entity, allowing local file disclosure, SSRF, or denial of service (Billion Laughs entity expansion).

## Remediation Protocol
Disable Document Type Definition (DTD) processing completely in XML parsers:
- **Python (defusedxml / lxml):** Use `defusedxml` package. For `lxml`: `parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)`.
- **Java (DOM / SAX / DocumentBuilder):**
  ```java
  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
  dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
  dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
  dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
  ```
- **Prefer Safer Formats:** Transition API payloads to standard JSON or Protocol Buffers.
