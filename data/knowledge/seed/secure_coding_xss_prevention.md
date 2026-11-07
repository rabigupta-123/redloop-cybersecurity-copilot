---
title: "Secure Coding: Context-Aware Output Encoding for XSS Prevention"
tags: ["secure-coding", "xss", "encoding", "csp", "web"]
source: "OWASP Cross-Site Scripting Prevention Cheat Sheet / CWE-79"
---

# Secure Coding: Context-Aware Output Encoding for XSS Prevention
## Source & Authority
OWASP Cross-Site Scripting (XSS) Prevention Cheat Sheet; CWE-79.

## Context-Aware Encoding Rules
1. **HTML Body Context:** Encode `&` to `&amp;`, `<` to `&lt;`, `>` to `&gt;`, `"` to `&quot;`, `'` to `&#x27;`.
2. **HTML Attribute Context:** Use strict alphanumeric allowlisting or attribute encoding. Never place untrusted data in `href="javascript:..."` or event handlers (`onclick="..."`).
3. **JavaScript Context:** Pass data via `JSON.parse()` inside a `<script type="application/json">` block, never through direct string concatenation.
4. **Sanitize Rich Text:** Use vetted libraries like `DOMPurify` to clean HTML input before rendering.
