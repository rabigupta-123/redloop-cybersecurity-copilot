---
title: "Clickjacking (UI Redressing) & Frame Busting Defenses"
tags: ["web", "clickjacking", "csp", "headers", "owasp"]
source: "OWASP Clickjacking Defense Cheat Sheet / W3C CSP Level 3"
---

# Clickjacking (UI Redressing) & Frame Busting Defenses
## Source & Authority
OWASP Clickjacking Defense Cheat Sheet; W3C Content Security Policy Level 3.

## Mechanics & Defenses
Clickjacking tricks a user into clicking invisible or disguised UI elements by loading the target page in a transparent `<iframe>` overlaid on an attacker-controlled site.

## Standards-Compliant Headers
1. **Content-Security-Policy (CSP) `frame-ancestors` Directive (Modern Standard):**
   - Disallow framing completely: `Content-Security-Policy: frame-ancestors 'none';`
   - Allow framing by same origin only: `Content-Security-Policy: frame-ancestors 'self';`
   - Allow specific trusted partners: `Content-Security-Policy: frame-ancestors 'self' https://trusted.example.com;`
2. **X-Frame-Options (Legacy Fallback):**
   - `X-Frame-Options: DENY`
   - `X-Frame-Options: SAMEORIGIN`
