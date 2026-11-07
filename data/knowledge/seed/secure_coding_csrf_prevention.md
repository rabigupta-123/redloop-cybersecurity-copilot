---
title: "Secure Coding: Cross-Site Request Forgery (CSRF) Defenses"
tags: ["secure-coding", "csrf", "cookies", "samesite", "tokens"]
source: "OWASP Cross-Site Request Forgery Prevention Cheat Sheet / RFC 6265bis"
---

# Secure Coding: Cross-Site Request Forgery (CSRF) Defenses
## Source & Authority
OWASP CSRF Prevention Cheat Sheet; IETF RFC 6265bis (Cookies: HTTP State Management Mechanism).

## Primary Defenses
1. **SameSite Cookie Attribute:**
   - `SameSite=Strict`: Cookies are never sent on cross-site requests.
   - `SameSite=Lax`: Cookies sent on top-level cross-site GET navigations, but blocked on POST, PUT, DELETE.
2. **Anti-CSRF Synchronizer Tokens:** Generate unique, cryptographically random tokens per session; embed token in forms or AJAX headers (`X-CSRF-Token`); verify token matches session state on state-changing requests.
3. **Custom Request Headers:** For APIs, requiring custom headers (e.g. `X-Requested-With`) blocks simple cross-origin form submissions.
