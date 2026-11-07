---
title: "SAML 2.0 vs OAuth 2.0 vs OpenID Connect (OIDC) Comparison"
tags: ["auth", "saml", "oauth", "oidc", "sso", "identity", "federation"]
source: "RFC 6749 (OAuth 2.0) / OpenID Connect Core 1.0 / OASIS SAML v2.0"
---

# SAML 2.0 vs OAuth 2.0 vs OpenID Connect (OIDC) Comparison
## Source & Authority
OASIS SAML v2.0 Standard; IETF RFC 6749 (The OAuth 2.0 Authorization Framework); OpenID Connect Core 1.0.

## Protocol Comparison
| Attribute | SAML 2.0 | OAuth 2.0 | OpenID Connect (OIDC) |
| :--- | :--- | :--- | :--- |
| **Core Purpose** | Federated Single Sign-On (SSO) | Delegated API Authorization | User Authentication & Identity |
| **Data Format** | XML Assertions (XML-DSig) | JSON Access Tokens (opaque/JWT) | JSON Web Tokens (`id_token`, JWT) |
| **Primary Actors** | Identity Provider (IdP) & Service Provider (SP) | Resource Owner, Client, Auth Server, Resource Server | End-User, Relying Party (RP), OpenID Provider (OP) |
| **Typical Target** | Enterprise SaaS Web Applications | API Access & Microservices | Web, Mobile & Single Page Apps (SPA) |

## Key Security Differences
- **OAuth is NOT Authentication:** OAuth 2.0 grants authorization scopes to clients; it does not reliably identify the user to the client application without OIDC.
- **OIDC Adds Identity Layer:** OIDC extends OAuth 2.0 with the `id_token` signed by the IdP, validated against the provider's JWKS endpoint (`/.well-known/jwks.json`).
- **SAML Attack Vectors:** XML Signature Wrapping (XSW), XML External Entity (XXE) injection, certificate expiration, timestamp replay.
