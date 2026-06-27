# SSO — Cheat Sheet

## Core Principle

One authentication → many applications. User logs in once, accesses multiple services without re-entering credentials.

## Comparison

| Protocol | Token Format | Transport | Best For |
|----------|-------------|-----------|----------|
| **SAML** | XML (signed) | Browser redirect + POST | Enterprise, AD-integrated |
| **OIDC** | JWT (signed) | Browser redirect + API | Modern web, mobile |
| **CAS** | Ticket string | Browser redirect | Academic, Java ecosystem |

## Token Exchange Pattern

```
Central Auth Server          App 1                   App 2
     │                        │                       │
     │  Issue SSO token       │                       │
     │<───────────────────────│                       │
     │                        │                       │
     │  POST /token/exchange  │                       │
     │  { sso_token }         │                       │
     │───────────────────────>│                       │
     │                        │                       │
     │  ← JWT for App 1       │                       │
     │                        │                       │
     │                        │  POST /token/exchange │
     │                        │  { sso_token }        │
     │                        │──────────────────────>│
     │                        │                       │
     │                        │  ← JWT for App 2     │
```

## SSO Cookie

| Attribute | Setting |
|-----------|---------|
| Domain | `.yourdomain.com` (shared across subdomains) |
| HttpOnly | `true` |
| Secure | `true` |
| SameSite | `Lax` |

## Security

- **SSO token**: single-use, short TTL (5 min)
- **App-specific JWTs**: short TTL (15 min), audience-scoped
- **Central logout**: invalidate SSO session → all apps log out
