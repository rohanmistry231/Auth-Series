<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://img.shields.io/badge/Auth_Series-000000?style=for-the-badge&logo=openid&logoColor=white">
    <img alt="Auth Series" src="https://img.shields.io/badge/Auth_Series-000000?style=for-the-badge&logo=openid&logoColor=white">
  </picture>
</p>

<p align="center">
  <em>A comprehensive, zero-fluff deep dive into every authentication & authorization mechanism that powers the modern web.</em>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT License"></a>
  <a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square" alt="PRs Welcome"></a>
  <a href="#topics"><img src="https://img.shields.io/badge/18-topics-important?style=flat-square" alt="18 Topics"></a>
  <a href="#topics"><img src="https://img.shields.io/badge/code-Python_•_TypeScript_•_Go-blue?style=flat-square" alt="Languages"></a>
  <a href="GLOSSARY.md"><img src="https://img.shields.io/badge/glossary-60+_terms-blue?style=flat-square" alt="Glossary"></a>
  <a href="CODE_OF_CONDUCT.md"><img src="https://img.shields.io/badge/code_of_conduct- Contributor_Covenant-yellow?style=flat-square" alt="Code of Conduct"></a>
</p>

---

## Overview

**Auth Series** is a structured, practical reference for engineers who want to truly understand authentication and authorization — not just use a library. Each topic folder contains:

- **Deep-dive README** — how it works, wire protocols, security considerations, trade-offs
- **Multi-language code** — production-style implementations in Python, TypeScript, and Go
- **Cheat sheets** — one-page quick references for daily use
- **Resources** — RFCs, papers, tools, and further reading

Whether you're a backend engineer integrating OAuth 2.0 for the first time, a security engineer auditing SAML assertions, or a student learning how JWT signatures work at the byte level — this repo has you covered.

If you're new to auth concepts, start with [00-foundations](00-foundations/). For quick lookups, check the [GLOSSARY](GLOSSARY.md).

---

## Learning Path

```
                         ┌──────────────────────────────┐
                         │   00. Foundations            │
                         │   (AuthN vs AuthZ, factors,  │
                         │    STRIDE threat model)      │
                         └──────────────┬───────────────┘
                                        │
                     ┌──────────────────▼──────────────────┐
                     │  Start Here                         │
                     │  01. Basic Auth                     │
                     │  02. Session & Cookies              │
                     │  03. JWT (JSON Web Tokens)          │
                     └──────────────────┬──────────────────┘
                                        │
                     ┌──────────────────▼──────────────────┐
                     │  Core Protocols                     │
                     │  04. OAuth 2.0                      │
                     │  05. OpenID Connect                 │
                     │  06. SAML 2.0                       │
                     └──────────────────┬──────────────────┘
                                        │
          ┌─────────────────────────────┼─────────────────────────────┐
          ▼                             ▼                             ▼
  ┌──────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
  │  Token Auth      │     │  Enterprise ID       │     │  Modern Auth         │
  │  07. API Keys    │     │  11. LDAP/AD         │     │  09. MFA             │
  │  13. Bearer      │     │  15. CAS             │     │  10. Passwordless    │
  │  14. Digest      │     │  08. SSO             │     │  12. Social Login    │
  └──────────────────┘     └──────────────────────┘     └──────────┬───────────┘
                                                                   │
                                                                   ▼
                                                       ┌──────────────────────┐
                                                       │  Patterns & Security │
                                                       │  16. Auth Patterns   │
                                                       │  17. Security        │
                                                       └──────────────────────┘
```

---

## Topics

| # | Topic | Read | Java | Python | TypeScript | Go | Rust |
|---|-------|------|------|--------|------------|-----|------|
| 00 | [Foundations](00-foundations/) | ✅ | — | — | — | — | — |
| 01 | [Basic Authentication](01-basic-auth/) | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| 02 | [Session & Cookies](02-session-cookies/) | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| 03 | [JWT (JSON Web Tokens)](03-jwt/) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 04 | [OAuth 2.0](04-oauth2/) | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| 05 | [OpenID Connect](05-oidc/) | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| 06 | [SAML 2.0](06-saml/) | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| 07 | [API Keys](07-api-keys/) | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| 08 | [Single Sign-On (SSO)](08-sso/) | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| 09 | [Multi-Factor Auth (MFA)](09-mfa/) | ✅ | ✅ | ✅ | ✅ | — | — |
| 10 | [Passwordless Auth](10-passwordless/) | ✅ | ✅ | ✅ | ✅ | — | — |
| 11 | [LDAP / Active Directory](11-ldap/) | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| 12 | [Social Login](12-social-login/) | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| 13 | [Bearer Tokens](13-bearer-token/) | ✅ | ✅ | ✅ | ✅ | — | — |
| 14 | [Digest Access Auth](14-digest-auth/) | ✅ | ✅ | ✅ | — | — | — |
| 15 | [Central Auth Service (CAS)](15-cas/) | ✅ | ✅ | ✅ | ✅ | — | — |
| 16 | [Auth Patterns & Architectures](16-auth-patterns/) | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| 17 | [Security](17-security/) | ✅ | ✅ | ✅ | ✅ | ✅ | — |

---

## Supplementary

| Directory | Purpose |
|-----------|---------|
| [cheat-sheets/](cheat-sheets/) | One-page quick references for every topic |
| [GLOSSARY.md](GLOSSARY.md) | 60+ authentication terms with plain-English definitions |
| [code-examples/](code-examples/) | Standalone runnable snippets (language-agnostic cross-cuts) |
| [resources/](resources/) | RFCs, books, papers, talks, and tools |

---

## How to Use This Repo

### By Topic (Recommended)
Pick a topic folder and start with the `README.md`. Then explore the code in your language of choice. Each README is self-contained — no prerequisite reading beyond the numbered order.

### By Language
Each topic folder contains language subdirectories:
```
04-oauth2/
├── python/        # FastAPI + httpx examples
├── typescript/    # Express + NextAuth-style examples
└── go/            # net/http + oauth2 examples
```

### As a Reference
The [cheat-sheets/](cheat-sheets/) folder is designed for daily use — print them, pin them, grep them.

---

## Prerequisites

You should be comfortable with:
- HTTP fundamentals (methods, headers, status codes)
- Basic cryptography concepts (hashing, symmetric/asymmetric encryption, signatures)
- At least one of: Python, TypeScript, or Go

---

## Contributing

Contributions are welcome and encouraged. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Topic request process
- Code style conventions per language
- Pull request workflow
- Adding a new language to existing topics

All contributors must adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## License

MIT — see [LICENSE](LICENSE). Free for personal, educational, and commercial use.
