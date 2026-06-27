# 00 — Foundations

Before studying any protocol, you must internalise the foundational models that every auth system inherits. This module establishes the vocabulary, threat taxonomy, and architectural primitives used throughout the series.

---

## 1. The AuthN / AuthZ Dichotomy

Every security decision sits on one side of this line:

```
┌─────────────────────────────────────────────────────────────┐
│                    REQUEST LIFECYCLE                         │
│                                                             │
│  ┌──────────┐     ┌──────────────┐     ┌─────────────────┐  │
│  │          │     │              │     │                 │  │
│  │  HTTP    │────>│  AuthN       │────>│  AuthZ          │  │
│  │  Request │     │  "Who are    │     │  "What may you  │  │
│  │          │     │   you?"      │     │   do?"          │  │
│  └──────────┘     └──────────────┘     └─────────────────┘  │
│                           │                     │           │
│                           ▼                     ▼           │
│                     Credential              Policy         │
│                     Validation              Evaluation      │
│                     401 / 200              403 / 200       │
└─────────────────────────────────────────────────────────────┘
```

| Aspect | Authentication (AuthN) | Authorization (AuthZ) |
|--------|------------------------|----------------------|
| Question | "Who are you?" | "What may you do?" |
| Mechanism | Password, biometric, token, certificate | RBAC, ABAC, ACL, scope, policy |
| Failure | `401 Unauthorized` | `403 Forbidden` |
| State change | Login / Logout | Role change, permission grant |
| Granularity | Binary (authenticated / not) | Continuous (read vs write vs admin) |
| Temporal | Session lifetime | Per-request evaluation |

---

## 2. The Three Factors + Extensions

```
  FACTOR CATEGORIES                      EXAMPLES
  ════════════════                      ════════

  ┌───────────────────┐
  │  KNOWLEDGE        │──► Password, PIN, security question, passphrase
  │  "Something you   │
  │   know"           │
  └───────────────────┘

  ┌───────────────────┐
  │  POSSESSION       │──► TOTP token, SMS code, hardware key (YubiKey),
  │  "Something you   │    smart card, phone (push notification)
  │   have"           │
  └───────────────────┘

  ┌───────────────────┐
  │  INHERENCE        │──► Fingerprint, Face ID, iris scan, voice,
  │  "Something you   │    palm vein, gait, typing rhythm
  │   are"            │
  └───────────────────┘

  ┌───────────────────┐
  │  LOCATION         │──► Geo-IP, GPS, network subnet, Bluetooth beacon
  │  "Where you are"  │    (risk signal, not standalone)
  └───────────────────┘

  ┌───────────────────┐
  │  BEHAVIOR         │──► Typing cadence, mouse movement, browsing pattern
  │  "How you act"    │    (continuous authentication signal)
  └───────────────────┘
```

**MFA requires ≥ 2 factors from ≥ 2 distinct categories.** Two passwords (both knowledge) is NOT MFA.

---

## 3. Protocol Taxonomy

Every auth protocol can be classified along three axes:

```
Axis 1: Who holds the credential?
├── User-memorised     (password, PIN)
├── User-possessed     (phone, hardware key)
├── Client-held        (OAuth client_secret, API key)
└── Mutual             (mTLS — both sides prove identity)

Axis 2: How is it transported?
├── HTTP Header        (Basic, Bearer, Digest)
├── Cookie             (Session ID)
├── Request Body       (OAuth token endpoint)
├── URL fragment       (Implicit grant — legacy)
└── Out-of-band        (SAML Artifact, Device Code)

Axis 3: What is the trust model?
├── Shared secret      (symmetric — HS256, Basic Auth)
├── Public-key         (asymmetric — RS256, mTLS, WebAuthn)
└── Delegated          (OAuth — AS issues token, RS trusts AS)
```

---

## 4. State Machines

### Session Lifecycle

```
       ┌──────────┐
       │  PENDING │  (no credentials presented)
       └────┬─────┘
            │ POST /login { credentials }
            ▼
     ┌──────────────┐
     │ VALIDATING   │  (credentials checked — may involve IdP)
     └──────┬───────┘
            │
     ┌──────┴───────┐
     │              │
     ▼              ▼
┌──────────┐  ┌──────────┐
│ ACTIVE   │  │ REJECTED │  (401 — may retry)
└────┬─────┘  └──────────┘
     │ timeout / logout / revoke
     ▼
┌──────────┐
│ EXPIRED  │  (session destroyed server-side)
└──────────┘
```

### Token Lifecycle

```
       ┌──────────┐
       │ UNBORN   │  (not yet issued)
       └────┬─────┘
            │ Issue
            ▼
       ┌──────────┐
       │ ACTIVE   │  (within exp window)
       └────┬─────┘
            │
     ┌──────┴───────┐
     │              │
     ▼              ▼
┌──────────┐  ┌──────────┐
│ EXPIRED  │  │ REVOKED  │  (added to blocklist)
└──────────┘  └──────────┘
     │
     ▼
┌──────────┐
│ ROTATED  │  (refresh token replaced)
└──────────┘
```

---

## 5. Trust Models

### Direct Trust

```
Client ──── shared secret ────► Server
```

- Both sides share a symmetric secret
- Examples: Basic Auth, API key, HS256 JWT
- Problem: every verifier must know the secret

### Third-Party Trust (Brokered)

```
Client ──► Auth Server ──token──► API Server
            (issuer)              (verifier)
```

- AS issues signed token, RS verifies signature using public key
- No shared secret between Client and RS
- Examples: OAuth 2.0, OIDC, SAML

### Web of Trust

```
Client ──► IdP A ──► IdP B ──► API
```

- Chain of assertions
- Rare in web auth; common in blockchain / PKI

---

## 6. The STRIDE Threat Model (Applied to Auth)

| Threat | Auth Example | Attack Vector | Defense |
|--------|-------------|---------------|---------|
| **S**poofing | Attacker impersonates user | Stolen password, stolen session cookie | MFA, biometrics, device binding |
| **T**ampering | Attacker modifies JWT payload | JWT `alg=none`, token injection | Signatures, validate `alg` |
| **R**epudiation | User claims "I didn't do that" | No audit trail | Signed audit logs, webhooks |
| **I**nformation Disclosure | Token leaked in logs | Verbose logging, shared snippet tools | Never log tokens, structured logging |
| **D**enial of Service | Brute force login | Botnet credential stuffing | Rate limiting, CAPTCHA, WAF |
| **E**levation of Privilege | User edits `role: user` → `role: admin` | Missing AuthZ check | Authorize every request |

---

## 7. Architectural Decision: Sessions vs. Tokens

```
┌────────────────────────────────────────────────────────────────────┐
│                      SESSIONS                 │     TOKENS         │
│                                              │                    │
│  Storage          Server-side (Redis, DB)    │ Client-held        │
│  Revocation       Instant (delete session)   │ TTL / blocklist    │
│  Scaling          Shared session store       │ Stateless (any      │
│                    needed                    │ service can verify) │
│  Payload          Minimal (session ID only) │ Rich (claims)       │
│  Mobile/SPA       Cookie challenges          │ Bearer header works │
│  Microservices    Gateway session lookup     │ Verify individually │
│  Latency          +1 DB round-trip           │ Cryptographic       │
│                                              │ verification        │
└────────────────────────────────────────────────────────────────────┘
```

| Use SESSIONS when                          | Use TOKENS when                          |
|--------------------------------------------|------------------------------------------|
| You need instant revocation                | You need stateless verification          |
| You run a monolithic web app               | You have many microservices              |
| You want simple CSRF protection            | Your clients are mobile / SPA            |
| You need to throttle concurrent sessions   | You need low latency (no DB call)        |
| You already have Redis                     | You need to pass identity across orgs    |

---

## 8. Cryptographic Primitives Cheat Sheet

| Primitive | What it does | Used In | Key type |
|-----------|-------------|---------|----------|
| **SHA-256** | One-way hash (collision-resistant) | JWT payload integrity, cert fingerprints | None |
| **HMAC-SHA256** | Keyed hash (verifies integrity + authenticity) | JWT HS256, AWS SigV4 | Symmetric |
| **RSA** | Asymmetric encryption & signing | JWT RS256, TLS, SAML | Asymmetric (public/private) |
| **ECDSA** | Asymmetric signing (smaller keys) | JWT ES256, WebAuthn | Asymmetric (P-256, P-384) |
| **EdDSA** | Asymmetric signing (fast, modern) | JWT EdDSA, SSH | Asymmetric (Ed25519) |
| **AES-256-GCM** | Symmetric encryption + auth tag | Cookie encryption, token encryption | Symmetric |
| **bcrypt** | Password hashing (slow, adaptive) | Password storage | None (salt + cost) |
| **Argon2id** | Password hashing (memory-hard) | Password storage | None (salt + cost + memory) |
| **X.509** | Certificate standard (binds identity to public key) | mTLS, SAML, HTTPS | Asymmetric |

---

## 9. The Auth Stack (OSI-like Model)

```
Layer 4: Application Protocols    OAuth 2.0, OIDC, SAML, CAS, LDAP
Layer 3: Token / Assertion Format JWT, SAML Assertion, Kerberos Ticket
Layer 2: Cryptographic Binding    JWS, XML-DSig, TLS Channel Binding
Layer 1: Transport Security       TLS 1.2+, mTLS, HTTPS
```

Each layer depends on the one below it. Breaking any layer breaks security.

---

## 10. Checkpoint

- [ ] Can you explain the difference between AuthN and AuthZ with a concrete HTTP response code?
- [ ] Can you name all three primary authentication factors and give two examples each?
- [ ] Can you describe the session state machine (4 states)?
- [ ] Can you apply STRIDE to identify threats in an auth system?
- [ ] Can you decide when to use sessions vs. tokens for a given architecture?
- [ ] Can you trace which cryptographic primitive belongs to which protocol layer?
