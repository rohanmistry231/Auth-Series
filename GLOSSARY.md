# Glossary

Common authentication and authorization terms with plain-English definitions and cross-references to relevant topics.

---

**A**

**Access Token** — A credential used to access protected resources. Presented in the `Authorization: Bearer` header. Unlike ID tokens, access tokens are opaque to the client. → [13-bearer-token](13-bearer-token/), [04-oauth2](04-oauth2/)

**Account Lockout** — Temporarily disabling an account after N failed login attempts to prevent brute-force attacks. → [17-security](17-security/)

**Algorithm Confusion Attack** — An attack where the attacker changes the JWT `alg` header to trick the verifier into using a weaker algorithm (e.g., RS256 → HS256 with the public key as the secret). → [03-jwt](03-jwt/)

**Argon2id** — Winner of the Password Hashing Competition (2015). The recommended algorithm for password hashing. Memory-hard, CPU-hard, resistant to GPU/ASIC attacks. → [17-security](17-security/)

**Assertion** — A statement from an identity provider (IdP) about a user, typically in SAML format. Contains claims about the user's identity, attributes, and authentication context. → [06-saml](06-saml/)

**aud (Audience)** — JWT claim identifying the intended recipient of the token. Must match the client's identifier. → [03-jwt](03-jwt/)

**Auth Code (Authorization Code)** — A temporary code issued by the authorization server after user consent. Exchanged for tokens via a back-channel request. → [04-oauth2](04-oauth2/), [12-social-login](12-social-login/)

**AuthN vs AuthZ** — Authentication (AuthN) is verifying identity ("who are you?"). Authorization (AuthZ) is verifying permissions ("what are you allowed to do?"). → [00-foundations](00-foundations/)

**B**

**bcrypt** — A password hashing function based on the Blowfish cipher. Automatically generates salts, has a configurable cost factor. Recommended where Argon2id is unavailable. → [17-security](17-security/)

**Bearer Token** — A token that grants access to the bearer (anyone who possesses it). Must be protected in transit (TLS) and storage. → [13-bearer-token](13-bearer-token/)

**BFF (Backend for Frontend)** — An architectural pattern where a server-side middleware handles token management on behalf of a browser-based client, keeping secrets out of the browser. → [16-auth-patterns](16-auth-patterns/)

**BIND** — LDAP operation that authenticates a client to the directory server. The foundation of LDAP-based authentication. → [11-ldap](11-ldap/)

**C**

**CAS (Central Authentication Service)** — A single sign-on protocol originally developed at Yale University. Uses tickets for authentication. → [15-cas](15-cas/)

**Claims** — Key-value pairs in a JWT payload or SAML assertion that convey information about the user or token. → [03-jwt](03-jwt/), [05-oidc](05-oidc/)

**Client Credentials Grant** — OAuth 2.0 flow for machine-to-machine (M2M) communication where the client authenticates directly, without a user. → [04-oauth2](04-oauth2/)

**Constant-Time Comparison** — A comparison function that takes the same amount of time regardless of input. Prevents timing attacks on HMACs, passwords, and tokens. → [17-security](17-security/)

**Credential Stuffing** — An attack where credentials leaked from one service are tried against others. The primary reason users should not reuse passwords. → [17-security](17-security/)

**CSRF (Cross-Site Request Forgery)** — An attack that tricks a user's browser into making an unintended request on a site where they're authenticated. Mitigated by SameSite cookies and CSRF tokens. → [02-session-cookies](02-session-cookies/), [17-security](17-security/)

**D**

**Digest Access Auth** — HTTP authentication scheme that sends credentials hashed with a server-provided nonce rather than in plaintext. Uses MD5. Largely obsolete. → [14-digest-auth](14-digest-auth/)

**DN (Distinguished Name)** — A unique identifier for an entry in an LDAP directory (e.g., `uid=jdoe,ou=users,dc=example,dc=com`). → [11-ldap](11-ldap/)

**DPoP (Demonstration of Proof-of-Possession)** — An extension to OAuth 2.0 that binds tokens to a specific client key, preventing token theft from being useful to an attacker. → [04-oauth2](04-oauth2/)

**E**

**exp (Expiration)** — Standard JWT claim indicating when the token expires. Must always be validated. → [03-jwt](03-jwt/)

**F**

**FIDO2** — A set of standards (WebAuthn + CTAP) enabling passwordless authentication with public-key cryptography. Phishing-resistant by design. → [10-passwordless](10-passwordless/)

**H**

**HMAC (Hash-based Message Authentication Code)** — A keyed hash function used for signing and verifying data integrity. Used in JWT (HS256) and cookie signing. → [03-jwt](03-jwt/), [02-session-cookies](02-session-cookies/)

**HOTP (HMAC-based One-Time Password)** — RFC 4226. Generates one-time passwords based on an HMAC and a moving counter. The basis for TOTP. → [09-mfa](09-mfa/)

**HttpOnly** — A cookie flag that prevents JavaScript from accessing the cookie. Critical for protecting session tokens against XSS attacks. → [02-session-cookies](02-session-cookies/)

**I**

**ID Token** — A JWT issued by an OIDC provider that contains identity claims about the user (sub, name, email, etc.). Must be validated by the client. → [05-oidc](05-oidc/)

**IdP (Identity Provider)** — A system that creates, maintains, and manages identity information and provides authentication services. Examples: Google, Okta, Keycloak. → [05-oidc](05-oidc/), [06-saml](06-saml/)

**IDOR (Insecure Direct Object Reference)** — An access control vulnerability where a user can access resources by guessing or manipulating identifiers. → [17-security](17-security/)

**iss (Issuer)** — JWT claim identifying who issued the token. Must match the expected issuer URL. → [03-jwt](03-jwt/), [05-oidc](05-oidc/)

**J**

**JWE (JSON Web Encryption)** — Encrypted JWT format where the payload is encrypted, not just signed. Provides confidentiality. → [03-jwt](03-jwt/)

**JWKS (JSON Web Key Set)** — A set of public keys published by an authorization server for verifying JWT signatures. Served at a well-known URL. → [03-jwt](03-jwt/), [05-oidc](05-oidc/)

**JWS (JSON Web Signature)** — Signed JWT format. The payload is base64-encoded (not encrypted) and signed. → [03-jwt](03-jwt/)

**JWT (JSON Web Token)** — A compact, URL-safe token format consisting of a header, payload, and signature. Used for access tokens, ID tokens, and more. → [03-jwt](03-jwt/)

**M**

**Magic Link** — A passwordless authentication method where a signed URL is sent to the user's email. Clicking the link authenticates them. → [10-passwordless](10-passwordless/)

**MFA (Multi-Factor Authentication)** — Authentication using two or more factors: something you know, something you have, and/or something you are. → [09-mfa](09-mfa/)

**mTLS (Mutual TLS)** — TLS where both the client and server present certificates. Used for high-security service-to-service authentication. → [04-oauth2](04-oauth2/), [07-api-keys](07-api-keys/)

**N**

**Nonce** — A number used once. In OIDC, protects against ID token replay. In digest auth, prevents replay of hashed passwords. → [05-oidc](05-oidc/), [14-digest-auth](14-digest-auth/)

**O**

**OAuth 2.0** — An authorization framework that enables third-party applications to obtain limited access to a user's resources without exposing credentials. → [04-oauth2](04-oauth2/)

**OIDC (OpenID Connect)** — An identity layer on top of OAuth 2.0. Provides user authentication via ID tokens and a UserInfo endpoint. → [05-oidc](05-oidc/)

**Opaque Token** — A token whose format is not meaningful to the client. It must be looked up in a database to determine its validity and associated data. → [13-bearer-token](13-bearer-token/)

**P**

**Passkey** — A FIDO2 credential synchronized across devices via a platform provider (Apple, Google, Microsoft). Replaces passwords for consumer auth. → [10-passwordless](10-passwordless/)

**Pepper** — A secret, fixed string added to a password before hashing (e.g., `HMAC(password, pepper)` then `bcrypt`). Unlike a salt, the pepper is not stored alongside the hash. → [17-security](17-security/)

**PKCE (Proof Key for Code Exchange)** — An extension to OAuth 2.0's Authorization Code flow that prevents interception of the authorization code. Required for public clients. → [04-oauth2](04-oauth2/)

**Principal** — The entity being authenticated (typically a user). The subject of an authentication event. → [00-foundations](00-foundations/)

**R**

**Refresh Token** — A long-lived token used to obtain new access tokens without requiring the user to re-authenticate. Should be rotated and support reuse detection. → [03-jwt](03-jwt/), [13-bearer-token](13-bearer-token/)

**Relying Party (RP)** — The service/application that relies on an identity provider for authentication. Synonymous with "client" in OAuth and "service provider" in SAML. → [05-oidc](05-oidc/)

**ROPC (Resource Owner Password Credentials)** — A legacy OAuth 2.0 grant where the client collects the user's password directly. Deprecated in OAuth 2.1. → [04-oauth2](04-oauth2/)

**S**

**Salt** — A random, per-password value added to the hash to prevent rainbow table attacks. Stored alongside the hash. → [17-security](17-security/)

**SAML 2.0 (Security Assertion Markup Language)** — An XML-based SSO protocol. Uses signed XML assertions. Predominantly used in enterprise environments. → [06-saml](06-saml/)

**SCIM (System for Cross-domain Identity Management)** — A protocol for provisioning and synchronizing user identities between systems (e.g., from an HR system to a SaaS app). → [08-sso](08-sso/)

**Scope** — A permission or access level associated with a token. In OAuth, scopes limit what the access token can do. → [04-oauth2](04-oauth2/), [07-api-keys](07-api-keys/)

**Session** — A server-side record of an authenticated user, typically identified by a cookie. The session stores user state and expiry information. → [02-session-cookies](02-session-cookies/)

**SSO (Single Sign-On)** — A property of an authentication system where one login grants access to multiple applications without re-authentication. → [08-sso](08-sso/), [15-cas](15-cas/)

**STRIDE** — A threat modeling framework: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. → [00-foundations](00-foundations/)

**T**

**TOTP (Time-based One-Time Password)** — RFC 6238. Generates one-time passwords based on an HMAC and the current time. 30-second window. → [09-mfa](09-mfa/)

**W**

**WebAuthn** — A W3C standard for passwordless authentication using public-key cryptography. Part of the FIDO2 set of standards. → [10-passwordless](10-passwordless/)

**Work Factor (Cost Factor)** — A parameter (e.g., bcrypt rounds, Argon2 time/memory) that controls how expensive a hash is to compute. Higher values make brute-force harder. → [17-security](17-security/)

**X**

**XSS (Cross-Site Scripting)** — An attack that injects malicious scripts into web pages. Can be used to steal tokens from localStorage or session cookies. → [17-security](17-security/)

**XSW (XML Signature Wrapping)** — A SAML attack where the attacker moves the original signed assertion outside the signature scope and inserts a forged one. → [06-saml](06-saml/)
