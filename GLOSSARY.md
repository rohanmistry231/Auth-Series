# Authentication Glossary

100+ terms with plain-English definitions.

| Term | Definition |
|------|------------|
| **ABAC (Attribute-Based Access Control)** | Access control model where policies are evaluated against attributes of the user, resource, action, and environment |
| **Access Token** | A credential used to access protected resources; typically short-lived |
| **Account Lockout** | Security mechanism that disables an account after N failed login attempts |
| **ACL (Access Control List)** | A list of permissions attached to an object specifying which subjects can access it |
| **ACR (Authentication Context Class Reference)** | Identifier representing the strength or level of authentication performed |
| **AMR (Authentication Methods Reference)** | JSON array listing the authentication methods used (e.g., `["pwd", "otp"]`) |
| **Argon2id** | Password hashing algorithm, winner of the Password Hashing Competition; memory-hard, resistant to GPU/ASIC |
| **AS (Authorization Server)** | The server that issues tokens after successfully authenticating the resource owner and obtaining authorisation |
| **Assertion** | A statement from an IdP about a principal, used in SAML |
| **Audience (aud)** | Claim identifying the intended recipient of a token |
| **AuthN (Authentication)** | The process of verifying identity ("who are you?") |
| **AuthZ (Authorization)** | The process of determining access rights ("what may you do?") |
| **Back-Channel** | Direct server-to-server communication (not through the browser) |
| **Base64** | Binary-to-text encoding scheme; used in Basic Auth and JWT (base64url variant) |
| **bcrypt** | Adaptive password hashing function based on Blowfish cipher; cost factor determines slowness |
| **Bearer Token** | A token that grants access to the bearer (anyone who possesses it) |
| **BFF (Backend for Frontend)** | Architectural pattern where a server-side component handles auth for a frontend app, keeping tokens out of the browser |
| **BIND** | LDAP operation to authenticate to the directory |
| **Canonicalization (c14n)** | Process of converting XML to a standard form for signature verification |
| **CAS (Central Authentication Service)** | Enterprise SSO protocol; uses service tickets and ticket-granting tickets |
| **Claim** | A piece of information asserted about an entity (e.g., "email": "user@example.com") |
| **Client Credentials Grant** | OAuth 2.0 grant for machine-to-machine communication; no user involved |
| **Client Secret** | A confidential string known only to the client and auth server |
| **COSE (CBOR Object Signing and Encryption)** | Compact binary encoding for cryptographic keys; used in WebAuthn |
| **Credential** | Evidence used to prove identity (password, key, token, biometric) |
| **Credential Stuffing** | Automated attack using username/password pairs leaked from other breaches |
| **CSRF (Cross-Site Request Forgery)** | Attack that tricks a user into performing an unwanted action on an authenticated site |
| **DIT (Directory Information Tree)** | Hierarchical tree structure of LDAP directory entries |
| **DN (Distinguished Name)** | Unique identifier for an LDAP entry (e.g., `cn=John Doe,ou=Users,dc=example,dc=com`) |
| **ECP (Enhanced Client or Proxy)** | SAML profile for non-browser clients (mobile, thick clients) |
| **EdDSA (Edwards-curve Digital Signature Algorithm)** | Modern, fast asymmetric signing algorithm using Ed25519 |
| **ES256** | ECDSA using P-256 curve and SHA-256; asymmetric signing algorithm for JWT |
| **Factor** | A category of authentication evidence: knowledge, possession, inherence |
| **Federation** | Trust relationship between organisations allowing identity sharing across domains |
| **FIDO2** | Standard for passwordless authentication using public-key cryptography |
| **Fragment** | The part of a URL after `#`; never sent to the server; used in the deprecated implicit grant |
| **Front-Channel** | Communication that goes through the browser (HTTP redirects, form POSTs) |
| **Grant Type** | OAuth 2.0 method for obtaining a token (authorization code, client credentials, etc.) |
| **HSTS (HTTP Strict Transport Security)** | Header that forces browsers to always use HTTPS |
| **HOTP (HMAC-Based One-Time Password)** | RFC 4226; event-based OTP using an incrementing counter |
| **HS256** | HMAC with SHA-256; symmetric signing algorithm for JWT |
| **IdP (Identity Provider)** | System that authenticates users and issues assertions/tokens |
| **ID Token** | JWT containing identity claims in OpenID Connect |
| **IDOR (Insecure Direct Object Reference)** | Vulnerability where a user can access resources by guessing IDs |
| **Introspection** | Protocol (RFC 7662) for a resource server to validate an opaque token via the auth server |
| **Issuer (iss)** | Claim identifying who issued the token |
| **JWA (JSON Web Algorithms)** | RFC 7518; defines algorithms for JWS, JWE, JWK |
| **JWK (JSON Web Key)** | RFC 7517; JSON representation of a cryptographic key |
| **JWKS (JSON Web Key Set)** | A set of JWKs exposed at an endpoint; used for verifying JWT signatures |
| **JWS (JSON Web Signature)** | RFC 7515; JSON-based signature format used by JWT |
| **JWT (JSON Web Token)** | RFC 7519; compact, URL-safe token format with signed claims |
| **Kerberos** | Network authentication protocol using tickets and a trusted Key Distribution Center (KDC) |
| **KID (Key ID)** | Claim in JWT header identifying which key was used to sign |
| **LDAP (Lightweight Directory Access Protocol)** | Protocol for accessing distributed directory services |
| **Magic Link** | Passwordless authentication via a one-time URL sent by email |
| **MD5** | Message Digest 5; broken cryptographic hash — never use for security |
| **MFA (Multi-Factor Authentication)** | Authentication requiring ≥2 factors from ≥2 distinct categories |
| **mTLS (Mutual TLS)** | Both client and server present TLS certificates to authenticate each other |
| **NameID** | SAML element identifying the principal (user) |
| **NIST SP 800-63** | US standard for digital identity; defines AAL (Authenticator Assurance Levels) |
| **Nonce** | Number used once; prevents replay attacks |
| **NumericDate** | JSON data type representing seconds since Unix epoch (not milliseconds) |
| **OAuth 2.0** | RFC 6749; protocol for delegated authorization |
| **OAuth 2.1** | Updated OAuth 2.0 spec removing implicit grant, requiring PKCE |
| **OIDC (OpenID Connect)** | Identity layer on top of OAuth 2.0; adds authentication (ID tokens) |
| **OneTimeUse** | SAML condition requiring the assertion to be consumed only once |
| **Opaque Token** | A random string that is not self-contained; requires server-side lookup or introspection |
| **OU (Organizational Unit)** | Container in LDAP for grouping related entries |
| **OWASP ASVS** | Application Security Verification Standard — framework for security requirements |
| **Passkey** | Multi-device WebAuthn credential synced via cloud (Apple, Google, Microsoft) |
| **PGT (Proxy Granting Ticket)** | CAS ticket that allows a service to obtain proxy tickets on behalf of a user |
| **PKCE (Proof Key for Code Exchange)** | Extension to OAuth 2.0 that prevents authorisation code interception |
| **Principal** | The entity being authenticated (user, service, device) |
| **RBAC (Role-Based Access Control)** | Access control model where permissions are assigned to roles, not directly to users |
| **Redirect URI** | OAuth parameter specifying where the auth server redirects after authentication |
| **Reference Token** | A short identifier that maps to stored claims; hybrid between opaque and JWT |
| **Refresh Token** | Long-lived credential used to obtain new access tokens without re-authentication |
| **Replay Attack** | Resending a captured authentication message to gain unauthorised access |
| **Revocation** | Invalidating a token or session before its natural expiration |
| **RO (Resource Owner)** | The user who owns the data being accessed |
| **RS (Resource Server)** | The server hosting the protected resources (API) |
| **RS256** | RSA with SHA-256; asymmetric signing algorithm for JWT |
| **SAML 2.0** | XML-based SSO protocol; uses assertions for identity federation |
| **SameSite** | Cookie attribute that controls when cookies are sent on cross-site requests |
| **Scope** | A permission or set of permissions requested by a client in OAuth 2.0 |
| **scrypt** | Memory-hard key derivation function |
| **Session** | A temporary, server-side record of an authenticated principal |
| **Session Fixation** | Attack where an attacker forces a victim to use a known session ID |
| **SHA-256** | Secure Hash Algorithm 256-bit; collision-resistant hash function |
| **SLO (Single Logout)** | Terminating session across all SPs when user logs out of one |
| **SP (Service Provider)** | The application the user wants to access (in SAML) |
| **SSO (Single Sign-On)** | Authenticating once to access multiple applications |
| **State** | OAuth parameter that links the authorisation request to the callback (CSRF protection) |
| **STRIDE** | Threat model: Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation |
| **Subject (sub)** | Claim identifying the principal the token is about |
| **TGT (Ticket Granting Ticket)** | CAS / Kerberos long-term session ticket |
| **TLS (Transport Layer Security)** | Cryptographic protocol securing communications over a network |
| **Token Exchange** | Exchanging one token for another (e.g., narrow scopes, different audience) |
| **Token Rotation** | Replacing a refresh token with a new one on each use; old token is revoked |
| **TOTP (Time-Based One-Time Password)** | RFC 6238; OTP using current time as the counter |
| **UserInfo Endpoint** | OIDC endpoint returning identity claims about the authenticated user |
| **WebAuthn** | W3C standard for passwordless authentication using public-key cryptography |
| **XML-DSig** | XML Signature standard; used in SAML to sign assertions |
| **XML-Enc** | XML Encryption standard; used in SAML to encrypt assertions |
| **XSS (Cross-Site Scripting)** | Injection attack where malicious scripts are executed in the user's browser |
| **Zero Trust** | Security model where no actor is trusted by default; every request is authenticated and authorised |
