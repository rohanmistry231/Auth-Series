# 03 — JWT (JSON Web Tokens)

RFC 7519 defines a compact, URL-safe token format for representing claims between two parties. JWTs are the backbone of modern stateless authentication.

---

## 1. Token Anatomy

```
                         JWT (URL-safe, compact)
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│  base64url(header) . base64url(payload) . base64url(signature)     │
│                                                                    │
│  ┌──────────────┐   ┌──────────────────┐   ┌───────────────────┐  │
│  │ {"alg":"HS256"│   │ {"sub":"user123", │   │ HMACSHA256(      │  │
│  │  "typ":"JWT"} │   │  "iat":1715000000,│   │  base64(header)  │  │
│  │              │   │  "exp":1715000900} │   │  +"."+           │  │
│  │  (unencoded) │   │  (unencoded)       │   │  base64(payload),│  │
│  │              │   │                    │   │  secret)         │  │
│  └──────────────┘   └──────────────────┘   │                   │  │
│  base64url(header)    base64url(payload)    └───────────────────┘  │
│                                              base64url(signature)  │
└────────────────────────────────────────────────────────────────────┘
```

### 1.1 Header

```json
{
  "alg": "HS256",       // Algorithm — REQUIRED
  "typ": "JWT",         // Token type — RECOMMENDED ("JWT")
  "kid": "key-v2",      // Key ID — for JWKS rotation
  "cty": "content-type" // Content type (rare)
}
```

### 1.2 Payload (Claims)

#### Registered Claims (IANA Registry)

| Claim | Full Name | Type | Constraints |
|-------|-----------|------|-------------|
| `iss` | Issuer | String | Case-sensitive URL/URN |
| `sub` | Subject | String | Locally unique, never reused |
| `aud` | Audience | String or Array of Strings | Must contain verifier's identifier |
| `exp` | Expiration Time | NumericDate | **Must** be checked |
| `nbf` | Not Before | NumericDate | Reject tokens used before this time |
| `iat` | Issued At | NumericDate | Reject tokens issued in the future |
| `jti` | JWT ID | String | Unique; prevents replay |

#### NumericDate definition

```javascript
// NumericDate = seconds since Unix epoch (ignoring leap seconds)
const now = Math.floor(Date.now() / 1000);
// NOT milliseconds!
```

#### Public / Private claims

```
Public:   Defined in IANA registry or collision-resistant URI (e.g., https://example.com/claims/role)
Private:  Agreed-upon between issuer and consumer (e.g., {"role": "admin"})
```

---

## 2. Signing Algorithms — Deep Dive

### 2.1 Algorithm matrix

| Algorithm | Type | Key Material | Signature Size | Verification Speed | Use Case |
|-----------|------|-------------|----------------|--------------------|----------|
| **HS256** | HMAC + SHA-256 | 256+ bit secret | 32 bytes | Very fast | Single service, trusted network |
| **HS384** | HMAC + SHA-384 | 384+ bit secret | 48 bytes | Fast | Higher security margin |
| **HS512** | HMAC + SHA-512 | 512+ bit secret | 64 bytes | Fast | Maximum symmetric security |
| **RS256** | RSA + SHA-256 | 2048+ bit key pair | 256 bytes | Slow (verify) | Distributed systems, many verifiers |
| **RS384** | RSA + SHA-384 | 2048+ bit key pair | 256 bytes | Slow (verify) | |
| **RS512** | RSA + SHA-512 | 2048+ bit key pair | 256 bytes | Slow (verify) | |
| **ES256** | ECDSA + P-256 | P-256 key pair | 64 bytes | Fast (verify) | Mobile, IoT, performance-sensitive |
| **ES384** | ECDSA + P-384 | P-384 key pair | 96 bytes | Fast (verify) | Higher ECDSA security |
| **EdDSA** | Ed25519 | Ed25519 key pair | 64 bytes | Very fast (verify) | Modern replacement for ECDSA |
| **PS256** | RSA-PSS + SHA-256 | 2048+ bit key pair | 256 bytes | Slow (verify) | RSA with probabilistic signature |

### 2.2 Symmetric vs. Asymmetric — trust boundary

```
Symmetric (HS256):                          Asymmetric (RS256/ES256):
┌──────────┐          ┌──────────┐         ┌──────────┐          ┌──────────┐
│ Auth Svr │          │ API Svr  │         │ Auth Svr │          │ API Svr  │
│          │          │          │         │          │          │          │
│ secret   │──────────│ secret   │         │ PRIVKEY  │          │ PUBKEY   │
│ SIGN ✓   │  same!   │ VERIFY ✓│         │ SIGN ✓   │──────────│ VERIFY ✓│
└──────────┘          └──────────┘         └──────────┘  public  └──────────┘
```

**Rule of thumb:** If the signer and verifier are the same process/share a network → HS256. If third parties verify → RS256/ES256.

---

## 3. Token State Machine

```
        ┌───────────┐
        │  PENDING  │  — not yet issued
        └─────┬─────┘
              │ Issue (sign)
              ▼
        ┌───────────┐
        │  ACTIVE   │  — within [nbf, exp)
        └─────┬─────┘
              │
        ┌─────┴─────┐
        │           │
        ▼           ▼
  ┌──────────┐ ┌──────────┐
  │ EXPIRED  │ │ REVOKED  │  — added to blocklist
  └──────────┘ └──────────┘
        │
        ▼
  ┌──────────┐
  │ ROTATED  │  — refresh token replaced
  └──────────┘
```

---

## 4. Access Token vs. Refresh Token — Separation of Concerns

| Property | Access Token | Refresh Token |
|----------|-------------|---------------|
| Lifetime | 5–30 minutes | Days to months |
| Scope | Carries authorisation scopes | Scope-less or same scopes |
| Format | JWT (structured, verifiable) | Opaque or JWT with `type: refresh` |
| Storage | Client memory / short-lived cache | Secure storage (httpOnly cookie, keychain) |
| Revocation | Implicit (short TTL) | Required (server-side DB) |
| Rotation | No | **Yes** — single use, replace on refresh |
| Sent on | Every API call | Only `/token` endpoint |

### Refresh Token Rotation Protocol

```
1. Client presents refresh_token R1
2. Server validates R1
3. Server revokes R1 (marks as used)
4. Server issues new R2 + new access_token
5. If R1 is reused (stolen): R1 is already revoked → TOKEN_REUSE_DETECTED
6. On reuse detection: revoke ALL refresh tokens in the same family
```

---

## 5. JWKS (JSON Web Key Set)

For asymmetric algorithms, public keys are exposed via a JWKS endpoint:

```
GET /.well-known/jwks.json
```

```json
{
  "keys": [
    {
      "kty": "EC",
      "kid": "key-2026-01",
      "use": "sig",
      "alg": "ES256",
      "crv": "P-256",
      "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
    },
    {
      "kty": "RSA",
      "kid": "key-2025-12",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuu...TZjmw",
      "e": "AQAB"
    }
  ]
}
```

### Key Rotation Strategy

```
Phase 1:  Publish new key (kid=new-key) alongside old key
          Sign new tokens with new-key
          Old tokens with old-key still verify

Phase 2:  Remove old key from JWKS
          All tokens must use new-key

          Window: at least the maximum token TTL
```

---

## 6. Validation Algorithm

```
function validateJWT(token: string, expectedIssuer: string, expectedAudience: string): Claims {
    // 1. Parse
    const [headerB64, payloadB64, signatureB64] = token.split('.');
    if (!signatureB64) throw new Error('Missing signature');

    // 2. Header validation
    const header = JSON.parse(base64urlDecode(headerB64));
    if (header.alg === 'none') throw new Error('alg=none attack');
    if (!SUPPORTED_ALGORITHMS.includes(header.alg)) throw new Error('Unsupported alg');

    // 3. Signature verification (algorithm-specific)
    const key = getKey(header.kid); // from JWKS
    if (!verify(token, signatureB64, key, header.alg)) throw new Error('Invalid signature');

    // 4. Payload validation
    const payload = JSON.parse(base64urlDecode(payloadB64));
    if (payload.iss !== expectedIssuer) throw new Error('Invalid issuer');
    if (!payload.aud.includes(expectedAudience)) throw new Error('Invalid audience');
    if (payload.exp < now()) throw new Error('Token expired');
    if (payload.nbf && payload.nbf > now()) throw new Error('Token not yet valid');
    if (payload.iat > now() + 5 * 60) throw new Error('Token from future');

    return payload;
}
```

---

## 7. Known Attacks

| Attack | Mechanism | Prevention |
|--------|-----------|------------|
| **alg=none** | Attacker sets `"alg":"none"`, sends token without signature | Reject `alg: none`; whitelist allowed algs |
| **Key confusion** | Attacker tricks RS256 verifier into using HS256 with public key as HMAC secret | Always validate `alg` against expected list; use separate key material per family |
| **JWKS injection** | Attacker serves their own JWKS | Pin JWKS URI; use `.well-known` URL; validate `kid` |
| **Token sidejacking** | Attacker steals token from localStorage / network | Short TTL; refresh rotation; secure storage |
| **Timing attack** | Attacker measures verification time to infer signature validity | Constant-time comparison |
| **Unicode confusion** | Different byte sequences produce the same displayed string | Normalize claims (NFC) |
| **Embedded XSS** | Token payload contains `<script>` rendered unsafely | Never render token payload in HTML without escaping |

---

## 8. Code Examples

### Java (Spring Boot with nimbus-jose-jwt)

```java
// pom.xml: <dependency><groupId>com.nimbusds</groupId><artifactId>nimbus-jose-jwt</artifactId><version>9.40</version></dependency>

@Service
public class JwtService {

    private final JWSSigner signer;
    private final JWSVerifier verifier;
    private final String issuer = "auth-series";

    public JwtService() throws JOSEException {
        // Use RSA for asymmetric — ES256 in production
        RSAKey rsaKey = new RSAKeyGenerator(2048)
            .keyID("key-2026")
            .generate();
        this.signer = new RSASSASigner(rsaKey);
        this.verifier = new RSASSAVerifier(rsaKey);
    }

    public String createAccessToken(String subject, String role)
            throws JOSEException {

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject(subject)
            .issuer(issuer)
            .claim("role", role)
            .expirationTime(Date.from(
                Instant.now().plus(15, ChronoUnit.MINUTES)))
            .issueTime(new Date())
            .jwtID(UUID.randomUUID().toString())
            .build();

        SignedJWT signed = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID("key-2026")
                .build(),
            claims);
        signed.sign(signer);
        return signed.serialize();
    }

    public JWTClaimsSet verify(String token) throws Exception {
        SignedJWT signed = SignedJWT.parse(token);

        if (!signed.verify(verifier))
            throw new SecurityException("Invalid signature");
        if (!signed.getJWTClaimsSet().getIssuer().equals(issuer))
            throw new SecurityException("Wrong issuer");

        Date exp = signed.getJWTClaimsSet().getExpirationTime();
        if (exp != null && exp.before(new Date()))
            throw new SecurityException("Token expired");

        return signed.getJWTClaimsSet();
    }
}
```

### Python (PyJWT)

```python
import jwt
from datetime import datetime, timedelta

ACCESS_SECRET = os.environ["JWT_ACCESS_SECRET"]
ALGORITHM = "HS256"

def create_access_token(subject: str, role: str) -> str:
    return jwt.encode(
        {
            "sub": subject,
            "role": role,
            "iss": "auth-series",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(minutes=15),
            "jti": uuid.uuid4().hex,
        },
        ACCESS_SECRET,
        algorithm=ALGORITHM,
    )

def verify_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        ACCESS_SECRET,
        algorithms=[ALGORITHM],
        issuer="auth-series",
        options={"require": ["exp", "iat", "iss"]},
    )
```

### TypeScript (jose)

```typescript
import { SignJWT, jwtVerify, type JWTPayload } from 'jose';

const secret = new TextEncoder().encode(process.env.JWT_SECRET);

export async function sign(sub: string, role: string): Promise<string> {
  return new SignJWT({ role })
    .setSubject(sub)
    .setIssuer('auth-series')
    .setIssuedAt()
    .setExpirationTime('15m')
    .setJti(crypto.randomUUID())
    .setProtectedHeader({ alg: 'HS256' })
    .sign(secret);
}

export async function verify(token: string): Promise<JWTPayload> {
  const { payload } = await jwtVerify(token, secret, {
    issuer: 'auth-series',
    algorithms: ['HS256'],
  });
  return payload;
}
```

### Go (golang-jwt)

```go
import "github.com/golang-jwt/jwt/v5"

type Claims struct {
    Role string `json:"role"`
    jwt.RegisteredClaims
}

func Sign(subject, role string) (string, error) {
    claims := Claims{
        role,
        jwt.RegisteredClaims{
            Subject:   subject,
            Issuer:    "auth-series",
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            ID:        uuid.New().String(),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

func Verify(tokenString string) (*Claims, error) {
    claims := &Claims{}
    token, err := jwt.ParseWithClaims(tokenString, claims,
        func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v",
                    token.Header["alg"])
            }
            return []byte(os.Getenv("JWT_SECRET")), nil
        },
        jwt.WithIssuer("auth-series"),
        jwt.WithValidMethods([]string{"HS256"}),
    )
    if err != nil {
        return nil, err
    }
    return claims, nil
}
```

### Rust (jsonwebtoken)

```rust
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub iss: String,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
}

pub fn sign(sub: &str, role: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        sub: sub.to_owned(),
        role: role.to_owned(),
        iss: "auth-series".to_owned(),
        exp: (chrono::Utc::now() + chrono::Duration::minutes(15)).timestamp() as usize,
        iat: chrono::Utc::now().timestamp() as usize,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(std::env::var("JWT_SECRET")?.as_bytes()),
    )
}
```

---

## 9. References

- [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7515 — JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 7517 — JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 7518 — JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
- [jwt.io](https://jwt.io) — Token debugger
- [Auth0 JWT Handbook](https://auth0.com/resources/ebooks/jwt-handbook)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
