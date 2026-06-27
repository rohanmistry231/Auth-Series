# 10 — Passwordless Authentication

Passwordless auth eliminates passwords entirely, replacing them with cryptographic keys (WebAuthn), one-time codes, or magic links. The result: no password reuse, no phishing of credentials, no forgotten passwords.

---

## 1. WebAuthn / Passkeys — Cryptographic Ceremony

WebAuthn (W3C) uses public-key cryptography. The private key never leaves the user's device.

### Registration Ceremony

```
┌────────────────────────────────────────────────────────────────────┐
│                                                                   │
│  Client                              Server (Relying Party)       │
│  ──────                              ──────────────────────       │
│                                                                   │
│  1. POST /register/begin                                          │
│     ────────────────────────────────────────────────────────────>  │
│                                                                   │
│                                    Generate challenge (32 bytes)  │
│                                    Store: challenge (session)     │
│                                                                   │
│  2. <── { challenge, rp, user, pubKeyCredParams }                 │
│                                                                   │
│  3. navigator.credentials.create({                                 │
│       publicKey: {                                                 │
│         challenge,                                                 │
│         rp: { name: "Auth Series" },                               │
│         user: { id: userId, name: "user@example.com" },           │
│         pubKeyCredParams: [{ alg: -7, type: "public-key" }],      │
│         authenticatorSelection: {                                  │
│           requireResidentKey: true,                                │
●          userVerification: "preferred"                             │
│         }                                                          │
│       }                                                            │
│     })                                                             │
│     ── Creates new key pair                                        │
│     ── User touches security key / Face ID / fingerprint           │
│     ── Returns PublicKeyCredential                                 │
│                                                                   │
│  4. POST /register/complete { id, rawId, response }               │
│     ────────────────────────────────────────────────────────────>  │
│                                                                   │
│                                    Verify signature               │
│                                    Store: credentialId + pubKey   │
│                                    Map to user account            │
│                                                                   │
│  5. <── { verified: true }                                        │
│                                                                   │
└────────────────────────────────────────────────────────────────────┘
```

### Authentication Ceremony

```
┌────────────────────────────────────────────────────────────────────┐
│                                                                   │
│  Client                              Server                       │
│                                                                   │
│  1. POST /login/begin                                             │
│     ────────────────────────────────────────────────────────────>  │
│                                    Look up user's credential IDs  │
│                                    Generate challenge             │
│                                    Return: allowCredentials + ch  │
│                                                                   │
│  2. navigator.credentials.get({                                    │
│       publicKey: {                                                 │
│         challenge,                                                 │
│         allowCredentials: [{ id, type: "public-key" }],           │
│         userVerification: "required"                               │
│       }                                                            │
│     })                                                             │
│     ── User touches security key / Face ID                         │
●     ── Private key signs challenge                                 │
│     ── Returns AuthenticatorAssertionResponse                      │
│                                                                   │
│  3. POST /login/complete { id, response }                         │
│     ────────────────────────────────────────────────────────────>  │
│                                    Verify signature                │
│                                    Check counter (clone detection) │
│                                    Create session                  │
│                                                                   │
│  4. <── { session_token }                                         │
│                                                                   │
└────────────────────────────────────────────────────────────────────┘
```

---

## 2. Algorithms (COSE Key Types)

| Algorithm ID | Name | Curve | Use Case |
|-------------|------|-------|----------|
| -7 | ES256 | P-256 | Most common, widely supported |
| -8 | EdDSA | Ed25519 | Modern, fast |
| -257 | RS256 | RSA 2048+ | Legacy support |
| -65535 | RS1 | SHA-1 | **Deprecated** |

---

## 3. Magic Links — Complete Protocol

```
┌─────────────────────────────────────────────────────┐
│                    MAGIC LINK FLOW                    │
│                                                      │
│  1. User enters email                                │
│  2. Server generates:                                │
│     token = crypto.randomBytes(32).toString('hex')   │
│     url = "https://app.example.com/auth?             │
│            token=<token>&action=login"               │
│  3. Server stores:                                   │
│     { token, email, expiresAt, used: false }         │
│  4. Email sent with link                             │
│  5. User clicks link                                 │
│  6. Server validates:                                │
│     - Token exists                                   │
│     - Not expired (5–15 min TTL)                     │
●     - Not already used                               │
│  7. Marks token as used (single-use)                 │
│  8. Creates session                                  │
│                                                      │
└─────────────────────────────────────────────────────┘
```

---

## 4. Code Examples

### Java (WebAuthn with webauthn4j)

```java
// build.gradle: implementation 'com.webauthn4j:webauthn4j-core:0.22.0'

@Service
public class WebAuthnService {

    private final WebAuthnManager manager = WebAuthnManager.createNonStrictWebAuthnManager();

    public PublicKeyCredentialCreationOptions startRegistration(String userId, String userName) {
        return manager.createCreationOptions(
            new ServerProperty(
                "https://app.example.com",
                "Auth Series",
                Optional.of("https://app.example.com")),
            new UserIdentity(
                userId.getBytes(StandardCharsets.UTF_8),
                userName,
                userName),
            new DefaultCredentialCreationRequest(
                false, false, false)
        );
    }

    public RegistrationResult completeRegistration(
            String credentialJson, PublicKeyCredentialCreationOptions options) {
        AuthenticationWebAuthnRegistrationRequest request =
            new JsonConverter().convertRegistrationRequest(credentialJson);
        RegistrationParameters params = new RegistrationParameters(
            options.toPublicKeyCredentialParameters(),  // client extension
            options, (id, clientDataJSON) -> true);     // origin check

        return manager.validate(params);
    }
}
```

### Python (WebAuthn)

```python
from webauthn import generate_registration_options, verify_registration_response
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement

# Registration
registration_options = generate_registration_options(
    rp_id="example.com",
    rp_name="Auth Series",
    user_id=b"user_123",
    user_name="user@example.com",
    authenticator_selection=AuthenticatorSelectionCriteria(
        user_verification=UserVerificationRequirement.PREFERRED,
    ),
)

# Store challenge in session
session["challenge"] = registration_options.challenge

# Verification
verification = verify_registration_response(
    credential=credential_response,
    expected_challenge=session["challenge"],
    expected_origin="https://example.com",
    expected_rp_id="example.com",
)

if verification.verified:
    store_credential(user_id, verification.credential_id, verification.credential_public_key)
```

### TypeScript (SimpleWebAuthn)

```typescript
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

// Registration
const options = await generateRegistrationOptions({
  rpName: 'Auth Series',
  rpID: 'example.com',
  userName: 'user@example.com',
  attestationType: 'none',
});
session.challenge = options.challenge;

// Verification
const verification = await verifyRegistrationResponse({
  credential: req.body,
  expectedChallenge: session.challenge,
  expectedOrigin: 'https://example.com',
  expectedRPID: 'example.com',
});
```

---

## 5. References

- [WebAuthn Level 2 (W3C)](https://www.w3.org/TR/webauthn-2/)
- [FIDO2 Overview](https://fidoalliance.org/fido2/)
- [Passkeys (Apple)](https://developer.apple.com/passkeys/)
- [Google Passkeys](https://developers.google.com/identity/passkeys)
- [SimpleWebAuthn](https://simplewebauthn.dev/)
- [webauthn4j (Java)](https://github.com/webauthn4j/webauthn4j)
