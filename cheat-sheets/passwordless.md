# Passwordless Auth — Cheat Sheet

## Methods

| Method | UX | Security | Implementation |
|--------|----|----------|---------------|
| **Magic Link** | Good | High | HMAC-signed token in URL |
| **WebAuthn** | Excellent | Very High | Public-key crypto |
| **OTP Email** | Good | Medium | 6-8 digit code, 5-10 min TTL |
| **OTP SMS** | Fair | Low (SIM swap) | Deprecated by NIST |

## Magic Link Token

```
Payload  = "email:uuid:exp"
Signature = HMAC-SHA256(secret, payload)
Token     = base64(payload) + "." + base64(signature)

Server: hash(token) → store (used flag)
User:   click link → server verifies HMAC + expiry + single-use
```

## Security Rules

| Rule | Why |
|------|-----|
| Single-use tokens | Prevent replay |
| 15 min expiry | Limit attack window |
| HMAC-signed | Prevent token forgery |
| Rate-limit per email | Prevent enumeration |
| Constant-time compare | Prevent timing attacks |

## WebAuthn Checklist

- [ ] Challenge is random per registration
- [ ] Origin bound to private key
- [ ] Attestation verified on registration
- [ ] Counter values tracked (clone detection)
