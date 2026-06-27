# Bearer Tokens — Cheat Sheet

## Header Format

```
Authorization: Bearer <token>
```

## Token Types

| Type | Format | Verify | Revocable |
|------|--------|--------|-----------|
| **Opaque** | Random string (48 bytes) | DB hash lookup | ✅ |
| **JWT** | `header.payload.signature` | Signature | ❌ |

## Opaque Token Lifecycle

```
1. Login → generate token (random 48 bytes → base64url)
2. Store SHA-256(token) in database
3. Return raw token to client
4. Client sends: Authorization: Bearer <token>
5. Server: hash(token) → lookup → validate → process
6. Introspect: POST /introspect { token } → { active, sub, scope }
7. Revoke: POST /revoke { token } → { result: "ok" }
```

## Security

| Rule | Why |
|------|-----|
| Store SHA-256 hash only | Never store raw credentials |
| Short TTL (15 min - 1 hr) | Limit stolen token window |
| Support revocation | Kill compromised tokens |
| Never log tokens | Credential leakage |
| Rate-limit /introspect | Prevent brute force |

## cURL

```bash
# Use token
curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." https://api.example.com/data

# Introspect
curl -X POST -d "token=..." https://auth.example.com/introspect

# Revoke
curl -X POST -d "token=..." https://auth.example.com/revoke
```
