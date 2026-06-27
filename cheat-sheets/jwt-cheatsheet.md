# JWT Cheat Sheet

## Structure

```
base64Url(HEADER).base64Url(PAYLOAD).base64Url(SIGNATURE)
```

## Standard Claims (Registered)

| Claim | Name | Description |
|-------|------|-------------|
| `iss` | Issuer | Who issued the token |
| `sub` | Subject | Who the token is about (user ID) |
| `aud` | Audience | Intended recipient (client ID) |
| `exp` | Expiration | Token expiry (Unix timestamp) |
| `nbf` | Not Before | Token not valid before this time |
| `iat` | Issued At | When token was issued |
| `jti` | JWT ID | Unique identifier (replay prevention) |

## Algorithms

| Algorithm | Type | Key Size |
|-----------|------|----------|
| HS256 | Symmetric | 256+ bits |
| RS256 | Asymmetric | 2048+ bits |
| ES256 | Asymmetric | P-256 curve |
| EdDSA | Asymmetric | Ed25519 |

## Validation Steps

```
1. Verify signature (using JWKS or shared secret)
2. Check iss matches expected issuer
3. Check aud contains your client ID
4. Check exp is in the future
5. Check nbf is in the past (if present)
6. Verify nonce (if present in ID Token)
7. Check token_type (access vs refresh vs id)
```
