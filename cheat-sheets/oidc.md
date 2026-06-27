# OIDC — Cheat Sheet

## Core Flow

```
RP → Discovery → Auth Request → ID Token → UserInfo
```

## ID Token Claims

| Claim | Required | Description |
|-------|----------|-------------|
| `iss` | ✅ | Issuer URL (must match discovery) |
| `sub` | ✅ | Unique user identifier |
| `aud` | ✅ | Client ID of the RP |
| `exp` | ✅ | Expiration time |
| `iat` | ✅ | Issued at time |
| `nonce` | ⚠️ | Replay protection (if sent in request) |

## Token Response

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "id_token": "eyJ...",
  "expires_in": 3600
}
```

## Discovery URL

```
GET /.well-known/openid-configuration
```

Returns: `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `scopes_supported`, `response_types_supported`

## Validation Steps

1. Verify `iss` matches expected issuer
2. Verify `aud` contains your client_id
3. Verify signature using provider's JWKS
4. Verify `exp` is not expired
5. Verify `nonce` if one was sent
6. (Optional) Verify `auth_time` for fresh auth

## cURL

```bash
# Discover
curl https://accounts.google.com/.well-known/openid-configuration

# Verify ID Token (decode header + payload)
echo "eyJ..." | cut -d. -f2 | base64 -d | jq .
```
