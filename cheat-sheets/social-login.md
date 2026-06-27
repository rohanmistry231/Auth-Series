# Social Login — Cheat Sheet

## Providers

| Provider | Protocol | Key Scope | User Info Endpoint |
|----------|----------|-----------|-------------------|
| Google | OIDC | `openid profile email` | `https://www.googleapis.com/oauth2/v3/userinfo` |
| GitHub | OAuth 2 | `read:user user:email` | `https://api.github.com/user` |
| Apple | OIDC | `name email` | Included in ID token |
| Facebook | OAuth 2 | `public_profile email` | `https://graph.facebook.com/me` |

## OAuth Code Flow (Every Provider)

```
1. Redirect user → provider's /authorize
   ?client_id=...&redirect_uri=...&scope=...&state=...
2. User consents → provider redirects back with ?code=...
3. Server POST → provider's /token
   { code, client_id, client_secret, redirect_uri }
4. Response: { access_token, id_token (OIDC) }
5. Verify id_token (OIDC) or GET /userinfo (OAuth 2)
```

## Account Linking

```sql
CREATE TABLE social_accounts (
  provider VARCHAR(50),
  provider_id VARCHAR(255),
  user_id UUID,
  email VARCHAR(255),
  PRIMARY KEY (provider, provider_id)
);
```

## Validation Checklist

- [ ] Verify `id_token` signature (JWKS)
- [ ] Check `iss` (issuer) matches provider
- [ ] Check `aud` (audience) matches your client_id
- [ ] Validate `state` to prevent CSRF
- [ ] Normalize emails before linking

## cURL

```bash
# Exchange code for token
curl -X POST https://oauth2.googleapis.com/token \
  -d "code=AUTH_CODE&client_id=...&client_secret=...&redirect_uri=...&grant_type=authorization_code"

# Get user info
curl -H "Authorization: Bearer ACCESS_TOKEN" https://www.googleapis.com/oauth2/v3/userinfo
```
