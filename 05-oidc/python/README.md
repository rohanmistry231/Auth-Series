# Python — OpenID Connect

## Requirements

- Python 3.10+
- `pip install "fastapi[standard]" uvicorn httpx pyjwt cryptography`

## Run the Provider (OP)

```bash
export ALICE_PASSWORD="super-secret"
export BOB_PASSWORD="another-secret"
export RP_SECRET="rp-secret"

python provider.py
```

Starts OIDC Provider at `http://localhost:8000`:
| Endpoint | Description |
|----------|-------------|
| `/.well-known/openid-configuration` | Discovery |
| `/.well-known/jwks.json` | Public keys |
| `/authorize` | Authorization |
| `/token` | Token + ID Token |
| `/userinfo` | User claims |

## Run the Relying Party (RP)

```bash
python rp.py
```

Demonstrates:
1. Discovery document fetch
2. Auth request with `openid` scope + `nonce`
3. Code exchange → access_token + id_token
4. ID Token validation (signature, iss, aud, exp, nonce)
5. UserInfo fetch

## Files

| File | Purpose |
|------|---------|
| `provider.py` | OIDC Provider (extends OAuth 2.0) |
| `rp.py` | Relying Party with full ID Token validation |
