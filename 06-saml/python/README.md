# Python — SAML 2.0

## Requirements

- Python 3.10+
- `pip install "fastapi[standard]" uvicorn lxml signxml cryptography`

## Run the Identity Provider (IdP)

```bash
export ALICE_PASSWORD="super-secret"

python idp.py
```

Starts at `http://localhost:8000`:
| Endpoint | Description |
|----------|-------------|
| `GET /sso` | Login form |
| `POST /sso` | Authenticate + POST signed SAML Response to SP |
| `GET /metadata` | IdP metadata XML |

## Run the Service Provider (SP)

```bash
python sp.py
```

Starts at `http://localhost:8001`:
| Endpoint | Description |
|----------|-------------|
| `GET /login` | Login page (link to IdP) |
| `POST /acs` | Assertion Consumer Service — validates SAML Response |
| `GET /metadata` | SP metadata XML |

## Test the Flow

1. Start IdP (`python idp.py`) — port 8000
2. Start SP (`python sp.py`) — port 8001
3. Open `http://localhost:8001/login`
4. Click the IdP link, log in as `alice`
5. IdP auto-POSTs signed SAML Response to SP
6. SP validates signature, issuer, audience, expiry → shows attributes

## Files

| File | Purpose |
|------|---------|
| `idp.py` | SAML IdP — signs assertions with RSA-SHA256 |
| `sp.py` | SAML SP — verifies XML signatures with signxml |
