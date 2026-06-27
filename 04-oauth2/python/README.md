# Python — OAuth 2.0

## Requirements

- Python 3.10+
- `pip install "fastapi[standard]" uvicorn httpx pyjwt cryptography`

## Run the Server (Authorization Server)

```bash
export ALICE_PASSWORD="super-secret"
export BOB_PASSWORD="another-secret"
export WEBAPP_SECRET="webapp-secret"
export SERVICE_A_SECRET="service-a-secret"

python server.py
```

Starts at `http://localhost:8000` with:
- `GET  /authorize` — authorize endpoint
- `POST /token` — token endpoint
- `POST /device/code` — device code initiation
- `GET  /device` — device approval form
- `GET  /userinfo` — protected resource
- `GET  /.well-known/oauth-authorization-server` — server metadata

## Run the Client

In another terminal:

```bash
# Run all flows
python client.py all

# Run individual flow
python client.py auth-code
python client.py pkce
python client.py client-creds
python client.py device
```

## Grant Types Implemented

| Flow | Client | PKCE | Secret |
|------|--------|------|--------|
| Authorization Code | `webapp` | ❌ | ✅ webapp-secret |
| Authorization Code + PKCE | `spa` | ✅ S256 | ❌ (public) |
| Client Credentials | `service-a` | N/A | ✅ service-a-secret |
| Device Code | `webapp` | N/A | N/A |
| Refresh Token | `webapp` | N/A | ✅ |

## Files

| File | Purpose |
|------|---------|
| `server.py` | Full OAuth 2.0 Authorization Server (all grant types) |
| `client.py` | Client demonstrating all 4 grant types + refresh |
