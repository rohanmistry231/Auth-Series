# Python — JWT Auth

## Requirements

- Python 3.10+
- `pip install "fastapi[standard]" uvicorn httpx pyjwt cryptography`

## Run the Server

```bash
export JWT_HS256_SECRET="a-very-secure-secret-at-least-32-chars-long"
export ALICE_PASSWORD="super-secret"
export BOB_PASSWORD="another-secret"

python server.py
```

## Run the Client

In another terminal:

```bash
export AUTH_USERNAME="alice"
export AUTH_PASSWORD="password-alice"

python client.py
```

## Architecture

| Component | Detail |
|-----------|--------|
| Access token signing | RS256 (RSA 2048-bit) for /protected; HS256 also accepted |
| Refresh token signing | HS256 |
| Refresh token storage | In-memory dict (keyed by `jti`) — revocable |
| Refresh token rotation | New refresh token issued on each use; old one invalidated |
| JWKS endpoint | `/.well-known/jwks.json` exposes RSA public key |

## Files

| File | Purpose |
|------|---------|
| `server.py` | FastAPI server with JWT auth (HS256 + RS256) |
| `client.py` | httpx client demonstrating login, access, refresh |
