# Python — API Key Auth

## Requirements

- Python 3.10+
- `pip install "fastapi[standard]" uvicorn httpx`

## Run the Server

```bash
python server.py
```

## Run the Client

```bash
python client.py
```

## Features

| Feature | Implementation |
|---------|----------------|
| Key generation | `secrets.token_urlsafe(32)` → 240-bit entropy |
| Key hashing | SHA-256 before storage |
| Key prefix/suffix | `enter_api_key_here` — never expose full key |
| Scopes | `read`, `write`, `admin` |
| Expiry | Time-based with auto-rejection |
| Rotation | New key generated, old deleted |
| Revocation | Instant deletion from store |
| Rate limiting | Token bucket (10 req / 60s per key) |

## Files

| File | Purpose |
|------|---------|
| `server.py` | FastAPI server with full API key management |
| `client.py` | Client demonstrating create, use, rotate, revoke |
