# Python — Magic Link Passwordless Auth

## Requirements

- Python 3.10+
- `pip install "fastapi[standard]" uvicorn httpx`

## Run the Server

```bash
export MAGIC_LINK_SECRET="my-secret-key"
export TOKEN_TTL_SECONDS=900

python server.py
```

## Run the Client

```bash
python client.py
```

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/auth/request` | POST | Generate magic link for email |
| `/auth/verify` | GET | Consume token, authenticate |

## Files

| File | Purpose |
|------|---------|
| `server.py` | FastAPI magic link server |
| `client.py` | Demonstrates request + verify flow |
