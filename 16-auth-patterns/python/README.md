# Python — Auth Patterns

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

## Patterns

| Pattern | Endpoints | Description |
|---------|-----------|-------------|
| **BFF** | `/bff/login`, `/bff/api/data` | Server-managed tokens, httpOnly session |
| **Token Rotation** | `/token/issue`, `/token/refresh` | Refresh + theft detection |
| **Gateway** | `/gateway/token`, `/gateway/validate`, `/gateway/api/resource` | Centralized token validation |

## Files

| File | Purpose |
|------|---------|
| `server.py` | All three pattern implementations |
| `client.py` | Demonstrates all three patterns |
