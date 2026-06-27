# Python — Bearer Token Auth

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

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/login` | POST | Issue bearer token |
| `/protected` | GET | Validate token (query or header) |
| `/introspect` | POST | Token introspection |
| `/revoke` | POST | Token revocation |

## Files

| File | Purpose |
|------|---------|
| `server.py` | FastAPI bearer token server |
| `client.py` | Full lifecycle demo |
