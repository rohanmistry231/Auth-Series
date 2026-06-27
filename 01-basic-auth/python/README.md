# Python — Basic Auth

## Requirements

- Python 3.10+
- `pip install fastapi uvicorn httpx`

## Run the Server

```bash
# Set credentials via environment (optional — defaults exist)
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

## Files

| File | Purpose |
|------|---------|
| `server.py` | FastAPI server with Basic Auth middleware |
| `client.py` | httpx client demonstrating all scenarios |
