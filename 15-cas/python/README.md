# Python — CAS SSO

## Requirements

- Python 3.10+
- `pip install "fastapi[standard]" uvicorn httpx`

## Run the Server

```bash
python server.py
```

Open `http://127.0.0.1:8000` and click the protected resource link.

## Run the Client

```bash
python client.py
```

## Architecture

This demo bundles both roles in one server:

| Role | Endpoints | Purpose |
|------|-----------|---------|
| **CAS Server** | `/login`, `/validate` | Authentication + ticket validation |
| **App** | `/`, `/protected` | CAS-protected resource |

## Files

| File | Purpose |
|------|---------|
| `server.py` | FastAPI CAS server + protected app |
| `client.py` | Browser-simulated CAS login flow |
