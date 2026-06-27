# Python — Social Login

## Requirements

- Python 3.10+
- `pip install "fastapi[standard]" uvicorn httpx pyjwt`

## Run the Server

```bash
python server.py
```

Open `http://127.0.0.1:8000` and click "Sign in with Google" or "Sign in with GitHub".

## Run the Client

```bash
python client.py
```

## Architecture

The server plays two roles:

| Role | Endpoints | Purpose |
|------|-----------|---------|
| **App** | `/`, `/auth/{provider}/login`, `/auth/{provider}/callback`, `/dashboard` | The app that uses social login |
| **Mock Provider** | `/mock/{provider}/authorize`, `/mock/{provider}/consent`, `/mock/{provider}/token`, `/mock/{provider}/userinfo` | Simulates Google/GitHub OAuth |

## Files

| File | Purpose |
|------|---------|
| `server.py` | FastAPI app + mock social providers |
| `client.py` | Automated OAuth flow demo |
