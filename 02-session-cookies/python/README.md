# Python — Session & Cookie Auth

## Requirements

- Python 3.10+
- `pip install fastapi uvicorn httpx`

## Run the Server

```bash
export SESSION_SECRET="a-secure-random-secret-at-least-32-chars"
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
| Session store | In-memory `dict` (not for production) |
| Cookie signing | HMAC-SHA256 to prevent tampering |
| Session ID | CSPRNG-generated UUID v4 |
| Absolute TTL | 1 hour |
| Idle TTL | 15 minutes |
| CSRF | Synchronizer token pattern |

## Files

| File | Purpose |
|------|---------|
| `server.py` | FastAPI server with session + cookie auth |
| `client.py` | httpx client demonstrating full lifecycle |
