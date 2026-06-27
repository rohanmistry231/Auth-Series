# Python — SSO

Demonstrates cross-domain SSO with a central auth server and two client apps.

## Run the SSO Server

```bash
export ALICE_PASSWORD="super-secret"
export BOB_PASSWORD="another-secret"

python server.py
```

Port 8000 — login, token issue, validation.

## Run App1 + App2 (two terminals)

```bash
# Terminal 1
export APP_ID=app1 APP_PORT=8001 APP_NAME="My Dashboard"
python app.py

# Terminal 2
export APP_ID=app2 APP_PORT=8002 APP_NAME="Admin Panel"
python app.py
```

## Test the Flow

1. Open `http://localhost:8001/dashboard` — redirected to SSO login
2. Log in as `alice` — redirected back to App1 with token
3. Open `http://localhost:8002/dashboard` — automatically logged in (SSO cookie!)
4. Logout of App1 — still in SSO, App2 still works
5. `http://localhost:8000/sso/logout` — full logout

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  SSO Server     │     │  App1           │     │  App2           │
│  localhost:8000 │     │  localhost:8001 │     │  localhost:8002 │
│                 │     │                 │     │                 │
│  POST /sso/login│◄────│  Redirect here  │     │  Redirect here  │
│  → issues JWT   │────►│  /sso/callback  │────►│  /sso/callback  │
│  → sets cookie  │     │  validates JWT  │     │  validates JWT  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Files

| File | Purpose |
|------|---------|
| `server.py` | SSO Server — issues and validates JWT tokens |
| `app.py` | SSO Client App — run with env vars for App1/App2 |
