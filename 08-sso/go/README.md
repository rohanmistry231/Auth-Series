# Go — SSO

## Requirements

- Go 1.21+
- No external dependencies

## Run the SSO Server

```bash
export ALICE_PASSWORD="super-secret"

go run server.go
```

## Run App1 + App2

```bash
# Terminal 1
APP_ID=app1 APP_PORT=8001 APP_NAME="My Dashboard" go run app.go

# Terminal 2
APP_ID=app2 APP_PORT=8002 APP_NAME="Admin Panel" go run app.go
```

## Files

| File | Purpose |
|------|---------|
| `server.go` | SSO Server — RSA-signed JWT tokens |
| `app.go` | Client app — run with env vars for App1/App2 |
