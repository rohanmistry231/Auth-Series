# TypeScript — SSO

## Requirements

- Node.js 18+
- No external dependencies

## Run the SSO Server

```bash
export ALICE_PASSWORD="super-secret"

npx tsx server.ts
```

## Run App1 + App2

```bash
# Terminal 1
APP_ID=app1 APP_PORT=8001 APP_NAME="My Dashboard" npx tsx app.ts

# Terminal 2
APP_ID=app2 APP_PORT=8002 APP_NAME="Admin Panel" npx tsx app.ts
```

## Files

| File | Purpose |
|------|---------|
| `server.ts` | SSO Server — JWT-based token issue + validation |
| `app.ts` | Client app — run with env vars for App1/App2 |
