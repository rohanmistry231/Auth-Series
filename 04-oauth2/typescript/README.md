# TypeScript — OAuth 2.0

## Requirements

- Node.js 18+
- No external dependencies (uses built-in `crypto`)

## Run the Server (Authorization Server)

```bash
export ALICE_PASSWORD="super-secret"
export BOB_PASSWORD="another-secret"
export WEBAPP_SECRET="webapp-secret"
export SERVICE_A_SECRET="service-a-secret"

npx tsx server.ts
```

## Run the Client

In another terminal:

```bash
# Run all flows
npx tsx client.ts all

# Run individual flow
npx tsx client.ts auth-code
npx tsx client.ts pkce
npx tsx client.ts client-creds
npx tsx client.ts device
```

## Grant Types

| Flow | Client | PKCE | Secret |
|------|--------|------|--------|
| Authorization Code | `webapp` | ❌ | ✅ webapp-secret |
| PKCE | `spa` | ✅ S256 | ❌ (public) |
| Client Credentials | `service-a` | N/A | ✅ service-a-secret |
| Device Code | `webapp` | N/A | N/A |

## Files

| File | Purpose |
|------|---------|
| `server.ts` | Full OAuth 2.0 Authorization Server |
| `client.ts` | Client demonstrating all grant types |
