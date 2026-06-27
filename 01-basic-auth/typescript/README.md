# TypeScript — Basic Auth

## Requirements

- Node.js 18+ (for built-in `fetch`)
- No external dependencies

## Run the Server

```bash
export ALICE_PASSWORD="super-secret"
export BOB_PASSWORD="another-secret"

npx tsx server.ts
```

## Run the Client

In another terminal:

```bash
export AUTH_USERNAME="alice"
export AUTH_PASSWORD="password-alice"

npx tsx client.ts
```

## Files

| File | Purpose |
|------|---------|
| `server.ts` | Node.js HTTP server with Basic Auth |
| `client.ts` | Fetch client demonstrating all scenarios |
