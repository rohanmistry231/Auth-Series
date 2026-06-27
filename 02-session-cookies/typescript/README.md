# TypeScript — Session & Cookie Auth

## Requirements

- Node.js 18+ (for built-in `fetch`)
- No external dependencies

## Run the Server

```bash
export SESSION_SECRET="a-secure-random-secret-at-least-32-chars"
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

## Architecture

| Component | Detail |
|-----------|--------|
| Session store | In-memory `Map` (not for production) |
| Cookie signing | HMAC-SHA256 via `crypto.createHmac` |
| Session ID | CSPRNG-generated UUID via `crypto.randomUUID` |
| Absolute TTL | 1 hour |
| Idle TTL | 15 minutes |
| CSRF | Synchronizer token pattern |

## Files

| File | Purpose |
|------|---------|
| `server.ts` | Node.js HTTP server with session + cookie auth |
| `client.ts` | Fetch client demonstrating full lifecycle |
