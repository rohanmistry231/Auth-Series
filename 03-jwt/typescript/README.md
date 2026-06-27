# TypeScript — JWT Auth

## Requirements

- Node.js 18+
- No external dependencies (uses built-in `crypto` for RSA + HMAC)

## Run the Server

```bash
export JWT_HS256_SECRET="a-very-secure-secret-at-least-32-chars-long"
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
| Access token signing | RS256 (RSA 2048-bit) via `crypto.generateKeyPairSync` |
| Refresh token signing | HS256 via `crypto.createHmac` |
| JWT encoding/decoding | Manual implementation with `Buffer` and `crypto` |
| Refresh token storage | In-memory `Map` (keyed by `jti`) |
| Refresh token rotation | Old token invalidated on each use |
| JWKS endpoint | `crypto.createPublicKey().export({ format: 'jwk' })` |

## Files

| File | Purpose |
|------|---------|
| `server.ts` | Node.js HTTP server with full JWT auth |
| `client.ts` | Fetch client demonstrating login, access, refresh |
