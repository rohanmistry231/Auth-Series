# TypeScript — Magic Link Passwordless Auth

## Requirements

- Node.js 18+

## Run the Server

```bash
export MAGIC_LINK_SECRET="my-secret-key"
export TOKEN_TTL_SECONDS=900

npx tsx server.ts
```

## Run the Client

```bash
npx tsx client.ts
```

## Files

| File | Purpose |
|------|---------|
| `server.ts` | Node.js magic link server |
| `client.ts` | Demonstrates request + verify flow |
