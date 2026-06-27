# TypeScript — OpenID Connect

## Requirements

- Node.js 18+
- No external dependencies

## Run the Provider (OP)

```bash
export ALICE_PASSWORD="super-secret"
export RP_SECRET="rp-secret"

npx tsx provider.ts
```

## Run the Relying Party (RP)

```bash
npx tsx rp.ts
```

## Files

| File | Purpose |
|------|---------|
| `provider.ts` | OIDC Provider with ID Token + Discovery |
| `rp.ts` | Relying Party with full ID Token validation |
