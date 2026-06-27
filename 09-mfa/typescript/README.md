# TypeScript — MFA / TOTP

## Requirements

- Node.js 18+
- `npm install otplib`

## Run the Server

```bash
export ALICE_PASSWORD="super-secret"

npx tsx server.ts
```

## Run the Client

```bash
npx tsx client.ts
```

## Files

| File | Purpose |
|------|---------|
| `server.ts` | Node.js server with TOTP MFA |
| `client.ts` | Demonstrates full MFA lifecycle |
