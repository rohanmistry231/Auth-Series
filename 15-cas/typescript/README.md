# TypeScript — CAS SSO

## Requirements

- Node.js 18+

## Run the Server

```bash
npx tsx server.ts
```

Open `http://127.0.0.1:8000` and click the protected resource link.

## Run the Client

```bash
npx tsx client.ts
```

## Files

| File | Purpose |
|------|---------|
| `server.ts` | Node.js CAS server + protected app |
| `client.ts` | Browser-simulated CAS login flow |
