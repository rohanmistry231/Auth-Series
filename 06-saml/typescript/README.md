# TypeScript — SAML 2.0

## Requirements

- Node.js 18+
- `npm install @xmldom/xmldom xml-crypto`

## Run the Identity Provider (IdP)

```bash
npx tsx idp.ts
```

Port 8000 — login form, generates signed SAML Responses.

## Run the Service Provider (SP)

```bash
npx tsx sp.ts
```

Port 8001 — ACS endpoint that validates SAML Responses.

## Test

1. `npx tsx idp.ts` + `npx tsx sp.ts`
2. Open `http://localhost:8001/login`
3. Click to IdP, log in as `alice`

## Files

| File | Purpose |
|------|---------|
| `idp.ts` | SAML IdP — signs assertions with xml-crypto |
| `sp.ts` | SAML SP — validates SAML Response |
