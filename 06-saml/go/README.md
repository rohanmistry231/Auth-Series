# Go — SAML 2.0

## Requirements

- Go 1.21+
- No external dependencies

## Run the Identity Provider (IdP)

```bash
export ALICE_PASSWORD="super-secret"

go run idp.go
```

Port 8000 — login form, generates signed SAML Responses.

## Run the Service Provider (SP)

```bash
go run sp.go
```

Port 8001 — ACS endpoint that validates SAML Response.

## Test

1. Start IdP + SP in separate terminals
2. Open `http://localhost:8001/login`
3. Click through to IdP, log in as `alice`

## Files

| File | Purpose |
|------|---------|
| `idp.go` | SAML IdP — generates RSA-signed XML assertions |
| `sp.go` | SAML SP — validates and displays SAML attributes |
