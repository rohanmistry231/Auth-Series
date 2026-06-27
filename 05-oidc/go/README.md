# Go — OpenID Connect

## Requirements

- Go 1.21+
- `go get github.com/golang-jwt/jwt/v5`

## Run the Provider (OP)

```bash
export ALICE_PASSWORD="super-secret"
export RP_SECRET="rp-secret"

go run provider.go
```

## Run the Relying Party (RP)

```bash
go run rp.go
```

## Files

| File | Purpose |
|------|---------|
| `provider.go` | OIDC Provider with RS256 ID Tokens |
| `rp.go` | Relying Party with manual JWKS-based signature verification |
