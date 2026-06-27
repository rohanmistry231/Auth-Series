# Go — JWT Auth

## Requirements

- Go 1.21+
- `go get github.com/golang-jwt/jwt/v5`

## Run the Server

```bash
export JWT_HS256_SECRET="a-very-secure-secret-at-least-32-chars-long"
export ALICE_PASSWORD="super-secret"
export BOB_PASSWORD="another-secret"

go run server.go
```

## Run the Client

In another terminal:

```bash
export AUTH_USERNAME="alice"
export AUTH_PASSWORD="password-alice"

go run client.go
```

## Architecture

| Component | Detail |
|-----------|--------|
| Access token signing | RS256 (RSA 2048-bit) via `crypto/rsa` |
| Refresh token signing | HS256 via `golang-jwt/jwt` |
| Refresh token storage | In-memory `map` with `sync.RWMutex` |
| Refresh token rotation | Old token invalidated on each use |
| JWKS endpoint | RSA public key in JWK format |

## Files

| File | Purpose |
|------|---------|
| `server.go` | Go net/http server with full JWT auth |
| `client.go` | Go net/http client demonstrating full lifecycle |
