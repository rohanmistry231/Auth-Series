# Go — OAuth 2.0

## Requirements

- Go 1.21+
- `go get github.com/golang-jwt/jwt/v5`

## Run the Server (Authorization Server)

```bash
export ALICE_PASSWORD="super-secret"
export BOB_PASSWORD="another-secret"
export WEBAPP_SECRET="webapp-secret"
export SERVICE_A_SECRET="service-a-secret"

go run server.go
```

## Run the Client

In another terminal:

```bash
# Run all flows
go run client.go all

# Run individual flow
go run client.go auth-code
go run client.go pkce
go run client.go client-creds
go run client.go device
```

## Grant Types

| Flow | Client | PKCE | Secret |
|------|--------|------|--------|
| Authorization Code | `webapp` | ❌ | ✅ webapp-secret |
| PKCE | `spa` | ✅ S256 | ❌ (public) |
| Client Credentials | `service-a` | N/A | ✅ service-a-secret |
| Device Code | `webapp` | N/A | N/A |

## Files

| File | Purpose |
|------|---------|
| `server.go` | Full OAuth 2.0 Authorization Server |
| `client.go` | Client demonstrating all grant types |
