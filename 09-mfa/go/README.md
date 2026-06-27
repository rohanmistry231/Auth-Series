# Go — MFA / TOTP

## Requirements

- Go 1.21+
- `go get github.com/pquerna/otp`

## Run the Server

```bash
export ALICE_PASSWORD="super-secret"

go run server.go
```

## Run the Client

```bash
go run client.go
```

## Files

| File | Purpose |
|------|---------|
| `server.go` | Go net/http server with TOTP MFA |
| `client.go` | Demonstrates full MFA lifecycle |
