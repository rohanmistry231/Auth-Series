# Go — Magic Link Passwordless Auth

## Requirements

- Go 1.21+

## Run the Server

```bash
export MAGIC_LINK_SECRET="my-secret-key"
export TOKEN_TTL_SECONDS=900

go run server.go
```

## Run the Client

```bash
go run client.go
```

## Files

| File | Purpose |
|------|---------|
| `server.go` | Go net/http magic link server |
| `client.go` | Demonstrates request + verify flow |
