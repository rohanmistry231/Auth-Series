# Go — Basic Auth

## Requirements

- Go 1.21+
- No external dependencies

## Run the Server

```bash
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

## Files

| File | Purpose |
|------|---------|
| `server.go` | Go net/http server with Basic Auth |
| `client.go` | Go net/http client demonstrating all scenarios |
