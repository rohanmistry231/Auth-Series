# Go — Session & Cookie Auth

## Requirements

- Go 1.21+
- No external dependencies

## Run the Server

```bash
export SESSION_SECRET="a-secure-random-secret-at-least-32-chars"
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
| Session store | In-memory `map` with `sync.RWMutex` |
| Cookie signing | HMAC-SHA256 |
| Session ID | CSPRNG-generated 32 hex chars |
| Absolute TTL | 1 hour |
| Idle TTL | 15 minutes |
| CSRF | Synchronizer token pattern |

## Files

| File | Purpose |
|------|---------|
| `server.go` | Go net/http server with session + cookie auth |
| `client.go` | Go net/http client with cookie jar |
