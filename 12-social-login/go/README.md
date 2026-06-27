# Go — Social Login

## Requirements

- Go 1.21+

## Run the Server

```bash
go run server.go
```

Open `http://127.0.0.1:8000` and click "Sign in with Google" or "Sign in with GitHub".

## Run the Client

```bash
go run client.go
```

## Files

| File | Purpose |
|------|---------|
| `server.go` | Go app + mock social providers |
| `client.go` | Automated OAuth flow demo |
