# Go — CAS SSO

## Requirements

- Go 1.21+

## Run the Server

```bash
go run server.go
```

Open `http://127.0.0.1:8000` and click the protected resource link.

## Run the Client

```bash
go run client.go
```

## Files

| File | Purpose |
|------|---------|
| `server.go` | Go CAS server + protected app |
| `client.go` | Browser-simulated CAS login flow |
