# Go — LDAP Auth

## Requirements

- Go 1.21+
- `go get gopkg.in/ldap.v3`

## Run the Server

```bash
export LDAP_HOST=ldap.forumsys.com
export LDAP_PORT=389
export LDAP_BASE_DN=dc=example,dc=com

go run server.go
```

## Run the Client

```bash
go run client.go
```

## Configuration

| Env Var | Default | Purpose |
|---------|---------|---------|
| `LDAP_HOST` | `ldap.forumsys.com` | LDAP server host |
| `LDAP_PORT` | `389` | LDAP port |
| `LDAP_BASE_DN` | `dc=example,dc=com` | Search base |
| `LDAP_BIND_DN` | `cn=read-only-admin,dc=example,dc=com` | Service bind DN |
| `LDAP_BIND_PASSWORD` | `password` | Service bind password |
| `LDAP_USER_FILTER` | `(&(uid={username})(objectClass=person))` | User search filter |

## Files

| File | Purpose |
|------|---------|
| `server.go` | Go net/http LDAP auth server |
| `client.go` | Demo login + search client |
