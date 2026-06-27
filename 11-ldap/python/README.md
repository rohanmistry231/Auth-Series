# Python — LDAP Auth

## Requirements

- Python 3.10+
- `pip install "fastapi[standard]" uvicorn httpx ldap3`

## Run the Server

```bash
export LDAP_HOST=ldap.forumsys.com
export LDAP_PORT=389
export LDAP_BASE_DN=dc=example,dc=com

python server.py
```

## Run the Client

```bash
python client.py
```

## Configuration

| Env Var | Default | Purpose |
|---------|---------|---------|
| `LDAP_HOST` | `ldap.forumsys.com` | LDAP server host |
| `LDAP_PORT` | `389` | LDAP port |
| `LDAP_USE_SSL` | `false` | Use LDAPS |
| `LDAP_BASE_DN` | `dc=example,dc=com` | Search base |
| `LDAP_BIND_DN` | `cn=read-only-admin,dc=example,dc=com` | Service bind DN |
| `LDAP_BIND_PASSWORD` | `password` | Service bind password |
| `LDAP_USER_FILTER` | `(&(uid={username})(objectClass=person))` | User search filter |

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/login` | POST | LDAP BIND auth → session |
| `/search` | POST | LDAP search (admin) |

## Files

| File | Purpose |
|------|---------|
| `server.py` | FastAPI LDAP auth server |
| `client.py` | Demo login + search client |
