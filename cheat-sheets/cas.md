# CAS — Cheat Sheet

## Protocol Flow

```
1. User visits protected app (service)
2. App redirects to CAS /login?service=APP_URL
3. User logs in on CAS server
4. CAS redirects back: APP_URL?ticket=ST-xxxx
5. App back-channel validates:
   GET /validate?ticket=ST-xxxx&service=APP_URL
6. CAS responds: "yes\nusername" or "no\nreason"
7. App sets session cookie
```

## Ticket Format

```
ST-<random-hex>     (Service Ticket — single use, 5 min TTL)
PGT-<random-hex>    (Proxy Granting Ticket — CAS 2.0+)
PT-<random-hex>     (Proxy Ticket)
```

## Key Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/login` | GET | Login form |
| `/login` | POST | Authenticate + issue ticket |
| `/validate` | GET | Validate ticket (CAS 1.0) |
| `/serviceValidate` | GET | Validate + attributes (CAS 2.0) |
| `/logout` | GET | Single logout |

## Security

| Rule | Why |
|------|-----|
| Single-use tickets | Prevent replay |
| 5 min ticket TTL | Limit attack window |
| Back-channel validation | Prevent MITM ticket theft |
| Validate service URL | Prevent redirect hijacking |
| HTTPS in production | Ticket visible in URL |
