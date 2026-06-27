# Session & Cookies — Cheat Sheet

## Cookie Header Format

```
Set-Cookie: session_id=abc123; HttpOnly; Secure; SameSite=Strict; Max-Age=3600; Path=/
Cookie: session_id=abc123
```

## Required Cookie Flags

| Flag | Value | Why |
|------|-------|-----|
| `HttpOnly` | (present) | Block JS access (XSS) |
| `Secure` | (present) | HTTPS only |
| `SameSite` | `Strict` or `Lax` | CSRF prevention |
| `Max-Age` | seconds | Limited lifetime |
| `Path` | `/` | Scope restriction |

## Quick Commands

### cURL (manual cookie handling)
```bash
# Login + capture cookie
curl -c cookies.txt -X POST -d '{"username":"alice","password":"secret"}' \
  -H "Content-Type: application/json" http://localhost:8000/login

# Use stored cookie
curl -b cookies.txt http://localhost:8000/me
```

## Session ID Best Practices

```
1. Generate: crypto/random (CSPRNG, 128+ bits)
2. Sign:    HMAC-SHA256(session_secret, session_id)
3. Store:   Redis with TTL
4. Send:    HttpOnly + Secure + SameSite cookie
5. Rotate:  On login (prevents session fixation)
6. Kill:    On logout (delete server-side AND clear cookie)
```

## CSRF Token Flow

```
GET /csrf-token  →  server returns token + stores in session
POST /data       →  client sends token in body → server compares
```

## ⚠️ Common Mistakes

- ❌ Not regenerating session ID after login
- ❌ Missing `HttpOnly` flag (XSS can steal cookie)
- ❌ Using `SameSite=None` without `Secure`
- ❌ Only clearing cookie on logout (server store still has it)
- ❌ Long session lifetimes (reduce window of compromise)
- ❌ Storing sensitive data in unsigned cookies
