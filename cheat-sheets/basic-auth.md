# Basic Auth — Cheat Sheet

## Header Format

```
Authorization: Basic base64(username:password)
```

## Encoding

```
username:password   →   base64   →   Authorization header

alice:secret123     →   YWxpY2U6c2VjcmV0MTIz    →   Basic YWxpY2U6c2VjcmV0MTIz
```

## Server Response (Unauthorized)

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Protected Area"
```

## Quick Commands

### cURL
```bash
curl -u alice:secret123 http://localhost:8000/protected
curl -H "Authorization: Basic $(echo -n alice:secret123 | base64)" http://localhost:8000/protected
```

### Python (httpx)
```python
httpx.get(url, auth=("alice", "secret123"))
```

### TypeScript (fetch)
```typescript
const h = "Basic " + Buffer.from("alice:secret123").toString("base64");
fetch(url, { headers: { Authorization: h } });
```

### Go (net/http)
```go
req.SetBasicAuth("alice", "secret123")
```

## ⚠️ MUST DO
- [ ] Use **HTTPS only** — Base64 is not encryption
- [ ] Never hardcode credentials in code
- [ ] Use environment variables or secret manager
- [ ] Rate-limit auth endpoints
- [ ] Use `secrets.compare_digest()` / constant-time comparison in Python

## Do NOT Use Basic Auth For
- Browser-based web apps (use sessions)
- Fine-grained permissions (use OAuth 2.0 / Bearer tokens)
- Long-lived access (use refresh tokens)
