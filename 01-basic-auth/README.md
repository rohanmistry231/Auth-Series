# 01 — HTTP Basic Authentication

RFC 7617 defines the most minimal authentication scheme in the HTTP standard. It is included here not for production use, but as a **didactic baseline** — every other scheme in this series is a response to Basic Auth's shortcomings.

---

## 1. Wire Format

```
Request:
  GET /protected HTTP/1.1
  Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l

The string "QWxhZGRpbjpPcGVuU2VzYW1l" is:
  base64("Aladdin:OpenSesame")
  → "QWxhZGRpbjpPcGVuU2VzYW1l"
```

### Character-by-character breakdown

| Offset | Byte | Meaning |
|--------|------|---------|
| 0 | `41` → `A` | First byte of base64 output |
| 1–7 | — | ... |
| *middle* | `3a` → `:` | The colon separator (ASCII 0x3A) |
| ... | — | ... |
| last | `3d` → `=` | Base64 padding |

The colon is the **only delimiter** — usernames containing `:` are ambiguous per the spec (practical servers URL-encode or reject them).

```
Server response (unauthorized):
  HTTP/1.1 401 Unauthorized
  WWW-Authenticate: Basic realm="User Visible Realm Name"
```

---

## 2. Protocol State Machine

```
     ┌────────────────┐
     │  UNPROMPTED    │  — request without Authorization header
     └───────┬────────┘
             │ server returns 401 + WWW-Authenticate
             ▼
     ┌────────────────┐
     │  CHALLENGED    │  — client SHOULD retry with credentials
     └───────┬────────┘
             │
     ┌───────┴────────┐
     ▼                ▼
┌──────────┐   ┌──────────┐
│ GRANTED  │   │ DENIED   │  — server returns 403
│ 200      │   │ 403      │    (or 401 again)
└──────────┘   └──────────┘
```

Note: there is **no logout** state. The browser caches credentials until the tab is closed.

---

## 3. Security Analysis (STRIDE)

| Threat | Severity | Explanation |
|--------|----------|-------------|
| **S**poofing | Critical | Base64 is trivial to decode; anyone who sees the header has the password |
| **T**ampering | Low | Credentials are not signed — but tampering them just breaks auth |
| **R**epudiation | Medium | No audit trail built-in |
| **I**nformation Disclosure | Critical | Base64 is not encryption. Packet capture reveals plaintext credentials |
| **D**enial of Service | Low | No state to exhaust, but login CPU cost applies |
| **E**levation of Privilege | Low | AuthZ is separate |

---

## 4. Production Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Credential capture over HTTP | Certain (on non-TLS) | Total compromise | **Enforce TLS** (HSTS) |
| Credential leakage in logs | High | Total compromise | Strip `Authorization` header from log pipelines |
| CSRF (if browser remembers) | Medium | Unauthorized actions | CSRF tokens (if using Basic with cookies) |
| Brute force | High | Account compromise | Rate limiting, account lockout |
| Replay attack | High | Account compromise | Nonce? Basic Auth has none. Use TLS to prevent capture. |

---

## 5. When (Not) to Use Basic Auth

### Acceptable use cases

- **Internal health checks**: `GET /health` with a fixed credential
- **Development / debugging**: Curl, Postman, HTTPie
- **Legacy compatibility**: Integrating with a system that only supports Basic
- **TLS-terminated internal networks**: Between services on the same Kubernetes cluster

### Unacceptable use cases

- **User-facing web applications**: Every other scheme is better
- **Public APIs**: Use Bearer tokens or API keys
- **Any endpoint without TLS**: Credentials are wire-readable
- **Mobile apps**: Credentials hard to rotate, no logout

---

## 6. Code Examples

### Java (Spring Boot Filter)

```java
@Component
public class BasicAuthFilter extends OncePerRequestFilter {

    private static final String REALM = "Auth Series";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        String auth = request.getHeader("Authorization");

        if (auth == null || !auth.startsWith("Basic ")) {
            response.setHeader("WWW-Authenticate",
                "Basic realm=\"" + REALM + "\"");
            response.sendError(401, "Unauthorized");
            return;
        }

        try {
            String base64 = auth.substring(6);
            String decoded = new String(
                Base64.getDecoder().decode(base64),
                StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');

            if (colon == -1) {
                response.sendError(400, "Invalid credential format");
                return;
            }

            String username = decoded.substring(0, colon);
            String password = decoded.substring(colon + 1);

            // Delegate to authentication provider
            if (!authenticate(username, password)) {
                response.sendError(403, "Forbidden");
                return;
            }

            request.setAttribute("auth.user", username);
            chain.doFilter(request, response);

        } catch (IllegalArgumentException e) {
            response.sendError(400, "Invalid Base64 encoding");
        }
    }

    private boolean authenticate(String username, String password) {
        // NEVER hardcode. Delegate to UserDetailsService / LDAP / etc.
        return "admin".equals(username) && "secret".equals(password);
    }
}
```

### Python (FastAPI)

```python
@app.get("/protected")
async def protected(request: Request):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Basic "):
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": "Basic realm=\"Auth Series\""}
        )

    decoded = base64.b64decode(auth.removeprefix("Basic ")).decode("utf-8")
    username, _, password = decoded.partition(":")

    if not verify_user(username, password):
        raise HTTPException(status_code=403)

    return {"user": username}
```

### TypeScript (Node.js Express)

```typescript
function basicAuth(req: Request, res: Response, next: NextFunction) {
  const auth = req.headers['authorization'];
  if (!auth?.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Auth Series"');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const decoded = Buffer.from(auth.slice(6), 'base64').toString('utf-8');
  const colon = decoded.indexOf(':');
  if (colon === -1) return res.status(400).json({ error: 'Invalid format' });

  const username = decoded.slice(0, colon);
  const password = decoded.slice(colon + 1);

  if (!verifyUser(username, password)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  req.user = username;
  next();
}
```

### Go (net/http)

```go
func BasicAuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user, pass, ok := r.BasicAuth()
        if !ok {
            w.Header().Set("WWW-Authenticate", `Basic realm="Auth Series"`)
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        if !verifyUser(user, pass) {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }
        ctx := context.WithValue(r.Context(), "user", user)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

---

## 7. References

- [RFC 7617 — The 'Basic' HTTP Authentication Scheme](https://datatracker.ietf.org/doc/html/rfc7617)
- [RFC 7235 — HTTP Authentication Framework](https://datatracker.ietf.org/doc/html/rfc7235)
- [MDN — HTTP Authentication](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication)
- [OWASP — Basic Authentication](https://owasp.org/www-community/controls/Basic_Authentication)
