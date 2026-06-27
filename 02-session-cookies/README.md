# 02 — Session & Cookie Authentication

Session-based auth is the traditional approach: after validating credentials, the server creates a session, stores it server-side, and sends the session ID to the client via a cookie. The client presents that cookie on subsequent requests.

## How It Works

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    C->>S: POST /login<br>{ username, password }
    S->>S: Validate credentials<br>Generate session_id<br>Store in DB/Redis
    S-->>C: 200 OK<br>Set-Cookie: session_id=abc...123
    Note over C: Cookie saved (HttpOnly, Secure, SameSite)

    C->>S: GET /dashboard<br>Cookie: session_id=abc...123
    S->>S: Lookup session<br>Check expiry
    S-->>C: 200 OK (dashboard data)

    C->>S: POST /logout<br>Cookie: session_id=abc...123
    S->>S: Delete session from store
    S-->>C: 200 OK<br>Set-Cookie: session_id=; Max-Age=0
```

```
Client                                     Server
  |                                           |
  |-- POST /login -------------------------->|
  |     { username, password }               |
  |                                           |  Validate credentials
  |                                           |  Generate session_id (random)
  |                                           |  Store { user, role, exp } in DB/Redis/memory
  |<-- 200 OK --------------------------------|
  |     Set-Cookie: session_id=abc...123      |  (HttpOnly, Secure, SameSite)
  |                                           |
  |-- GET /dashboard ----------------------->|
  |     Cookie: session_id=abc...123         |
  |                                           |  Lookup session by ID
  |                                           |  Check expiry
  |<-- 200 OK --------------------------------|
  |     (dashboard data)                      |
  |                                           |
  |-- POST /logout ------------------------->|
  |     Cookie: session_id=abc...123         |
  |                                           |  Delete session from store
  |<-- 200 OK --------------------------------|
  |     Set-Cookie: session_id=; Max-Age=0    |  Clear client cookie
```

## Session ID Requirements

| Property | Why |
|----------|-----|
| **High entropy** (128+ bits) | Prevent guessing/prediction |
| **Random** (CSPRNG) | No pattern attackers can exploit |
| **Unique per session** | Prevent collisions |
| **Short-lived** | Limit window of compromise |

## Session Storage Strategies

| Storage | Latency | Persistence | Scale-out | Revocation |
|---------|---------|-------------|-----------|------------|
| **In-memory** (dict/map) | 🟢 Fast | 🔴 Lost on restart | 🔴 Single node | ✅ Instant |
| **Database** (Postgres/MySQL) | 🟡 Medium | 🟢 Persistent | 🟢 Yes | ✅ Instant |
| **Redis / Memcached** | 🟢 Fast | 🟡 TTL-driven | 🟢 Yes | ✅ Instant |
| **Signed cookie** (stateless) | 🟢 Fast | 🟢 Persistent | 🟢 Yes | 🔴 Can't revoke |

> **For production:** Use Redis. It's fast, supports TTL, survives restarts, and is the de facto standard for session storage.

## Cookie Flags (Security)

| Flag | Purpose | Must |
|------|---------|------|
| `HttpOnly` | Blocks JavaScript access (XSS protection) | ✅ Yes |
| `Secure` | Only sent over HTTPS | ✅ Yes |
| `SameSite=Strict` | Prevents CSRF by blocking cross-site sends | ✅ Yes |
| `SameSite=Lax` | Allows top-level GET navigation (fallback) | ✅ Yes |
| `Path=/` | Restricts cookie scope | ✅ Yes |
| `Max-Age` / `Expires` | Finite lifetime | ✅ Yes |

## CSRF Protection

Cookies are **automatically sent** by the browser with every request to the domain — even if the request originates from a different site. This is the basis of **Cross-Site Request Forgery (CSRF)**.

### Mitigations

| Technique | How it works |
|-----------|-------------|
| **Synchronizer token** | Server embeds a CSRF token in forms; validates on submit |
| **SameSite cookie** | Browser won't send the cookie for cross-site requests |
| **Double-submit cookie** | Send CSRF token in both cookie and header; server checks match |
| **Origin / Referer check** | Validate the `Origin` header matches your domain |

## Security Considerations

- **Regenerate session ID on login** — Prevents [session fixation](https://owasp.org/www-community/attacks/Session_fixation)
- **Set absolute + idle timeouts** — Force re-auth after N minutes idle
- **Logout must delete server-side session** — Clearing the cookie alone is not enough
- **Rate-limit login** — Prevent brute-force attacks
- **Never store sensitive data in plain cookies** — If you must, sign + encrypt

## Code Examples

| Language | Server | Client |
|----------|--------|--------|
| [Python](python/) | FastAPI + in-memory store | httpx with cookie jar |
| [TypeScript](typescript/) | Node.js HTTP + in-memory store | fetch with `credentials: include` |
| [Go](go/) | net/http + in-memory store | net/http with `Jar` |

## References

- [RFC 6265 — HTTP Cookies](https://datatracker.ietf.org/doc/html/rfc6265)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Mozilla MDN — Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
- [The Budapest Reference — session fixation](https://owasp.org/www-community/attacks/Session_fixation)
