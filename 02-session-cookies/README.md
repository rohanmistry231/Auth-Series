# 02 — Session & Cookie Authentication

Session-based authentication uses a server-side session identified by a cookie. It is the dominant auth mechanism for traditional server-rendered web applications.

---

## 1. Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                    SESSION ARCHITECTURE                        │
│                                                               │
│  ┌──────────┐                 ┌───────────────────────────┐   │
│  │  CLIENT  │   Cookie:       │        SERVER             │   │
│  │  Browser │───session_id───>│                           │   │
│  │          │                 │  ┌─────────────────────┐  │   │
│  │  Stores  │                 │  │   Session Store     │  │   │
│  │  cookie  │                 │  │  (Redis / DB / Mem) │  │   │
│  │          │                 │  └─────────────────────┘  │   │
│  └──────────┘                 │         │                 │   │
│                               │         ▼                 │   │
│                               │  ┌─────────────────────┐  │   │
│                               │  │   Session Data      │  │   │
│                               │  │   { userId, role,   │  │   │
│                               │  │     expiresAt }     │  │   │
│                               │  └─────────────────────┘  │   │
│                               └───────────────────────────┘   │
└───────────────────────────────────────────────────────────────┘
```

---

## 2. State Machine

```
     ┌──────────────┐
     │   ANONYMOUS  │  — no session cookie
     └──────┬───────┘
            │ POST /login { username, password }
            ▼
     ┌──────────────┐
     │ VALIDATING   │  — checking credentials
     └──────┬───────┘
            │
     ┌──────┴───────┐
     ▼              ▼
┌──────────┐  ┌──────────┐
│ ACTIVE   │  │ REJECTED │  — 401, may retry
└────┬─────┘  └──────────┘
     │
     ├── logout (explicit)
     ├── idle timeout (no activity for N minutes)
     ├── absolute timeout (session created > N hours ago)
     ├── revoke (admin action)
     └── concurrent session limit exceeded
     │
     ▼
┌──────────┐
│ TERMINATED│
└──────────┘
```

---

## 3. Cookie Security Flags — Complete Reference

```
Set-Cookie: session_id=abc123def456;
  Expires=Wed, 21 Oct 2026 07:28:00 GMT;   ← exact expiry
  Max-Age=86400;                             ← seconds from now (preferred)
  Domain=.example.com;                       ← which domains (omit for origin-only)
  Path=/;                                    ← which paths
  Secure;                                    ← HTTPS only
  HttpOnly;                                  ← no JavaScript access
  SameSite=Strict;                           ← CSRF protection
  Priority=High;                             ← Chrome priority hint
```

### SameSite in detail

| Value | Same-site `<a>` | Same-site form | Cross-site `<a>` | Cross-site form | Cross-site iframe |
|-------|----------------|----------------|------------------|-----------------|-------------------|
| `Strict` | ✅ | ✅ | ❌ | ❌ | ❌ |
| `Lax` | ✅ | ✅ | ✅ GET only | ❌ | ❌ |
| `None` (Secure) | ✅ | ✅ | ✅ | ✅ | ✅ |

**Recommendation:** `SameSite=Lax` for most session cookies (allows top-level navigation). `SameSite=Strict` for sensitive operations (admin panels).

---

## 4. Session Storage — Comparison

| Store | Read Latency | Write Latency | Persistence | Cluster Ready | Eviction |
|-------|-------------|--------------|-------------|---------------|----------|
| In-Memory (local) | <1µs | <1µs | ❌ (process crash) | ❌ | N/A |
| Redis (in-memory) | <1ms | <1ms | Configurable | ✅ | TTL |
| Memcached | <1ms | <1ms | ❌ (restart) | ✅ | LRU |
| Database (PostgreSQL) | 1–10ms | 1–10ms | ✅ | ✅ | Manual |
| Encrypted Cookie | 0 (client) | 0 (client) | ✅ (client) | ✅ | N/A |

### Session Serialization

```javascript
// Recommended: JSON
{
  "id": "sess_abc123",
  "userId": "u_456",
  "role": "admin",
  "createdAt": 1718000000000,
  "lastActivity": 1718000500000,
  "ip": "203.0.113.42",
  "userAgent": "Mozilla/5.0 ...",
  "mfaVerified": true,
  "expiresAt": 1718086400000
}
```

---

## 5. Threat Model — Session Hijacking & Fixation

### Session Hijacking

```
Attack vector:     Steal session cookie via XSS, network sniffing, or physical access
Severity:          Critical (attorney gains full access)
Prevention:
  - HttpOnly flag (block XSS access)
  - Secure flag (require HTTPS)
  - SameSite flag (block CSRF)
  - Fingerprint validation (IP, User-Agent)
  - Short session TTL
```

### Session Fixation

```
Attack:            1. Attacker obtains a valid session ID
                   2. Attacker tricks victim into using that session ID
                   3. Victim logs in with attacker's session
                   4. Attacker now has an authenticated session

Prevention:
  - Regenerate session ID on login
  - Regenerate session ID on privilege escalation
  - Never accept session ID from URL parameters
```

---

## 6. Code Examples

### Java (Spring Boot + Redis)

```java
// build.gradle: implementation 'org.springframework.session:spring-session-data-redis'

@Configuration
@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 1800)
public class SessionConfig {

    @Bean
    public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
        return new GenericJackson2JsonRedisSerializer();
    }

    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookieName("session_id");
        serializer.setUseHttpOnlyCookie(true);
        serializer.setUseSecureCookie(true);        // HTTPS only
        serializer.setSameSite("Strict");            // CSRF protection
        serializer.setCookiePath("/");
        serializer.useBase64Encoding(false);
        serializer.setCookieMaxAge(24 * 60 * 60);   // 24 hours
        return serializer;
    }
}

@RestController
public class SessionController {

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody LoginRequest request,
            HttpSession session) {

        // Regenerate session ID to prevent fixation
        session.invalidate();
        session = request.getSession(true);

        User user = authenticate(request.username(), request.password());
        if (user == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }

        session.setAttribute("userId", user.getId());
        session.setAttribute("role", user.getRole());
        session.setAttribute("mfaVerified", false);

        return ResponseEntity.ok(Map.of("message", "Logged in"));
    }

    @GetMapping("/dashboard")
    public ResponseEntity<?> dashboard(HttpSession session) {
        String userId = (String) session.getAttribute("userId");
        if (userId == null) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(Map.of("user", userId));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpSession session) {
        session.invalidate();
        return ResponseEntity.ok(Map.of("message", "Logged out"));
    }
}
```

### Python (Flask)

```python
from flask import Flask, session, request, abort
from flask_session import Session
import redis

app = Flask(__name__)
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_REDIS"] = redis.from_url("redis://localhost:6379")
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)
Session(app)

@app.route("/login", methods=["POST"])
def login():
    username = request.json["username"]
    password = request.json["password"]
    if not authenticate(username, password):
        abort(401)

    # Regenerate session
    session.clear()
    session["user_id"] = "u_456"
    session["role"] = "admin"
    return {"message": "Logged in"}

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        abort(401)
    return {"user": session["user_id"]}
```

### TypeScript (Express + Redis)

```typescript
import session from 'express-session';
import connectRedis from 'connect-redis';
import { createClient } from 'redis';

const redisClient = createClient({ url: process.env.REDIS_URL });
const RedisStore = connectRedis(session);

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET!,
  name: 'session_id',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000,  // 24 hours
    path: '/',
  },
}));
```

### Go (gorilla/sessions + Redis)

```go
import (
    "github.com/gorilla/sessions"
    "github.com/boj/redistore"
)

var store *redistore.RediStore

func init() {
    var err error
    store, err = redistore.NewRediStore(10, "tcp", ":6379", "",
        []byte(os.Getenv("SESSION_SECRET")))
    if err != nil { log.Fatal(err) }
    store.Options = &sessions.Options{
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteStrictMode,
        MaxAge:   86400,
    }
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session_id")
    // Regenerate
    session.Options.MaxAge = -1 // delete old
    session.Save(r, w)

    session, _ = store.New(r, "session_id")
    session.Values["userId"] = "u_456"
    session.Values["role"] = "admin"
    session.Save(r, w)
}

func requireAuth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        session, _ := store.Get(r, "session_id")
        if session.Values["userId"] == nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

---

## 7. References

- [RFC 6265 — HTTP State Management Mechanism](https://datatracker.ietf.org/doc/html/rfc6265)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP CSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [SameSite: Same Origin Policy](https://web.dev/articles/samesite-cookies-explained)
