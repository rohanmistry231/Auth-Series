# 17 — Security Best Practices

Security is not a feature — it is a **property** of the entire system. This module consolidates the non-negotiable practices that must apply across every authentication mechanism.

---

## 1. Password Storage — Algorithm Comparison

| Algorithm | Type | Memory Hard | GPU/ASIC Resistant | Recommended Work Factor | Status |
|-----------|------|-------------|--------------------|------------------------|--------|
| **Argon2id** | PHC Winner | Yes (CPU + memory) | Yes | t=3, m=65536KB, p=4 | ✅ Preferred |
| **bcrypt** | Adaptive | No (CPU only) | Partial | cost=12+ | ✅ Acceptable |
| **scrypt** | Memory-hard | Yes | Yes | N=2^14, r=8, p=1 | ✅ Good |
| **PBKDF2-HMAC-SHA256** | Iterated | No | No (easy GPU) | 600,000+ iterations | ⚠️ Legacy |
| **MD5 / SHA-1 / SHA-256** | Fast hash | No | **Trivially parallelized** | N/A | ❌ Never |

### Implementation (Argon2id)

```java
// Java (argon2-jvm)
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

public class PasswordService {

    private final Argon2 argon2 = Argon2Factory.create(
        Argon2Factory.Argon2Types.ARGON2id, 32, 64);

    public String hash(char[] password) {
        return argon2.hash(3,       // iterations
                          65536,   // memory in KB
                          4,       // parallelism
                          password);
    }

    public boolean verify(String hash, char[] password) {
        return argon2.verify(hash, password);
    }
}
```

```python
# Python (argon2-cffi)
from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,  # KB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

hash = ph.hash("correct horse battery staple")
ph.verify(hash, "correct horse battery staple")  # True
```

---

## 2. OWASP ASVS (Application Security Verification Standard) Mapping

### Level 1 (Automated — minimum for any app)

| ASVS # | Requirement | Module |
|--------|-------------|--------|
| 2.1.1 | Verify all passwords are hashed with a one-way algorithm | 17-Security |
| 2.2.1 | Verify passwords are at least 8 characters | 17-Security |
| 2.3.1 | Verify rate limiting is applied to authentication endpoints | 17-Security |
| 2.5.1 | Verify that credentials are transported using TLS | All modules |
| 3.1.1 | Verify session IDs are sufficiently random (≥ 64 bits) | 02-Sessions |
| 3.2.1 | Verify session IDs are regenerated on login | 02-Sessions |

### Level 2 (Defense-in-depth — most applications)

| ASVS # | Requirement | Module |
|--------|-------------|--------|
| 2.2.2 | Verify multi-factor authentication is supported | 09-MFA |
| 2.4.1 | Verify that logout terminates all sessions | 02-Sessions |
| 2.6.1 | Verify JWTs are signed and validated correctly | 03-JWT |
| 3.3.1 | Verify cookies are HttpOnly + Secure + SameSite | 02-Sessions |
| 3.5.1 | Verify session inactivity timeout is enforced | 02-Sessions |

### Level 3 (High-security — financial, healthcare)

| ASVS # | Requirement | Module |
|--------|-------------|--------|
| 2.1.3 | Verify password storage uses Argon2id | 17-Security |
| 2.8.1 | Verify step-up or adaptive authentication is implemented | 09-MFA |
| 2.9.1 | Verify that compromised credentials are detected | 17-Security |
| 4.1.1 | Verify access controls are enforced at every request | 16-Patterns |

---

## 3. Rate Limiting — Production Configuration

```java
// Java (Bucket4j)
@Configuration
public class RateLimitConfig {

    @Bean
    public FilterRegistrationBean<OncePerRequestFilter> rateLimitFilter() {
        FilterRegistrationBean<OncePerRequestFilter> bean = new FilterRegistrationBean<>();
        bean.setFilter(new OncePerRequestFilter() {
            private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

            @Override
            protected void doFilterInternal(
                    HttpServletRequest request,
                    HttpServletResponse response,
                    FilterChain chain) throws IOException, ServletException {

                String key = request.getRemoteAddr();
                if (request.getRequestURI().contains("/login")) {
                    key = "login:" + request.getRemoteAddr();
                }

                Bucket bucket = buckets.computeIfAbsent(key, k ->
                    Bucket4j.builder()
                        .addLimit(Bandwidth.simple(5, Duration.ofMinutes(1)))  // 5 req/min
                        .build());

                if (bucket.tryConsume(1)) {
                    chain.doFilter(request, response);
                } else {
                    response.setStatus(429);
                    response.setHeader("Retry-After", "60");
                    response.getWriter().write("Rate limit exceeded");
                }
            }
        });
        bean.addUrlPatterns("/login", "/api/login", "/auth/*");
        return bean;
    }
}
```

---

## 4. Security Headers — Complete Reference

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

---

## 5. Audit Logging

```java
// Structured audit log (JSON) — never log secrets
@Component
public class AuditLogger {

    private static final Logger log = LoggerFactory.getLogger("audit");

    public void logAuthEvent(AuthEvent event) {
        // NEVER include: passwords, tokens, secrets
        // ALWAYS include: timestamp, event type, user, IP, outcome

        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("@timestamp", Instant.now().toString());
        entry.put("event", event.getType());
        entry.put("user", event.getUserId());
        entry.put("ip", event.getIpAddress());
        entry.put("userAgent", event.getUserAgent());
        entry.put("outcome", event.getOutcome());  // SUCCESS / FAILURE
        entry.put("reason", event.getFailureReason());

        log.info("{}", JsonUtils.toJson(entry));
    }
}

public enum AuthEvent {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGOUT,
    MFA_SETUP,
    MFA_VERIFY,
    PASSWORD_RESET,
    TOKEN_REFRESH,
    TOKEN_REVOKE,
    ACCOUNT_LOCKED,
    PRIVILEGE_ESCALATION
}
```

---

## 6. Security Checklist

- [x] Passwords hashed with Argon2id or bcrypt (cost 12+)
- [ ] TLS 1.2+ enforced across all endpoints (HSTS enabled)
- [ ] Secure, HttpOnly, SameSite cookies
- [ ] Rate limiting on all auth endpoints
- [ ] Account lockout after N failed attempts
- [ ] MFA available (required for admin roles)
- [ ] Session idle timeout (15–30 min) + absolute timeout
- [ ] Session regeneration on login and privilege escalation
- [ ] JWT signed (asymmetric preferred); `alg` validated; claims checked
- [ ] JWKS properly managed and rotated (overlapping key periods)
- [ ] Auth events logged (structured, no secrets)
- [ ] Secrets in vault / secret manager (never in code or config)
- [ ] CORS properly restricted (explicit origins, not `*`)
- [ ] Input validation and output encoding
- [ ] Regular dependency updates (Snyk, Dependabot)
- [ ] CSRF protection (SameSite cookies + CSRF tokens for stateful apps)

---

## 7. References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B — Digital Identity](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Top 10 — 2021](https://owasp.org/Top10/)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [TLS Best Practices (SSLLabs)](https://www.ssllabs.com/projects/best-practices/index.html)
