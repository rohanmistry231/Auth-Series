# 16 — Authentication Design Patterns & Architecture

Auth is not just a library choice — it is an **architectural decision**. This module covers the deployment topologies, token strategies, and integration patterns used in production.

---

## 1. Deployment Topologies

### 1.1 Monolithic Auth (Server-Side Sessions)

```
┌────────────────────────────────────────┐
│           APPLICATION SERVER            │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  /login   /logout   /register    │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  Session Store (Redis / DB)      │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │  /api/users   /api/orders        │  │
│  └───────────────────────────────────┘  │
└────────────────────────────────────────┘
```

### 1.2 Dedicated Auth Service

```
                        ┌──────────────┐
                        │              │
     ┌──────────────────│  AUTH SRV    │
     │                  │  auth.app    │
     │                  └──────┬───────┘
     │                         │
┌────┴────┐              ┌────┴────┐
│         │              │         │
│ API 1   │              │ API 2   │
│         │              │         │
└─────────┘              └─────────┘
     │                        │
     └───── Introspect ───────┘
            or verify JWT
```

### 1.3 API Gateway Auth

```
                  ┌──────────────┐
Client ──────────│  API GATEWAY │────→ Service A
                  │  (Auth check)│────→ Service B
                  └──────────────┘────→ Service C
```

### 1.4 Backend for Frontend (BFF)

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐
│  SPA     │────>│   BFF        │────>│   API 1      │
│  Browser │     │  (Session    │     └──────────────┘
└──────────┘     │   + Token)   │     ┌──────────────┐
                 └──────────────┘────>│   API 2      │
                                      └──────────────┘

BFF responsibilities:
  - Maintains session for SPA (httpOnly cookie)
  - Exchanges session for Bearer token for APIs
  - Token never exposed to browser
  - CSRF protection built-in
```

### 1.5 Zero Trust Architecture

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐
│  Client  │────>│   PROXY      │────>│   SERVICE    │
└──────────┘     │  (Auth every │     └──────────────┘
                  │   request)   │
                  └──────────────┘

Every request is:
  - Authenticated
  - Authorized
  - Encrypted (mTLS)
  - Audited
```

---

## 2. Token Storage Strategy

| Storage | XSS Risk | CSRF Risk | Persistence | Refresh | Use Case |
|---------|----------|-----------|-------------|---------|----------|
| **Browser memory (variable)** | None | None | Tab close | SPA can refresh | Best for SPAs |
| **httpOnly cookie (session)** | None | Moderate | Configurable | Built-in | Traditional web |
| **httpOnly cookie (token)** | None | Moderate | Configurable | Custom | BFF pattern |
| **localStorage** | **Critical** | None | Forever | Built-in | **AVOID** |
| **sessionStorage** | **Critical** | None | Tab close | Built-in | Avoid for tokens |
| **Web Worker** | Low | None | Tab close | Custom | Advanced SPAs |

---

## 3. Refresh Token Rotation — Complete Protocol

```
State machine per refresh token family:

                        ┌──────────────┐
                        │   ACTIVE     │  — current valid token
                        └──────┬───────┘
                               │
            ┌──────────────────┼──────────────────┐
            │                  │                  │
            ▼                  ▼                  ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  CONSUMED    │  │  COMPROMISED  │  │  EXPIRED     │
    │  (normal     │  │  (reuse       │  │  (TTL ended) │
    │   rotation)  │  │   detected)   │  │              │
    └──────────────┘  └──────────────┘  └──────────────┘
                            │
                            ▼
                    ┌──────────────┐
                    │  FAMILY      │
                    │  REVOKED     │  — all tokens in family invalidated
                    └──────────────┘

On COMPROMISED: revoke entire family and force re-authentication
```

---

## 4. Integration Patterns

### Pattern 1: Session + API Token (Hybrid)

```
Web browser → Session cookie (httpOnly)
Mobile app → Access + Refresh token (Bearer)
3rd-party  → API Key (X-API-Key)
```

### Pattern 2: Token Exchange

```
Service A (has token for scope X)
  ──→  Auth Server
      POST /token?grant_type=urn:ietf:params:oauth:grant-type:token-exchange
      subject_token=<A's token>
      requested_token_type=access_token
  ──→  Receives token for scope Y (narrower scopes)
  ──→  Calls Service B with new token
```

### Pattern 3: Token Chaining

```
User → Auth Service → access_token (scope: API A + B)
API A receives token
API A calls API B with SAME token (symmetric)
API B verifies token independently (JWKS)
```

---

## 5. Code Examples

### Java (Spring Cloud Gateway — Auth Filter)

```java
@Component
public class GatewayAuthFilter implements GlobalFilter, Ordered {

    @Autowired
    private ReactiveOpaqueTokenIntrospector introspector;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String auth = exchange.getRequest().getHeaders()
            .getFirst(HttpHeaders.AUTHORIZATION);

        if (auth == null || !auth.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = auth.substring(7);
        return introspector.introspect(token)
            .flatMap(principal -> {
                // Add user info as headers for downstream services
                ServerHttpRequest mutated = exchange.getRequest().mutate()
                    .header("X-User-Id", principal.getAttribute("sub"))
                    .header("X-User-Role", principal.getAttribute("role"))
                    .build();
                return chain.filter(exchange.mutate().request(mutated).build());
            })
            .onErrorResume(e -> {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            });
    }

    @Override
    public int getOrder() {
        return -100;  // Run early in the filter chain
    }
}
```

---

## 6. References

- [Microsoft — Auth Architecture](https://learn.microsoft.com/en-us/azure/architecture/patterns/)
- [Auth0 — Architecture Scenarios](https://auth0.com/docs/get-started/architecture-scenarios)
- [BFF Pattern (Auth0)](https://auth0.com/blog/the-backend-for-frontend-pattern-bff/)
- [Google BeyondCorp (Zero Trust)](https://cloud.google.com/beyondcorp)
- [NIST Zero Trust Architecture (SP 800-207)](https://www.nist.gov/publications/zero-trust-architecture)
