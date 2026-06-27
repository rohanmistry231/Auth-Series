# 13 — Bearer Token Authentication

Bearer tokens are the most common token format for HTTP API authentication. Anyone who **bears** the token can access the protected resource — hence the name.

---

## 1. Token Types — Architectural Decision

| Property | Opaque Token | Structured Token (JWT) | Reference Token |
|----------|-------------|----------------------|-----------------|
| Format | `sk_live_` + 48 random bytes | `header.payload.signature` | `ref_` + UUID |
| Content | None (random) | All claims | Minimal (just ID) |
| Verification | Hash → DB lookup | Cryptographic | Hash → DB lookup |
| Latency | +1 DB call | ~0 (crypto only) | +1 DB call |
| Revocation | Instant (DB delete) | TTL / blocklist | Instant (DB delete) |
| Size | ~48 chars | ~500–2000 chars | ~40 chars |
| Self-contained | No | Yes | No |
| Introspectable | Yes | Not needed | Yes |

---

## 2. Token Introspection (RFC 7662)

Allows a resource server to validate an opaque token against the auth server:

```
POST /introspect
Content-Type: application/x-www-form-urlencoded

token=enter_api_key_here&token_type_hint=access_token
```

```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "active": true,
  "sub": "user_456",
  "client_id": "my-app",
  "scope": "read write",
  "token_type": "Bearer",
  "exp": 1718000000,
  "iat": 1717996400,
  "nbf": 1717996400,
  "iss": "https://auth.example.com",
  "jti": "token_uuid",
  "username": "jane@example.com",
  "role": "admin"
}
```

### Token Revocation (RFC 7009)

```
POST /revoke
Content-Type: application/x-www-form-urlencoded

token=enter_api_key_here&token_type_hint=access_token

→ 200 OK (always, to prevent enumeration)
```

---

## 3. Code Examples

### Java (Spring Security — Opaque Token Introspection)

```java
// build.gradle: implementation 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'

@Configuration
@EnableWebSecurity
public class ResourceServerConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasAuthority("SCOPE_admin")
                .anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2
                .opaqueToken(opaque -> opaque
                    .introspector(opaqueTokenIntrospector())));
        return http.build();
    }

    @Bean
    public OpaqueTokenIntrospector opaqueTokenIntrospector() {
        return new NimbusOpaqueTokenIntrospector(
            "https://auth.example.com/introspect",
            ClientRegistration.withRegistrationId("auth-server")
                .clientId("resource-server")
                .clientSecret("rs-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenUri("https://auth.example.com/token") // for client_creds
                .build()
        ) {
            @Override
            public OAuth2AuthenticatedPrincipal introspect(String token) {
                OAuth2AuthenticatedPrincipal principal = super.introspect(token);
                // Map claims to authorities
                Collection<GrantedAuthority> authorities = new ArrayList<>();
                String scope = (String) principal.getAttribute("scope");
                if (scope != null) {
                    for (String s : scope.split(" ")) {
                        authorities.add(new SimpleGrantedAuthority("SCOPE_" + s));
                    }
                }
                return new OAuth2AuthenticatedPrincipal(
                    principal.getName(),
                    principal.getAttributes(),
                    authorities
                );
            }
        };
    }
}
```

### Python (FastAPI — Bearer middleware)

```python
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def verify_token(creds: HTTPAuthorizationCredentials = Security(security)):
    token = creds.credentials

    # Introspection (opaque token)
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://auth.example.com/introspect",
            data={"token": token, "token_type_hint": "access_token"},
        )
        result = resp.json()

    if not result.get("active"):
        raise HTTPException(401, "Token inactive or revoked")

    return result  # { sub, scope, role, ... }

@app.get("/api/users")
async def get_users(token: dict = Depends(verify_token)):
    if "admin" not in token.get("scope", ""):
        raise HTTPException(403)
    return {"users": [...]}
```

### TypeScript (Express — Bearer + introspection)

```typescript
interface TokenIntrospection {
  active: boolean;
  sub?: string;
  scope?: string;
  role?: string;
  exp?: number;
}

async function introspect(token: string): Promise<TokenIntrospection> {
  const resp = await fetch('https://auth.example.com/introspect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      token,
      token_type_hint: 'access_token',
      client_id: process.env.RS_CLIENT_ID!,
      client_secret: process.env.RS_CLIENT_SECRET!,
    }),
  });
  return resp.json();
}

function bearerAuth(requiredScopes?: string[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const auth = req.headers['authorization'];
    if (!auth?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing token' });
    }

    const token = auth.slice(7);
    const info = await introspect(token);

    if (!info.active) {
      return res.status(401).json({ error: 'Token invalid' });
    }

    req.user = { sub: info.sub!, scope: info.scope!, role: info.role! };

    if (requiredScopes) {
      const tokenScopes = info.scope?.split(' ') ?? [];
      const hasAll = requiredScopes.every(s => tokenScopes.includes(s));
      if (!hasAll) return res.status(403).json({ error: 'Insufficient scope' });
    }

    next();
  };
}
```

---

## 4. References

- [RFC 6750 — Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [RFC 7662 — Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 7009 — Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
