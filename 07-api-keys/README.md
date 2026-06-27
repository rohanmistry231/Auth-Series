# 07 — API Key Authentication

API keys are the simplest form of machine-to-machine authentication — a static, long-lived credential that identifies a client.

---

## 1. Key Format Design

```
Prefix    Environment    Encoding (base62/base64url)
│         │              │
│         │              │
sk_live_enter_api_key_here
│         │              │
│         │              └─ 128+ bits of entropy (min 32 chars base62)
│         └──────────────── "live" / "test" / "dev"
└────────────────────────── "sk" (secret key) / "pk" (publishable key)
```

### Entropy calculation

```
Base62 chars:  a-z (26) + A-Z (26) + 0-9 (10) = 62 characters
Entropy per char: log2(62) ≈ 5.95 bits

32 chars → 190 bits   ✓ sufficient
48 chars → 286 bits   ✓ recommended
64 chars → 381 bits   ✓ belt-and-suspenders
```

---

## 2. Storage Model

```sql
CREATE TABLE api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(100) NOT NULL,          -- human-readable label
    prefix      VARCHAR(10) NOT NULL,            -- "sk_live"
    key_hash    VARCHAR(64) NOT NULL UNIQUE,     -- SHA-256 of full key
    key_suffix  VARCHAR(6) NOT NULL,             -- last 4 chars (UI display)
    scopes      TEXT[] NOT NULL DEFAULT '{}',    -- ["read:users", "write:orders"]
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,                     -- NULL = never expires
    last_used   TIMESTAMPTZ,
    revoked     BOOLEAN NOT NULL DEFAULT false,
    ip_restrictions INET[],                      -- optional IP whitelist
    rate_limit  INT DEFAULT 1000                 -- requests per hour
);

CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_prefix ON api_keys(prefix);
```

---

## 3. Key Lifecycle

```
     ┌──────────┐
     │ GENERATED│  — returned to client ONCE (store only hash)
     └────┬─────┘
          │ Activate
          ▼
     ┌──────────┐
     │  ACTIVE  │  — usable until revoked or expired
     └────┬─────┘
          │
     ┌────┴───────┐
     │            │
     ▼            ▼
┌──────────┐ ┌──────────┐
│ REVOKED  │ │ EXPIRED  │  — permanent (not reactivatable)
└──────────┘ └──────────┘
          │
          ▼
┌──────────┐
│  ROTATED │  — new key replaces old; old revoked
└──────────┘
```

---

## 4. Validation Flow

```
Client                              API Server
  │                                    │
  │  GET /api/v1/data                  │
  │  X-API-Key: sk_live_enter_api_key_here │
  │───────────────────────────────────>│
  │                                    │
  │  1. Extract key from header         │
  │  2. Determine prefix → find env    │
  │  3. SHA-256 hash the key           │
  │  4. Look up key_hash in DB         │
  │  5. Check revoked = false          │
  │  6. Check expires_at > now          │
  │  7. Check IP restrictions (if any) │
  │  8. Check rate limit               │
  │  9. Validate scopes match endpoint │
  │  10. Update last_used              │
  │                                    │
  │  200 OK { data }                   │
  │<───────────────────────────────────│
```

---

## 5. Scopes — Design Patterns

```javascript
// Scope format: resource:action

// Flat scopes
"read:users write:users read:orders"

// Hierarchical
"users:read users:write"

// Wildcard
"users:*"                     // all user actions
"*:read"                      // read all resources
"*"                           // everything

// Predefined sets
"basic"                       // read profile
"premium"                     // basic + read orders
"admin"                       // everything
```

---

## 6. Code Examples

### Java (Spring Boot)

```java
@Component
public class ApiKeyFilter extends OncePerRequestFilter {

    @Autowired
    private ApiKeyRepository repository;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        String apiKey = extractKey(request);

        if (apiKey == null) {
            response.sendError(401, "Missing API key");
            return;
        }

        // Hash the key (don't look up raw key in DB)
        String keyHash = sha256(apiKey);

        ApiKeyRecord record = repository.findByKeyHash(keyHash);
        if (record == null || record.isRevoked()) {
            response.sendError(403, "Invalid API key");
            return;
        }

        if (record.getExpiresAt() != null
                && record.getExpiresAt().isBefore(Instant.now())) {
            response.sendError(403, "API key expired");
            return;
        }

        // Rate limit check
        if (rateLimiter.isRateLimited(record.getId())) {
            response.sendError(429, "Rate limit exceeded");
            return;
        }

        // IP restriction check
        if (!record.getIpRestrictions().isEmpty() &&
                !record.getIpRestrictions().contains(request.getRemoteAddr())) {
            response.sendError(403, "IP not allowed");
            return;
        }

        // Set request attributes
        request.setAttribute("apiKeyId", record.getId());
        request.setAttribute("apiKeyScopes", record.getScopes());

        // Update last_used asynchronously
        repository.updateLastUsed(record.getId());

        chain.doFilter(request, response);
    }

    private String extractKey(HttpServletRequest request) {
        String key = request.getHeader("X-API-Key");
        if (key == null) {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                key = auth.substring(7);
            }
        }
        return key;
    }

    private String sha256(String value) {
        return Hashing.sha256().hashString(value, StandardCharsets.UTF_8).toString();
    }
}
```

### Python (FastAPI)

```python
from fastapi import Security, HTTPException, Depends
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_api_key(
    x_api_key: str = Security(api_key_header),
    authorization: str = Security(HTTPBearer(auto_error=False)),
) -> ApiKeyRecord:
    key = x_api_key or (authorization.credentials if authorization else None)
    if not key:
        raise HTTPException(401, "Missing API key")

    key_hash = hashlib.sha256(key.encode()).hexdigest()
    record = await db.fetch_one(
        "SELECT * FROM api_keys WHERE key_hash = :hash", {"hash": key_hash}
    )
    if not record or record.revoked:
        raise HTTPException(403, "Invalid API key")
    if record.expires_at and record.expires_at < datetime.utcnow():
        raise HTTPException(403, "API key expired")

    return record
```

### TypeScript (Express)

```typescript
function apiKeyAuth(req: Request, res: Response, next: NextFunction) {
  const key = req.headers['x-api-key']
    ?? req.headers['authorization']?.startsWith('Bearer ')
       ? req.headers['authorization']!.slice(7)
       : null;

  if (!key) return res.status(401).json({ error: 'Missing API key' });

  const keyHash = createHash('sha256').update(key).digest('hex');
  const record = db.apiKeys.findByHash(keyHash);

  if (!record || record.revoked) return res.status(403).json({ error: 'Invalid key' });
  if (record.expiresAt && record.expiresAt < Date.now()) {
    return res.status(403).json({ error: 'Key expired' });
  }

  req.apiKey = record;
  next();
}
```

---

## 7. References

- [Stripe API Key Best Practices](https://stripe.com/docs/keys)
- [GitHub API Key Authentication](https://docs.github.com/en/rest/overview/other-authentication-methods)
- [AWS API Key Management](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-usage-plans.html)
