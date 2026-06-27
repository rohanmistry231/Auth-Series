# 14 — Digest Access Authentication

RFC 7616 defines an HTTP authentication scheme that hashes credentials rather than sending them in the clear (as Basic Auth does). It provides challenge-response authentication with replay protection via nonces.

---

## 1. Digest Calculation

```
HA1  = MD5(username ":" realm ":" password)
HA2  = MD5(method ":" digestURI)
RESP = MD5(HA1 ":" nonce ":" nc ":" cnonce ":" qop ":" HA2)

Where:
  HA1    = hash of credentials
  HA2    = hash of request target
  RESP   = hash sent to server
  qop    = quality of protection ("auth" or "auth-int")
  nc     = nonce count (hex, increments each request)
  cnonce = client nonce (random, chosen by client)
```

### Request / Response example

```
Server challenge:
  WWW-Authenticate: Digest
    realm="example.com",
    nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
    opaque="5ccc069c403ebaf9f0171e9517f40e41",
    qop="auth",
    algorithm=MD5

Client response:
  Authorization: Digest
    username="jdoe",
    realm="example.com",
    nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
    uri="/protected",
    qop=auth,
    nc=00000001,
    cnonce="0a4f113b543ab1fb",
    response="6629fae49393a05397450978507c4ef1",
    opaque="5ccc069c403ebaf9f0171e9517f40e41"
```

---

## 2. Protocol State Machine

```
     ┌────────────────┐
     │  UNPROMPTED    │  client sends request (no auth)
     └───────┬────────┘
             │ 401 + WWW-Authenticate: Digest (nonce, realm, qop)
             ▼
     ┌────────────────┐
     │  CHALLENGED    │  client computes RESP, retries
     └───────┬────────┘
             │
     ┌───────┴────────┐
     ▼                ▼
┌──────────┐   ┌──────────┐
│ 200 OK   │   │ 401 / 403│  — can challenge with new nonce
└──────────┘   └──────────┘
```

Each request may carry a new `nc` (nonce count) to prevent replay.

---

## 3. Security Analysis

| Threat | Severity | Explanation |
|--------|----------|-------------|
| **Password hash capture** | Medium | HA1 = MD5(user:realm:pass) — offline cracking possible if MD5 is fast |
| **Replay (within nonce window)** | Medium | Protected by `nc` counter (each request increments) |
| **MITM downgrade** | High | Server can challenge with Basic. Client must enforce Digest only. |
| **MD5 collision** | Low for auth | Collision does not reveal password |
| **Chosen-plaintext attack** | Medium | Server controls nonce |

---

## 4. Code Examples

### Java

```java
@Component
public class DigestAuthFilter extends OncePerRequestFilter {

    private static final String REALM = "Auth Series";
    private final Map<String, NonceEntry> nonceStore = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        String auth = request.getHeader("Authorization");

        if (auth == null || !auth.startsWith("Digest ")) {
            challenge(response);
            return;
        }

        Map<String, String> params = parseDigestParams(auth.substring(7));
        String username = params.get("username");
        String nonce = params.get("nonce");
        String uri = params.get("uri");
        String responseDigest = params.get("response");
        String qop = params.getOrDefault("qop", "auth");
        String nc = params.get("nc");
        String cnonce = params.get("cnonce");

        // Validate nonce exists and not expired
        NonceEntry entry = nonceStore.get(nonce);
        if (entry == null || entry.isExpired()) {
            challenge(response);
            return;
        }

        // Hash stored password + compute expected response
        String ha1 = md5(username + ":" + REALM + ":" + getPassword(username));
        String ha2 = md5(request.getMethod() + ":" + uri);
        String expected = md5(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2);

        if (!MessageDigest.isEqual(
                expected.getBytes(), responseDigest.getBytes())) {
            response.sendError(403);
            return;
        }

        chain.doFilter(request, response);
    }

    private void challenge(HttpServletResponse response) {
        String nonce = UUID.randomUUID().toString().replace("-", "");
        nonceStore.put(nonce, new NonceEntry());

        response.setHeader("WWW-Authenticate",
            "Digest realm=\"" + REALM + "\", "
            + "nonce=\"" + nonce + "\", "
            + "qop=\"auth\", "
            + "algorithm=MD5");
        response.setStatus(401);
    }
}
```

---

## 5. References

- [RFC 7616 — HTTP Digest Access Authentication](https://datatracker.ietf.org/doc/html/rfc7616)
- [RFC 2617 — HTTP Authentication (Original)](https://datatracker.ietf.org/doc/html/rfc2617)
- [MDN — Digest Authentication](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication#digest_authentication)
