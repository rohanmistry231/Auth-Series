# 04 — OAuth 2.0

RFC 6749 defines the industry-standard protocol for **authorization**. OAuth 2.0 allows a client application to obtain limited access to a resource server on behalf of a resource owner, without exposing the owner's long-term credentials.

---

## 1. Actors and Trust Relationships

```
┌───────────────────────────────────────────────────────────────────┐
│                                                                   │
│     ┌──────────────┐    authorisation      ┌────────────────┐    │
│     │  Resource    │◄────── grant ────────│   Client App   │    │
│     │  Owner (RO)  │                      │  (Web / Mobile) │    │
│     │  (User)      │                      │                 │    │
│     └──────────────┘                      └───────┬─────────┘    │
│                                                    │              │
│                                           redirects│ +            │
│                                           makes    │ requests     │
│                                           requests │              │
│                                                    │              │
│     ┌──────────────────────┐              ┌────────┴─────────┐   │
│     │   Authorisation      │◄──── Auth ───│  Resource        │   │
│     │   Server (AS)        │    request   │  Server (RS)     │   │
│     │   (e.g., Auth0)      │    token     │  (API)           │   │
│     └──────────────────────┘    ────────► └──────────────────┘   │
│                                              Bearer token        │
│                                                                   │
│     Trust relationships:                                          │
│       RO → AS:     Authenticates + consents                       │
│       Client → AS: Registers, authenticates (client_secret)       │
│       Client → RS: Presents token issued by AS                    │
│       RS → AS:    Validates token (introspection / JWKS)          │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

---

## 2. Client Types

| Type | Can keep a secret? | Examples |
|------|-------------------|----------|
| **Confidential** | Yes | Server-side web app (Node, Spring, Django) |
| **Public** | No | SPA, mobile app, CLI tool, IoT device |

---

## 3. Grant Types — State Machines

### 3.1 Authorisation Code Grant (Confidential clients)

```
     ┌─────────────────┐
     │     INIT        │  User initiates login
     └────────┬────────┘
              │ GET /authorize?response_type=code&...
              ▼
     ┌─────────────────┐
     │  AWAITING_AUTH  │  User logs in + consents at AS
     └────────┬────────┘
              │ Redirect with ?code=AUTH_CODE
              ▼
     ┌─────────────────┐
     │  CODE_RECEIVED  │  Client exchanges code at /token
     └────────┬────────┘
              │ POST /token?grant_type=authorization_code&...
              ▼
     ┌─────────────────┐
     │  TOKEN_ISSUED   │  { access_token, refresh_token }
     └────────┬────────┘
              │
              ▼
     ┌─────────────────┐
     │    ACTIVE       │  Using access_token for API calls
     └────────┬────────┘
              │ token expires
              ▼
     ┌─────────────────┐
     │  TOKEN_EXPIRED  │  Use refresh_token → new tokens
     └─────────────────┘
```

**Wire format — Authorize request:**

```
GET https://as.example.com/authorize?
  response_type=code
  &client_id=s6BhdRkqt3
  &redirect_uri=https://client.example.org/cb
  &scope=openid+profile+email
  &state=xyzABC123
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

**Wire format — Token request:**

```
POST https://as.example.com/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTH_CODE_123
&redirect_uri=https://client.example.org/cb
&client_id=s6BhdRkqt3
&client_secret=SECRET
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

**Wire format — Token response:**

```json
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
  "scope": "openid profile email"
}
```

### 3.2 Authorisation Code + PKCE (Public clients)

PKCE (RFC 7636) prevents the authorisation code interception attack.

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  Client generates:                                           │
│                                                              │
│    code_verifier  = crypto.randomBytes(32).toString('base64url')
│    code_challenge = base64url(sha256(code_verifier))         │
│                                                              │
│  ┌─────────────┐                                             │
│  │  /authorize │ ← code_challenge                           │
│  └──────┬──────┘                                             │
│         ▼                                                    │
│  ┌─────────────┐                                             │
│  │    /token   │ ← code_verifier                            │
│  └──────┬──────┘                                             │
│         ▼                                                    │
│  AS verifies: sha256(verifier) == challenge                  │
│                                                              │
│  Security property: even if the auth code is intercepted,    │
│  the attacker does not know the code_verifier                │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 3.3 Client Credentials Grant (M2M)

```
     ┌─────────────────┐
     │     INIT        │  Service A needs to call Service B
     └────────┬────────┘
              │ POST /token?grant_type=client_credentials&
              │          client_id=svc-a&client_secret=SECRET
              ▼
     ┌─────────────────┐
     │  TOKEN_ISSUED   │  { access_token }
     └────────┬────────┘
              │ Bearer token on each API call
              ▼
     ┌─────────────────┐
     │    ACTIVE       │  Until token expires
     └─────────────────┘
```

### 3.4 Device Code Grant (TV / CLI / IoT)

```
     ┌─────────────────┐
     │   DEVICE_INIT   │  Client POSTs /device_authorization
     └────────┬────────┘
              │ { device_code, user_code, verification_uri, interval }
              ▼
     ┌─────────────────┐
     │ AWAITING_USER   │  "Go to example.com/device, enter ABCD-1234"
     └────────┬────────┘
              │ User visits URL, enters code, consents
              ▼
     ┌─────────────────┐
     │   POLLING       │  Client polls /token every `interval` sec
     └────────┬────────┘
              │ authorization_pending → slow_down → tokens!
              ▼
     ┌─────────────────┐
     │  TOKEN_ISSUED   │
     └─────────────────┘
```

---

## 4. Token Formats — Deep Comparison

| Property | Opaque Token | JWT (Structured) | Reference Token |
|----------|-------------|------------------|-----------------|
| Format | Random string | Signed JWT | Short ID → DB lookup |
| Content | None (lookup) | All claims inside | Minimal (just ID) |
| Verification | DB call | Cryptographic | DB call |
| Revocation | Instant (delete) | TTL / blocklist | Instant (delete) |
| Size | 40–64 chars | ~500–2000 chars | 40–64 chars |
| Introspection | Needed | Not needed | Needed |
| Leakage risk | Low | High (contains PII) | Low |

**Recommendation:** Use JWT for distributed systems where RS needs to verify without calling AS. Use opaque + introspection for high-security environments where revocation must be instant.

---

## 5. Scopes — Design Patterns

```
# Resource-scoped
scope=read:users write:users

# Hierarchical
scope=users:read users:write

# Action-resource
scope=read_users write_users delete_users

# OpenID Connect
scope=openid profile email

# API versioning
scope=api:v1:read api:v2:write

# Predefined sets
scope=basic premium admin
```

### Scope size limits

- Auth servers typically limit scope strings to 512–4096 bytes
- Token size increases with scope claims (for JWT)
- Scope granularity should be at the right level — too coarse (only `admin`) defeats the purpose; too fine (per-endpoint) creates management overhead

---

## 6. OAuth 2.1 — Breaking Changes

| Change | OAuth 2.0 | OAuth 2.1 | Migration |
|--------|-----------|-----------|-----------|
| PKCE | Optional for public clients | **Required** for all public clients | Add PKCE to SPA/mobile flows |
| Implicit Grant | Available | **Removed** | Use Auth Code + PKCE instead |
| Password Grant | Available | **Removed** | Use Auth Code + PKCE (or separate login service) |
| Refresh Token Rotation | Not required | **Recommended** | Rotate refresh tokens on each use |
| Bearer in URL query | Allowed | **Prohibited** | Use Authorization header only |
| `redirect_uri` | Exact match or pattern | **Exact match only** | Tighten redirect_uri validation |

---

## 7. Security Considerations

### Redirect URI validation

```
Allowed:    https://client.example.com/cb
            https://client.example.com/cb?path=123    (exact match)

Redirect:   https://client.example.com
  
Vulnerable: https://client.example.com.evil.com/cb   (subdomain trick)
            https://client.example.com/cb?url=http://evil.com  (open redirect)
```

### State parameter (CSRF protection)

```
The `state` value MUST be:
  - Cryptographically random (≥ 128 bits)
  - Bound to the user's browser session
  - Verified on the redirect callback
  - Single-use (consumed after first use)

Without `state`, an attacker can:
  1. Initiate their own OAuth flow
  2. Intercept the redirect with the auth code
  3. Inject it into the victim's browser
  4. Link attacker's social account to victim's account
```

---

## 8. Code Examples

### Java (Spring Security OAuth2 Client)

```java
// build.gradle: implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'

@Configuration
@EnableWebSecurity
public class OAuth2Config {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .oauth2Login(oauth2 -> oauth2
                .authorizationEndpoint(auth -> auth
                    .authorizationRequestResolver(
                        new NimbusAuthorizationRequestResolver(
                            clientRegistrationRepository)))
                .tokenEndpoint(token -> token
                    .accessTokenResponseClient(authorizationCodeTokenResponseClient()))
            )
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/login", "/oauth2/**").permitAll()
                .anyRequest().authenticated()
            );
        return http.build();
    }

    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
            authorizationCodeTokenResponseClient() {
        var client = new NimbusAuthorizationCodeTokenResponseClient();
        client.setRequestEntityConverter(request -> {
            var converter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
            MultiValueMap<String, String> params = converter.convert(request);

            // Add PKCE code_verifier if stored in session
            String verifier = ...; // retrieve from session
            if (verifier != null) {
                params.add("code_verifier", verifier);
            }
            return new RequestEntity<>(
                params,
                request.getHeaders(),
                HttpMethod.POST,
                URI.create(request.getClientRegistration()
                    .getProviderDetails().getTokenUri()));
        });
        return client;
    }
}
```

### Python (Authlib)

```python
from authlib.integrations.flask_client import OAuth

oauth = OAuth(app)

oauth.register(
    name="auth-series-idp",
    client_id=os.environ["OAUTH_CLIENT_ID"],
    client_secret=os.environ["OAUTH_CLIENT_SECRET"],
    server_metadata_url="https://idp.example.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email"},
)

@app.route("/login")
def login():
    redirect_uri = url_for("authorize", _external=True)
    return oauth.auth_series_idp.authorize_redirect(redirect_uri)

@app.route("/authorize")
def authorize():
    token = oauth.auth_series_idp.authorize_access_token()
    # token contains access_token, refresh_token, id_token (if OIDC)
    return redirect("/dashboard")
```

### TypeScript (NextAuth.js)

```typescript
// app/api/auth/[...nextauth]/route.ts
import NextAuth from "next-auth";
import GoogleProvider from "next-auth/providers/google";
import { type AuthOptions } from "next-auth";

export const authOptions: AuthOptions = {
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      authorization: {
        params: {
          scope: "openid profile email",
          prompt: "consent",
          access_type: "offline",
          response_type: "code",
        },
      },
    }),
  ],
  callbacks: {
    async jwt({ token, account }) {
      if (account) {
        token.accessToken = account.access_token;
        token.refreshToken = account.refresh_token;
      }
      return token;
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken as string;
      return session;
    },
  },
};

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
```

### Go (golang.org/x/oauth2)

```go
import "golang.org/x/oauth2"

var config = &oauth2.Config{
    ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
    ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
    Endpoint: oauth2.Endpoint{
        AuthURL:  "https://idp.example.com/authorize",
        TokenURL: "https://idp.example.com/token",
    },
    RedirectURL: "http://localhost:8080/callback",
    Scopes:      []string{"openid", "profile", "email"},
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    url := config.AuthCodeURL("state-token",
        oauth2.SetAuthURLParam("code_challenge_method", "S256"),
        oauth2.SetAuthURLParam("code_challenge", codeChallenge))
    http.Redirect(w, r, url, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
    token, err := config.Exchange(r.Context(), r.URL.Query().Get("code"),
        oauth2.SetAuthURLParam("code_verifier", codeVerifier))
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    // token.AccessToken, token.RefreshToken, token.Extra("id_token")
}
```

---

## 9. References

- [RFC 6749 — OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 6750 — Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8628 — Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [OAuth 2.1 (draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [OAuth 2.0 Security BCP (RFC 9700)](https://datatracker.ietf.org/doc/html/rfc9700)
