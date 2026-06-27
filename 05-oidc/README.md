# 05 — OpenID Connect (OIDC)

OpenID Connect 1.0 is an **identity layer** built on top of OAuth 2.0. While OAuth 2.0 authorises *access*, OIDC authenticates *identity* — answering "who is the user?" rather than "what may the client do?"

---

## 1. OAuth 2.0 vs OIDC

```
OAuth 2.0 only:                        OIDC adds:
┌──────────────────────────┐           ┌──────────────────────────┐
│  1. Client gets token    │           │  1. Client gets token    │
│  2. Token: opaque/JWT    │           │  2. Token: access_token  │
│  3. Contains: scopes     │           │     + id_token (JWT)     │
│  4. Identity: ? (opaque) │           │  3. id_token contains    │
│                          │           │     user identity claims │
│                          │           │  4. UserInfo endpoint    │
│                          │           │     returns fresh claims │
└──────────────────────────┘           └──────────────────────────┘
```

---

## 2. ID Token — Complete Specification

The ID Token is a signed JWT containing identity claims:

```json
{
  "iss": "https://accounts.example.com",
  "sub": "110169484474386276784",
  "aud": ["my-client-id"],
  "exp": 1718000000,
  "iat": 1717996400,
  "auth_time": 1717996400,
  "nonce": "n-0S6_WzA2Mj",
  "acr": "urn:mace:incommon:iap:silver",
  "amr": ["pwd", "otp"],
  "azp": "my-client-id",
  "at_hash": "mt_a3N8t1U4xj4C5X9KSA",
  "c_hash": "x7K9mN2qP3rV8bL5",
  "name": "Jane Doe",
  "given_name": "Jane",
  "family_name": "Doe",
  "middle_name": "Marie",
  "nickname": "JD",
  "preferred_username": "jane.doe",
  "profile": "https://example.com/jane",
  "picture": "https://example.com/jane/avatar.jpg",
  "website": "https://jane.example.com",
  "email": "jane@example.com",
  "email_verified": true,
  "gender": "female",
  "birthdate": "1990-01-15",
  "zoneinfo": "America/New_York",
  "locale": "en-US",
  "phone_number": "+1 (555) 123-4567",
  "phone_number_verified": false,
  "address": {
    "street_address": "123 Main St",
    "locality": "New York",
    "region": "NY",
    "postal_code": "10001",
    "country": "US"
  },
  "updated_at": 1717996400
}
```

### Claim Categories

| Category | Claims | Standard Scope |
|----------|--------|---------------|
| **Subject** | `sub`, `iss`, `aud` | `openid` (required) |
| **Profile** | `name`, `family_name`, `given_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` | `profile` |
| **Email** | `email`, `email_verified` | `email` |
| **Phone** | `phone_number`, `phone_number_verified` | `phone` |
| **Address** | `address` | `address` |

---

## 3. ID Token Validation — Step-by-Step

```
function validateIdToken(idToken: string,
                         clientId: string,
                         issuer: string,
                         expectedNonce: string,
                         jwks: JWKS): Claims {

    // 1. Parse JWT
    const [headerB64, payloadB64, signatureB64] = idToken.split('.');
    const header = JSON.parse(base64urlDecode(headerB64));
    const payload = JSON.parse(base64urlDecode(payloadB64));

    // 2. Signature verification
    const key = findKey(jwks, header.kid, header.alg);
    if (!verifySignature(idToken, key)) throw INVALID_SIGNATURE;

    // 3. Issuer verification
    if (payload.iss !== issuer) throw WRONG_ISSUER;
    // iss MUST exactly match the expected value (including trailing slash if present)

    // 4. Audience verification
    if (!payload.aud.includes(clientId)) throw WRONG_AUDIENCE;
    // MUST contain this client's ID. MAY contain multiple audiences (azienda).
    // If multiple audiences: verify azp (authorized party) = client ID

    // 5. Authorized party
    if (payload.aud.length > 1 && payload.azp !== clientId) {
        throw WRONG_AZP;
    }

    // 6. Expiration
    if (payload.exp < currentTime()) throw TOKEN_EXPIRED;
    // Standard leeway: 60 seconds

    // 7. Issued-at
    if (payload.iat > currentTime() + 300) throw FUTURE_TOKEN;
    // 5-minute clock skew allowance

    // 8. Nonce
    if (payload.nonce !== expectedNonce) throw NONCE_MISMATCH;
    // Prevents replay. Server must remember used nonces or use short expiry.

    // 9. Authentication time
    // auth_time may be used to determine how recently the user authenticated

    // 10. at_hash (if present) — hash of access_token
    if (payload.at_hash) {
        const hash = sha256(accessToken).slice(0, len(key) / 2);
        if (base64url(hash) !== payload.at_hash) throw AT_HASH_MISMATCH;
    }

    return payload;
}
```

---

## 4. OIDC Flows

### 4.1 Authorisation Code Flow (recommended)

```
Browser            Client App               OIDC Provider (OP)
  │                     │                        │
  │  1. Login click     │                        │
  │────────────────────>│                        │
  │                     │                        │
  │  2. Auth request    │                        │
  │  scope=openid+      │                        │
  │  profile+email      │                        │
  │<────────────────────│                        │
  │                     │                        │
  │  3. ──────────────────────────────────────> │
  │  User authenticates │                        │
  │<─────────────────────────────────────────── │
  │                     │                        │
  │  4. Auth code       │                        │
  │────────────────────>│                        │
  │                     │                        │
  │                     │  5. Token request       │
  │                     │  code + client_secret  │
  │                     │────────────────────────>│
  │                     │                        │
  │                     │  6. access_token +     │
  │                     │     id_token (JWT)     │
  │                     │<────────────────────────│
  │                     │                        │
  │                     │  7. Validate id_token  │
  │                     │                        │
  │  8. Authenticated   │                        │
  │<────────────────────│                        │
```

### 4.2 Hybrid Flow (partial tokens returned in authorisation response)

```
  response_type=code id_token token  →  immediate id_token + eventual code
  response_type=code token          →  immediate access_token + eventual code
  response_type=code id_token       →  immediate id_token + eventual code
```

---

## 5. Endpoints

| Endpoint | Path | Purpose |
|----------|------|---------|
| **Discovery** | `/.well-known/openid-configuration` | Provider metadata |
| **Authorise** | `/authorize` | User authentication + consent |
| **Token** | `/token` | Exchange code for tokens |
| **UserInfo** | `/userinfo` | Get identity claims (authenticated) |
| **JWKS** | `/jwks` | Public keys for token verification |
| **End Session** | `/logout` | RP-initiated logout |
| **Introspect** | `/introspect` | Token introspection (RFC 7662) |
| **Revoke** | `/revoke` | Token revocation (RFC 7009) |

### Discovery Document

```
GET https://accounts.example.com/.well-known/openid-configuration
```

```json
{
  "issuer": "https://accounts.example.com",
  "authorization_endpoint": "https://accounts.example.com/authorize",
  "token_endpoint": "https://accounts.example.com/token",
  "userinfo_endpoint": "https://accounts.example.com/userinfo",
  "jwks_uri": "https://accounts.example.com/jwks",
  "scopes_supported": ["openid", "profile", "email", "address", "phone"],
  "response_types_supported": ["code", "code id_token", "id_token"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public", "pairwise"],
  "id_token_signing_alg_values_supported": ["RS256", "ES256"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time",
    "name", "email", "picture"],
  "end_session_endpoint": "https://accounts.example.com/logout"
}
```

---

## 6. Pairwise vs Public Subject Identifiers

| Type | Description | Example |
|------|-------------|---------|
| **Public** | Same `sub` value across all clients | `110169484474386276784` |
| **Pairwise** | Different `sub` per client (prevents cross-client correlation) | `d2917d9c...` (computed from client_id + user) |

---

## 7. RP-Initiated Logout

```
1. RP redirects user to OP's end_session_endpoint
   GET https://op.example.com/logout?
     id_token_hint=<id_token>&
     post_logout_redirect_uri=https://rp.example.com/logged-out&
     state=xyz

2. OP clears user's session and redirects back
   GET https://rp.example.com/logged-out?state=xyz
```

### Session Management (iframe-based)

```
OP sets a session cookie (auth session).
RP embeds hidden iframe pointing to OP's check_session endpoint.
RP polls iframe via postMessage to verify session state.
If session changed: RP re-authenticates user (silent or visible).
```

---

## 8. Code Examples

### Java (Spring Security OIDC)

```java
// build.gradle: implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'

@Configuration
public class OidcConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfo -> userInfo
                    .oidcUserService(this.oidcUserService())))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/login", "/oauth2/**").permitAll()
                .anyRequest().authenticated())
            .logout(logout -> logout
                .logoutSuccessHandler(oidcLogoutSuccessHandler()));
        return http.build();
    }

    @Bean
    public OIDCUserService oidcUserService() {
        return new OIDCUserService() {
            @Override
            public OIDCUser loadUser(OIDCUserRequest userRequest)
                    throws OAuth2AuthenticationException {

                OIDCUser user = super.loadUser(userRequest);
                OidcIdToken idToken = userRequest.getIdToken();

                // Validate all required claims
                if (!"https://accounts.example.com".equals(idToken.getIssuer())) {
                    throw new OAuth2AuthenticationException("Invalid issuer");
                }
                if (!idToken.getAudience().contains(
                        userRequest.getClientRegistration().getClientId())) {
                    throw new OAuth2AuthenticationException("Invalid audience");
                }

                // Extract profile
                Map<String, Object> attributes = user.getClaims();
                String email = (String) attributes.get("email");
                Boolean emailVerified = (Boolean) attributes.get("email_verified");

                return user;
            }
        };
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        return (request, response, authentication) -> {
            OidcIdToken idToken = ((OidcUser) authentication.getPrincipal())
                .getIdToken();
            String logoutUrl = "https://accounts.example.com/logout?"
                + "id_token_hint=" + idToken.getTokenValue()
                + "&post_logout_redirect_uri="
                + URLEncoder.encode("https://rp.example.com", "UTF-8");
            response.sendRedirect(logoutUrl);
        };
    }
}
```

### Python (Authlib)

```python
from authlib.integrations.flask_client import OAuth

oauth = OAuth(app)

oauth.register(
    name="example-oidc",
    server_metadata_url="https://accounts.example.com/.well-known/openid-configuration",
    client_id=os.environ["OIDC_CLIENT_ID"],
    client_secret=os.environ["OIDC_CLIENT_SECRET"],
    client_kwargs={"scope": "openid profile email"},
)

@app.route("/login")
def login():
    return oauth.example_oidc.authorize_redirect(
        url_for("callback", _external=True),
        nonce=secrets.token_urlsafe(16),
    )

@app.route("/callback")
def callback():
    token = oauth.example_oidc.authorize_access_token()
    # token["access_token"] — API access
    # token["id_token"] — user identity
    userinfo = oauth.example_oidc.userinfo()  # calls /userinfo endpoint
    return {"user": userinfo}
```

### TypeScript (openid-client)

```typescript
import { Issuer, generators } from 'openid-client';

const issuer = await Issuer.discover(
  'https://accounts.example.com/.well-known/openid-configuration');

const client = new issuer.Client({
  client_id: process.env.CLIENT_ID!,
  client_secret: process.env.CLIENT_SECRET!,
  redirect_uris: ['http://localhost:3000/callback'],
  response_types: ['code'],
});

app.get('/login', (req, res) => {
  const nonce = generators.nonce(32);
  const state = generators.state(32);
  req.session.nonce = nonce;
  req.session.state = state;

  const url = client.authorizationUrl({
    scope: 'openid profile email',
    state,
    nonce,
  });
  res.redirect(url);
});

app.get('/callback', async (req, res) => {
  const params = client.callbackParams(req);
  const tokenSet = await client.callback(
    'http://localhost:3000/callback',
    params,
    {
      state: req.session.state,
      nonce: req.session.nonce,
    }
  );
  // tokenSet.access_token, tokenSet.id_token, tokenSet.refresh_token
  const userinfo = await client.userinfo(tokenSet.access_token!);
  res.json(userinfo);
});
```

### Go (coreos/go-oidc)

```go
import (
    "context"
    "github.com/coreos/go-oidc/v3/oidc"
    "golang.org/x/oauth2"
)

func oidcHandler(w http.ResponseWriter, r *http.Request) {
    provider, err := oidc.NewProvider(r.Context(),
        "https://accounts.example.com")
    if err != nil { http.Error(w, err.Error(), 500); return }

    config := oauth2.Config{
        ClientID:     os.Getenv("OIDC_CLIENT_ID"),
        ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
        Endpoint:     provider.Endpoint(),
        RedirectURL:  "http://localhost:8080/callback",
        Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
    }

    state := generators.State() // crypto random
    nonce := generators.Nonce()
    url := config.AuthCodeURL(state,
        oidc.Nonce(nonce))
    http.Redirect(w, r, url, http.StatusFound)
}
```

---

## 9. References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OpenID Connect Session Management](https://openid.net/specs/openid-connect-session-1_0.html)
