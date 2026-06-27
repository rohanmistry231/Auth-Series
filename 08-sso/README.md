# 08 — Single Sign-On (SSO)

SSO allows a user to authenticate **once** and gain access to **multiple applications** without re-entering credentials. It is the foundation of enterprise identity management.

---

## 1. SSO Topologies

### 1.1 Same-Domain SSO (Cookie-Based)

```
Browser                     Auth (auth.example.com)       App1, App2, App3
  │                              │                        (.example.com)
  │  POST /login                 │
  │─────────────────────────────>│
  │                              │
  │  Set-Cookie: sso_session=abc │
  │  Domain=.example.com         │
  │<─────────────────────────────│
  │                              │
  │  GET app1.example.com        │
  │  Cookie: sso_session=abc     │
  │─────────────────────────────────────────────────────>│
  │                              │                        │
  │  App1 validates cookie       │                        │
  │  with shared session store   │                        │
  │<──────────────────────────────────────────────────────│
  │                              │                        │
  │  GET app2.example.com        │                        │
  │  Cookie: sso_session=abc     │                        │
  │─────────────────────────────────────────────────────────────────>│
  │                              │                        │
  │  (already authenticated)     │                        │
  │<──────────────────────────────────────────────────────────────────│
```

### 1.2 Cross-Domain SSO (Federated — OIDC / SAML)

```
Browser                  IdP                      App1                    App2
  │                       │                        │                      │
  │  Access App1          │                        │                      │
  │───────────────────────────────────────────────>│                      │
  │                       │                        │                      │
  │  Redirect to IdP      │                        │                      │
  │<───────────────────────────────────────────────│                      │
  │                       │                        │                      │
  │──────────────────────>│                        │                      │
  │                       │                        │                      │
  │  User authenticates   │                        │                      │
  │<──────────────────────│                        │                      │
  │                       │                        │                      │
  │  Token for App1       │                        │                      │
  │───────────────────────────────────────────────>│                      │
  │                       │                        │                      │
  │  Session set          │                        │                      │
  │<───────────────────────────────────────────────│                      │
  │                       │                        │                      │
  │  Access App2          │                        │                      │
  │──────────────────────────────────────────────────────────────────────>│
  │                       │                        │                      │
  │  No session →         │                        │                      │
  │  redirect to IdP      │                        │                      │
  │<──────────────────────────────────────────────────────────────────────│
  │                       │                        │                      │
  │  Redirect with token  │                        │                      │
  │  (silent, IdP cookie  │                        │                      │
  │  already authentic)   │                        │                      │
  │──────────────────────────── Token for App2 ──────────────────────────>│
  │                       │                        │                      │
  │  Session set          │                        │                      │
  │<──────────────────────────────────────────────────────────────────────│
```

---

## 2. SSO Protocols — Decision Matrix

| Protocol | Transport | Token | Federation | Mobile | Complexity |
|----------|-----------|-------|------------|--------|------------|
| **SAML 2.0** | Browser + SOAP | XML Assertion | Cross-org | Poor (ECP) | High |
| **OIDC** | HTTP REST | JWT | Cross-org | Native | Low |
| **CAS** | Browser + Ticket | Service Ticket | Within org | Poor | Medium |
| **Kerberos** | Network protocol | Ticket | Windows domain | None | Medium |

---

## 3. IdP-Initiated vs SP-Initiated

### SP-Initiated (most common)

```
User → SP (no session) → SP redirects to IdP → IdP authenticates → IdP redirects back → SP creates session
```

### IdP-Initiated (portal model)

```
User → IdP → IdP authenticates → User selects an app → IdP issues assertion → App validates → Session created
```

---

## 4. Single Logout (SLO)

### Front-Channel Logout (browser redirect)

```
1. User clicks "Logout" in App1
2. App1 redirects browser to IdP logout endpoint
3. IdP clears its session
4. IdP loads iframes/redirects from each registered SP's logout URL
5. Each SP clears its local session
6. User is logged out everywhere
```

### Back-Channel Logout (SOAP)

```
1. User logs out of App1
2. App1 calls IdP's SLO endpoint (SOAP — not via browser)
3. IdP sends SOAP logout requests to all SPs
4. Each SP clears session and acknowledges
```

---

## 5. Security Considerations

| Threat | Description | Mitigation |
|--------|-------------|------------|
| **SSO SPOF** | IdP outage blocks all app access | IdP clustering, failover IdP |
| **IdP compromise** | Attacker controls IdP = all apps compromised | Hardware security modules, MFA for IdP admin |
| **Session hijacking** | SSO session stolen = all apps accessible | Short session TTL, device binding |
| **SLO failure** | Logout from one app does not propagate | Both front-channel and back-channel SLO |
| **Cross-domain cookie** | Browser isolates cookies by domain | Use federated tokens (OIDC/SAML), not cookies |

---

## 6. Code Examples

### Java (Spring Security — OIDC SSO)

```java
// build.gradle: implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'

@Configuration
@EnableWebSecurity
public class SsoConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .saml2Login(saml2 -> saml2     // SAML for enterprise
                .relyingPartyRegistration(...))
            .oauth2Login(oauth2 -> oauth2  // OIDC for modern
                .clientRegistrationRepository(clientRegistrations()))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/login", "/logout").permitAll()
                .anyRequest().authenticated())
            .logout(logout -> logout
                .logoutSuccessHandler(ssoLogoutHandler()));
        return http.build();
    }

    @Bean
    public ClientRegistrationRepository clientRegistrations() {
        return new InMemoryClientRegistrationRepository(
            ClientRegistration.withRegistrationId("oidc")
                .issuerUri("https://idp.example.com")
                .clientId("sso-client")
                .clientSecret("sso-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid", "profile", "email")
                .build()
        );
    }

    private LogoutSuccessHandler ssoLogoutHandler() {
        return (request, response, authentication) -> {
            // Front-channel logout: redirect to IdP
            String idpLogoutUrl = "https://idp.example.com/logout?"
                + "post_logout_redirect_uri="
                + URLEncoder.encode("https://app.example.com", UTF_8);
            response.sendRedirect(idpLogoutUrl);
        };
    }
}
```

---

## 7. References

- [NIST SP 800-63 — Digital Identity](https://pages.nist.gov/800-63-3/)
- [OIDC SSO (Auth0)](https://auth0.com/docs/authenticate/single-sign-on)
- [SAML SSO (Okta)](https://www.okta.com/single-sign-on/)
- [OpenID Connect Session Management](https://openid.net/specs/openid-connect-session-1_0.html)
