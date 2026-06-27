# 12 — Social Login

Social login allows users to authenticate using existing accounts from identity providers (Google, GitHub, Apple, Microsoft, etc.), built on OAuth 2.0 + OIDC.

---

## 1. Provider Comparison

| Provider | Protocol | OIDC? | ID Token | Refresh Token | PKCE Support |
|----------|----------|-------|----------|---------------|--------------|
| **Google** | OAuth 2.0 + OIDC | Yes | JWT (RS256) | Yes | Yes |
| **GitHub** | OAuth 2.0 (custom) | No | No (uses access_token for /user) | Yes (doesn't expire) | Yes |
| **Apple** | OAuth 2.0 + OIDC | Yes | JWT (RS256, ES256) | Yes | Yes |
| **Microsoft** | OAuth 2.0 + OIDC | Yes | JWT (RS256) | Yes | Yes |
| **Facebook** | OAuth 2.0 (custom) | No | No (uses access_token for /me) | Short-lived | Yes |
| **Twitter/X** | OAuth 2.0 | No | No | No (OAuth 1.0a legacy) | Yes |

---

## 2. Account Linking — Decision Matrix

| Scenario | Strategy |
|----------|----------|
| User exists with email, no social link | Send verification email, then link |
| User exists with email, different casing | Normalise to lowercase before comparison |
| Social email differs from account email | Allow linking with additional verification |
| User has multiple social providers | All providers → same user account |
| Provider email changes | Re-verify email after each social login |
| User un-links provider | Delete provider entry; keep user account |

---

## 3. Provider-Specific Response Examples

### Google (OIDC — ID Token)

```json
// From ID Token (JWT payload)
{
  "iss": "https://accounts.google.com",
  "sub": "110169484474386276784",
  "aud": "my-client-id.apps.googleusercontent.com",
  "exp": 1718000000,
  "iat": 1717996400,
  "email": "jane@example.com",
  "email_verified": true,
  "name": "Jane Doe",
  "picture": "https://lh3.googleusercontent.com/a/...",
  "given_name": "Jane",
  "family_name": "Doe",
  "locale": "en"
}
```

### GitHub (OAuth — UserInfo API)

```json
// GET https://api.github.com/user (Authorization: Bearer <access_token>)
{
  "login": "jane-doe",
  "id": 12345678,
  "node_id": "MDQ6VXNlcjEyMzQ1Njc4",
  "avatar_url": "https://avatars.githubusercontent.com/u/12345678",
  "url": "https://api.github.com/users/jane-doe",
  "name": "Jane Doe",
  "company": "Acme Corp",
  "blog": "https://jane.dev",
  "email": "jane@example.com",
  "hireable": false,
  "bio": "Software engineer",
  "public_repos": 42,
  "followers": 100
}
```

### Apple (OIDC — ID Token)

```json
// From ID Token (JWT payload)
{
  "iss": "https://appleid.apple.com",
  "sub": "000123.abc123def4567890",
  "aud": "com.example.app",
  "exp": 1718000000,
  "iat": 1717996400,
  "nonce": "...",
  "nonce_supported": true,
  "email": "jane@example.com",
  "email_verified": true,
  "is_private_email": true        // Apple relay (when user hides email)
}
```

---

## 4. Code Examples

### Java (Spring Security OAuth2 Client — Multi-Provider)

```java
@Configuration
public class SocialLoginConfig {

    @Bean
    public ClientRegistrationRepository clientRegistrations() {
        return new InMemoryClientRegistrationRepository(
            googleRegistration(),
            githubRegistration(),
            appleRegistration()
        );
    }

    private ClientRegistration googleRegistration() {
        return ClientRegistration.withRegistrationId("google")
            .clientId(env("GOOGLE_CLIENT_ID"))
            .clientSecret(env("GOOGLE_CLIENT_SECRET"))
            .scope("openid", "profile", "email")
            .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
            .tokenUri("https://oauth2.googleapis.com/token")
            .userInfoUri("https://openidconnect.googleapis.com/v1/userinfo")
            .userNameAttributeName("sub")
            .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
            .redirectUri("{baseUrl}/login/oauth2/code/google")
            .build();
    }

    private ClientRegistration githubRegistration() {
        return ClientRegistration.withRegistrationId("github")
            .clientId(env("GITHUB_CLIENT_ID"))
            .clientSecret(env("GITHUB_CLIENT_SECRET"))
            .scope("read:user", "user:email")
            .authorizationUri("https://github.com/login/oauth/authorize")
            .tokenUri("https://github.com/login/oauth/access_token")
            .userInfoUri("https://api.github.com/user")
            .userNameAttributeName("id")
            .redirectUri("{baseUrl}/login/oauth2/code/github")
            .build();
    }

    private ClientRegistration appleRegistration() {
        return ClientRegistration.withRegistrationId("apple")
            .clientId(env("APPLE_CLIENT_ID"))
            .clientSecret(env("APPLE_CLIENT_SECRET"))
            .scope("openid", "name", "email")
            .authorizationUri("https://appleid.apple.com/auth/authorize")
            .tokenUri("https://appleid.apple.com/auth/token")
            .userInfoUri("https://appleid.apple.com/auth/userinfo")
            .userNameAttributeName("sub")
            .jwkSetUri("https://appleid.apple.com/auth/keys")
            .redirectUri("{baseUrl}/login/oauth2/code/apple")
            .build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .oauth2Login(oauth2 -> oauth2
                .successHandler(this::onSocialLoginSuccess))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/login").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }

    private void onSocialLoginSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException {

        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
        String provider = ((OAuth2AuthenticationToken) authentication)
            .getAuthorizedClientRegistrationId();
        String providerId = oauthUser.getAttribute("sub") != null
            ? oauthUser.getAttribute("sub").toString()
            : oauthUser.getAttribute("id").toString();
        String email = oauthUser.getAttribute("email");

        // Find or create user, link accounts
        User user = accountLinkingService.findOrCreate(email, provider, providerId);
        response.sendRedirect("/dashboard");
    }
}
```

---

## 5. Security Considerations

| Risk | Description | Mitigation |
|------|-------------|------------|
| **Account takeover via social** | Attacker creates social account with victim's email | Verify email ownership before linking |
| **Email change on provider** | User changes email on Google → new email mismatches | Allow email update with verification |
| **Provider compromise** | Google/Auth0 compromised → attacker can log into any linked app | Hardware MFA for social provider |
| **Token theft** | Social access token stolen | Short TTL, rotate refresh tokens |
| **Same-email different providers** | jane@gmail.com vs jane@company.com (same person) | Account merging flow |
| **Rate limiting by provider** | Provider blocks repeated failed auths | Handle gracefully |

---

## 6. References

- [Google Sign-In](https://developers.google.com/identity/sign-in/web)
- [GitHub OAuth Apps](https://docs.github.com/en/developers/apps)
- [Sign in with Apple](https://developer.apple.com/sign-in-with-apple/)
- [Facebook Login](https://developers.facebook.com/docs/facebook-login/)
- [Microsoft Identity Platform](https://learn.microsoft.com/en-us/azure/active-directory/develop/)
