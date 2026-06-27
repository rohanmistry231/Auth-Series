# 15 — CAS (Central Authentication Service)

CAS is an enterprise SSO protocol originally developed at Yale University. Widely used in academic and Java Spring ecosystems.

---

## 1. CAS Protocol v3 — Full Flow

```
Browser                   CAS Server                Application
  │                          │                         │
  │  1. Request /dashboard   │                         │
  │───────────────────────────────────────────────────>│
  │                          │                         │
  │  2. No session →         │                         │
  │     redirect to CAS      │                         │
  │     GET /login?service=  │                         │
  │     <appURL>             │                         │
  │<───────────────────────────────────────────────────│
  │                          │                         │
  │  3. CAS login page       │                         │
  │─────────────────────────>│                         │
  │                          │                         │
  │  4. User authenticates   │                         │
  │     (username + password)│                         │
  │─────────────────────────>│                         │
  │                          │                         │
  │  5. Create TGT (session) │                         │
  │     Set TGC cookie       │                         │
  │     (Ticket Granting     │                         │
  │      Cookie)             │                         │
  │                          │                         │
  │  6. Create ST (Service   │                         │
  │     Ticket), redirect    │                         │
  │     to app with ?ticket= │                         │
  │──────────────────────────│                         │
  │  ──> ticket ST-12345-ABC │                         │
  │<─────────────────────────│                         │
  │                          │                         │
  │  7. Access /dashboard    │                         │
  │     ?ticket=ST-12345-ABC │                         │
  │───────────────────────────────────────────────────>│
  │                          │                         │
  │                          │ 8. Validate ticket      │
  │                          │    GET /serviceValidate? │
  │                          │    ticket=ST-...&       │
  │                          │    service=<appURL>     │
  │                          │────────────────────────>│
  │                          │                         │
  │                          │ 9. CAS response (XML)   │
  │                          │<────────────────────────│
  │                          │                         │
  │ 10. Create local session │                         │
  │<───────────────────────────────────────────────────│
```

---

## 2. Ticket Types

| Ticket | Prefix | Purpose | Lifetime | Storage |
|--------|--------|---------|----------|---------|
| **TGT** (Ticket Granting Ticket) | `TGT-` | Long-term CAS session (TGC cookie) | Hours–days | CAS server (memory/DB) |
| **ST** (Service Ticket) | `ST-` | Single-use, access one app | Seconds–minutes | CAS server |
| **PGT** (Proxy Granting Ticket) | `PGT-` | Allows proxy to obtain PTs | Hours | CAS server |
| **PT** (Proxy Ticket) | `PT-` | Delegate to another service | Minutes | CAS server |

---

## 3. CAS Response XML

### Success

```xml
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user>jdoe</cas:user>
    <cas:attributes>
      <cas:email>jdoe@example.edu</cas:email>
      <cas:role>admin</cas:role>
      <cas:department>Engineering</cas:department>
    </cas:attributes>
    <cas:proxyGrantingTicket>PGTIOU-...</cas:proxyGrantingTicket>
  </cas:authenticationSuccess>
</cas:serviceResponse>
```

### Failure

```xml
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationFailure code="INVALID_TICKET">
    Ticket ST-12345 not recognized
  </cas:authenticationFailure>
</cas:serviceResponse>
```

---

## 4. Code Examples

### Java (Spring Security + CAS)

```java
// build.gradle: implementation 'org.springframework.security:spring-security-cas'

@Configuration
@EnableWebSecurity
public class CasConfig {

    @Value("${cas.server.url}")
    private String casServerUrl;

    @Value("${cas.server.login}")
    private String casLoginUrl;

    @Value("${cas.service.url}")
    private String serviceUrl;

    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties sp = new ServiceProperties();
        sp.setService(serviceUrl + "/login/cas");
        sp.setSendRenew(false);
        return sp;
    }

    @Bean
    public CasAuthenticationEntryPoint casEntryPoint() {
        CasAuthenticationEntryPoint entry = new CasAuthenticationEntryPoint();
        entry.setLoginUrl(casLoginUrl);
        entry.setServiceProperties(serviceProperties());
        return entry;
    }

    @Bean
    public CasAuthenticationFilter casFilter() {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setServiceProperties(serviceProperties());
        filter.setFilterProcessesUrl("/login/cas");
        return filter;
    }

    @Bean
    public TicketValidator ticketValidator() {
        Cas30ServiceTicketValidator validator = new Cas30ServiceTicketValidator(casServerUrl);
        validator.setProxyCallbackUrl(serviceUrl + "/proxy/callback");
        return validator;
    }

    @Bean
    public CasAuthenticationProvider casProvider() {
        CasAuthenticationProvider provider = new CasAuthenticationProvider();
        provider.setServiceProperties(serviceProperties());
        provider.setTicketValidator(ticketValidator());
        provider.setUserDetailsService((username) ->
            new User(username, "", AuthorityUtils.createAuthorityList("ROLE_USER")));
        provider.setKey("cas-auth-series");
        return provider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .exceptionHandling(except -> except
                .authenticationEntryPoint(casEntryPoint()))
            .addFilterAt(casFilter(), UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/login/cas", "/proxy/**").permitAll()
                .anyRequest().authenticated())
            .logout(logout -> logout
                .logoutSuccessUrl(casServerUrl + "/logout"));
        return http.build();
    }
}
```

### Python (cas-client)

```python
from cas import CASClient

cas_client = CASClient(
    server_url="https://cas.example.edu/cas",
    service_url="https://app.example.edu",
    version=3,
)

@app.route("/login")
def login():
    ticket = request.args.get("ticket")
    if not ticket:
        return redirect(cas_client.get_login_url())

    user, attributes, pgtiou = cas_client.verify_ticket(ticket)
    if not user:
        return redirect(cas_client.get_login_url())

    session["user"] = user
    session["attributes"] = attributes
    return redirect("/dashboard")
```

### TypeScript (cas-authentication)

```typescript
import CAS from 'cas-authentication';

const casClient = new CAS({
  cas_url: 'https://cas.example.edu',
  service_url: 'https://app.example.edu',
  cas_version: '3.0',
  session_name: 'cas_user',
  session_info: 'cas_attributes',
  destroy_session: true,
});

app.get('/dashboard', casClient.block, (req, res) => {
  res.json({
    user: req.session!.cas_user,
    attributes: req.session!.cas_attributes,
  });
});
```

---

## 5. References

- [CAS Protocol v3 Spec](https://apereo.github.io/cas/6.6.x/protocol/CAS-Protocol-V2-Specification.html)
- [Apereo CAS Project](https://github.com/apereo/cas)
- [Spring Security CAS](https://docs.spring.io/spring-security/reference/servlet/cas.html)
