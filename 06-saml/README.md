# 06 — SAML 2.0

Security Assertion Markup Language (SAML) 2.0 is an XML-based, enterprise-grade SSO protocol. It enables identity federation across organisational boundaries.

---

## 1. Actors

| Actor | Abbreviation | Role |
|-------|------------|------|
| **Principal** | — | The user seeking access |
| **Identity Provider** | IdP | Authenticates users, issues assertions |
| **Service Provider** | SP | The application the user wants to access |

---

## 2. SAML Assertion — Complete Structure

```xml
<Assertion
  xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_abc123def456"
  IssueInstant="2026-01-15T10:30:00Z"
  Version="2.0">

  <!-- WHO ISSUED IT -->
  <Issuer>https://idp.example.com</Issuer>

  <!-- XML SIGNATURE (REQUIRED in production) -->
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod
        Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod
        Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_abc123def456">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>j6lwx3rvEPO0vKtMup4NbeVu8nk=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>...</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Certificate>MIID... (PEM-encoded cert)</ds:X509Certificate>
    </ds:KeyInfo>
  </ds:Signature>

  <!-- WHO IT'S ABOUT -->
  <Subject>
    <NameID
      Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      user@example.com
    </NameID>
    <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <SubjectConfirmationData
        NotOnOrAfter="2026-01-15T10:35:00Z"
        Recipient="https://sp.example.com/acs"
        InResponseTo="_request123"/>
    </SubjectConfirmation>
  </Subject>

  <!-- CONDITIONS (validity window) -->
  <Conditions NotBefore="2026-01-15T10:29:00Z"
              NotOnOrAfter="2026-01-15T10:35:00Z">
    <AudienceRestriction>
      <Audience>https://sp.example.com</Audience>
    </AudienceRestriction>
    <OneTimeUse/>
  </Conditions>

  <!-- ATTRIBUTES (user data) -->
  <AttributeStatement>
    <Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <AttributeValue>user@example.com</AttributeValue>
    </Attribute>
    <Attribute Name="role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <AttributeValue>admin</AttributeValue>
    </Attribute>
    <Attribute Name="department">
      <AttributeValue>Engineering</AttributeValue>
    </Attribute>
  </AttributeStatement>

  <!-- AUTHN STATEMENT (when/how user authenticated) -->
  <AuthnStatement AuthnInstant="2026-01-15T10:30:00Z"
                  SessionIndex="_session123">
    <AuthnContext>
      <AuthnContextClassRef>
        urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
      </AuthnContextClassRef>
    </AuthnContext>
  </AuthnStatement>
</Assertion>
```

---

## 3. Bindings

| Binding | Transport | Security | Use Case |
|---------|-----------|----------|----------|
| **HTTP Redirect** | URL query (base64-encoded + signed) | Low (URL limits) | SP → IdP (AuthnRequest) |
| **HTTP POST** | HTML form (base64-encoded) | Medium | IdP → SP (Response) |
| **HTTP Artifact** | Short reference → SOAP backend | High (backend channel) | Large assertions, high security |
| **SOAP** | Direct SOAP call | High | Backchannel (Artifact resolve, SLO) |
| **PAOS** | Reverse SOAP (via browser) | Medium | ECP (Enhanced Client or Proxy) |

---

## 4. SP-Initiated SSO — Full Protocol

```
Browser                  SP                        IdP
  │                       │                         │
  │  1. Request resource  │                         │
  │─────────────────────>│                         │
  │                       │                         │
  │  2. No session        │                         │
  │                       │                         │
  │  3. AuthnRequest      │                         │
  │  <─── HTTP Redirect ──│                         │
  │                       │                         │
  │  4. GET /sso?SAMLRequest=<base64>               │
  │─────────────────────────────────────────────────>│
  │                       │                         │
  │  5. User authenticates                          │
  │  <──────────────────────────────────────────────│
  │                       │                         │
  │  6. HTTP POST with    │                         │
  │     SAML Response     │                         │
  │  ────────────────────>│                         │
  │                       │                         │
  │  7. Validate:         │                         │
  │     - XML signature   │                         │
  │     - Issuer          │                         │
  │     - Conditions      │                         │
  │     - SubjectConfirm  │                         │
  │     - Audience        │                         │
  │                       │                         │
  │  8. Session created   │                         │
  │  <─── 200 OK ─────────│                         │
```

---

## 5. AuthnRequest (SP → IdP)

```xml
<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  ID="_request123"
  Version="2.0"
  IssueInstant="2026-01-15T10:29:00Z"
  Destination="https://idp.example.com/sso"
  AssertionConsumerServiceURL="https://sp.example.com/acs"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">

  <saml:Issuer>https://sp.example.com</saml:Issuer>

  <ds:Signature>...</ds:Signature>

  <samlp:NameIDPolicy
    Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    AllowCreate="true"/>

  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>
      urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
    </saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>

</samlp:AuthnRequest>
```

---

## 6. Validation Checklist (SP side)

```
□ Signature verification:
   - Validate XML signature using IdP's X.509 certificate
   - Use exclusive XML canonicalisation (exc-c14n)
   - Verify digest algorithm (SHA-256 recommended)

□ Issuer verification:
   - <Issuer> must match the configured IdP entityID

□ Subject confirmation:
   - Method must be "bearer" (for POST binding)
   - NotOnOrAfter must be in the future
   - Recipient must match the SP's ACS URL
   - InResponseTo must match a pending AuthnRequest

□ Conditions:
   - NotBefore must be in the past (with clock skew allowance)
   - NotOnOrAfter must be in the future
   - AudienceRestriction must include the SP's entityID
   - OneTimeUse: enforce single use (store assertion ID)

□ AuthnStatement:
   - AuthnInstant must be reasonable (not future)
   - AuthnContextClassRef must meet the SP's minimum assurance

□ Replay prevention:
   - Store assertion ID in a cache; reject duplicates
```

---

## 7. SAML vs OIDC — Decision Matrix

| Criterion | SAML 2.0 | OIDC |
|-----------|----------|------|
| Token format | XML | JSON |
| Transport | Browser + SOAP | HTTP REST |
| Identity data | Assertion attributes | ID Token claims + UserInfo |
| Cryptographic binding | XML-DSig (c14n, enveloped) | JWS (compact, detached) |
| Key distribution | X.509 certificate exchange | JWKS endpoint (always current) |
| Mobile friendliness | Poor (ECP is rarely implemented) | Native (PKCE, AppAuth) |
| API integration | Poor (designed for browsers) | Excellent (Bearer tokens) |
| Session logout | SAML SLO (front + back channel) | RP-Initiated Logout |
| Implementation complexity | High (XML parsing, canonicalisation, signature handling) | Low (JSON parsing, standard JWT libraries) |
| Enterprise adoption | Banking, government, universities | Modern SaaS, startups, mobile |
| Metadata | XML metadata files (entityID, certificates, endpoints) | OIDC Discovery document (JSON) |

---

## 8. Security Considerations

### XML Signature Wrapping Attack

```
Attack: Attacker moves the signed assertion outside the signature scope
         and inserts their own unsigned assertion.

Example:
  <Response>
    <Signature>signs original Assertion</Signature>
    <Assertion ID="original"> ← signed
      ...
    </Assertion>
    <Assertion ID="fake"> ← NOT signed!
      <Subject><NameID>attacker@evil.com</NameID></Subject>
    </Assertion>
  </Response>

Defense:
  - Verify that the signed <Assertion> is the one actually used
  - Use ID reference in signature to confirm exact element
  - Use enveloped signature transform correctly
```

### Other Attacks

| Attack | Description | Prevention |
|--------|-------------|------------|
| XML Signature Wrapping | Signature validates old assertion; new assertion is used | Verify ID reference match; use exclusive c14n |
| Replay Attack | Capture response XML, replay later | OneTimeUse + assertion ID cache |
| Clock Skew | Expired assertion accepted due to clock differences | Max 5-minute skew; use NTP |
| Certificate Theft | Attacker steals IdP's signing cert | Short-lived certs; cert revocation |
| Open Redirect | SP redirect URI is attacker-controlled | Whitelist redirect URIs; validate Recipient |

---

## 9. Code Examples

### Java (Spring Security SAML)

```java
// build.gradle: implementation 'org.springframework.security:spring-security-saml2-service-provider'

@Configuration
@EnableWebSecurity
public class SamlConfig {

    @Value("${saml.idp.metadata-uri}")
    private String idpMetadataUri;

    @Value("${saml.sp.entity-id}")
    private String spEntityId;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .saml2Login(saml2 -> saml2
                .relyingPartyRegistration(registration -> registration
                    .registrationId("saml-idp")
                    .entityId(spEntityId)
                    .assertionConsumerServiceLocation(
                        "https://sp.example.com/login/saml2/sso/saml-idp")
                    .singleLogoutServiceLocation(
                        "https://sp.example.com/logout/saml2/slo")
                    .idp(config -> config
                        .entityId("https://idp.example.com")
                        .verificationCertificate(
                            readCertificate("classpath:idp-cert.crt"))
                        .ssoUrl("https://idp.example.com/sso")
                        .sloUrl("https://idp.example.com/slo"))
                    .build()))
            .saml2Logout(saml2 -> saml2
                .logoutRequest(req -> req
                    .destination("https://idp.example.com/slo")))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/login", "/saml2/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    public RelyingPartyRegistrationRepository registrations() {
        // Load from IDP metadata XML
        return new RelyingPartyRegistrationRepository(
            RelyingPartyRegistrations
                .fromMetadataLocation(idpMetadataUri)
                .registrationId("saml-idp")
                .entityId(spEntityId)
                .build()
        );
    }

    @Bean
    public Saml2AuthenticationManager authenticationManager(
            RelyingPartyRegistrationRepository registrations) {
        return new OpenSaml4AuthenticationProvider(registrations) {
            @Override
            protected void validateAssertion(
                    Assertion assertion,
                    RelyingPartyRegistration registration) {
                // Additional custom validation
                super.validateAssertion(assertion, registration);
            }
        };
    }
}
```

### Python (python3-saml)

```python
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path="/path/to/saml/settings")
    return auth

# SP-initiated SSO
@app.route("/login")
def login():
    auth = init_saml_auth(request)
    return redirect(auth.login())

# ACS endpoint
@app.route("/acs", methods=["POST"])
def acs():
    auth = init_saml_auth(request)
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        abort(401, str(errors))
    if not auth.is_authenticated():
        abort(401)
    return {"nameid": auth.get_nameid(), "attributes": auth.get_attributes()}
```

### TypeScript (samlify)

```typescript
import { ServiceProvider, IdentityProvider } from 'samlify';

const sp = ServiceProvider({
  entityID: 'https://sp.example.com/metadata',
  assertionConsumerService: [
    { binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      location: 'https://sp.example.com/acs' }
  ],
  signingCert: readFileSync('sp-cert.pem'),
  privateKey: readFileSync('sp-key.pem'),
});

const idp = IdentityProvider({
  entityID: 'https://idp.example.com',
  singleSignOnService: [
    { binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
      location: 'https://idp.example.com/sso' }
  ],
  signingCert: readFileSync('idp-cert.pem'),
});

app.get('/login', (req, res) => {
  const { context } = sp.createLoginRequest(idp, 'redirect');
  res.redirect(context);
});

app.post('/acs', async (req, res) => {
  try {
    const { extract } = await sp.parseLoginResponse(idp, 'post', req);
    const user = { nameId: extract.nameid, attributes: extract.attributes };
    req.session.user = user;
    res.redirect('/dashboard');
  } catch (err) {
    res.status(401).send('SAML authentication failed');
  }
});
```

---

## 10. References

- [SAML 2.0 Core Specification](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-core-2.0-os.pdf)
- [SAML 2.0 Bindings](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-bindings-2.0-os.pdf)
- [SAML 2.0 Profiles](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-profiles-2.0-os.pdf)
- [OWASP SAML Security](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [XML Signature (XML-DSig)](https://www.w3.org/TR/xmldsig-core1/)
- [XML Exclusive Canonicalisation](https://www.w3.org/TR/xml-exc-c14n/)
