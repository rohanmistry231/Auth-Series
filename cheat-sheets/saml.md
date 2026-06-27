# SAML 2.0 — Cheat Sheet

## Core Concepts

| Term | Meaning |
|------|---------|
| **IdP** | Identity Provider (authenticates users) |
| **SP** | Service Provider (protected app) |
| **Assertion** | XML document with auth claims |
| **Metadata** | XML describing IdP/SP capabilities |

## SAML Bindings

| Binding | Transport | Use |
|---------|-----------|-----|
| **HTTP-Redirect** | GET (query param) | SP-init SSO |
| **HTTP-POST** | POST (form) | IdP-init SSO, SLO |
| **HTTP-Artifact** | Back-channel | High security |

## AuthnRequest → Response

```
SP → IdP: AuthnRequest (signed)
IdP → SP: Response (signed assertion)
```

## Key XML Elements

```xml
<Response>
  <Assertion>
    <Issuer>https://idp.example.com</Issuer>
    <Subject>
      <NameID>user@example.com</NameID>
    </Subject>
    <Conditions NotBefore="..." NotOnOrAfter="..."/>
    <AttributeStatement>
      <Attribute Name="email">user@example.com</Attribute>
    </AttributeStatement>
  </Assertion>
</Response>
```

## Validation Steps

1. Verify Response signature (IdP's cert)
2. Verify Assertion signature
3. Check `NotOnOrAfter` / `NotBefore` timing
4. Verify `Audience` matches SP entityId
5. Verify `Issuer` matches expected IdP

## Tools

```bash
# Decode SAML (base64 → inflate → XML)
echo "SAML_RESPONSE" | base64 -d | python -c "import zlib,sys; print(zlib.decompress(sys.stdin.buffer.read()))"

# Check signature with xmlsec1
xmlsec1 --verify --trusted-pem idp-cert.pem response.xml
```
