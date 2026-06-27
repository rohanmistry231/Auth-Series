# HTTP Auth Headers Cheat Sheet

## Request Headers

```
# Basic Auth
Authorization: Basic base64(username:password)

# Bearer Token
Authorization: Bearer <token>

# API Key (custom header)
X-API-Key: <api-key>

# Digest Auth
Authorization: Digest username="user", realm="...", nonce="...",
                    uri="...", response="...", opaque="..."

# AWS Signature V4
Authorization: AWS4-HMAC-SHA256 Credential=.../SignedHeaders=.../Signature=...

# Mutual TLS (client cert)
SSL_CLIENT_CERT: <certificate>
```

## Response Headers

```
# WWW-Authenticate (401 response)
WWW-Authenticate: Basic realm="Protected Area"
WWW-Authenticate: Bearer realm="example", error="invalid_token"
WWW-Authenticate: Digest realm="example", nonce="...", algorithm=MD5
```
