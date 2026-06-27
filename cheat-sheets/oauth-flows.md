# OAuth 2.0 Grant Types Comparison

## Authorization Code (+ PKCE)

```
Best for:      Web apps, mobile apps, SPAs
Security:     ★★★★★ (with PKCE)
Tokens:       access_token + refresh_token + id_token (OIDC)
User creds:   Never exposed to client
```

## Client Credentials

```
Best for:      Machine-to-machine, backend services
Security:     ★★★★☆
Tokens:       access_token (no refresh)
User creds:   Client ID + Client Secret
```

## Device Code

```
Best for:      Smart TVs, CLI tools, IoT
Security:     ★★★☆☆
Tokens:       access_token + refresh_token
UX:           User enters code on another device
```

## Resource Owner Password (Deprecated)

```
Best for:      Legacy migration ONLY
Security:     ★★☆☆☆
Tokens:       access_token + refresh_token
Warning:      Removed in OAuth 2.1
```
