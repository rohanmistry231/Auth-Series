# Digest Auth — Cheat Sheet

## HTTP Exchange

```
Client                          Server
  │                               │
  │  GET /resource                │
  │──────────────────────────────>│
  │                               │
  │  401                          │
  │  WWW-Authenticate: Digest     │
  │   realm="example.com"         │
  │   nonce="dcd98b..."           │
  │   opaque="5ccc..."            │
  │   qop="auth"                  │
  │<──────────────────────────────│
  │                               │
  │  Authorization: Digest        │
  │   username="alice"            │
  │   realm="example.com"         │
  │   nonce="dcd98b..."           │
  │   uri="/resource"             │
  │   response="6629fae4..."      │
  │   opaque="5ccc..."            │
  │   qop=auth                    │
  │   nc=00000001                 │
  │   cnonce="0a4f..."            │
  │──────────────────────────────>│
```

## Response Calculation

```
HA1  = MD5("user:realm:password")
HA2  = MD5("METHOD:uri")
RESP = MD5("HA1:nonce:nc:cnonce:qop:HA2")
```

## Security Notes

| Issue | Impact |
|-------|--------|
| MD5 is broken | Collision attacks possible |
| No MITM protection | Use HTTPS always |
| No forward secrecy | Key compromise = all sessions |
| Nonce must be random | Prevents replay |
| **Deprecated** | Use JWT or sessions instead |
