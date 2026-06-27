# Cookie Security Flags Cheat Sheet

## Recommended Configuration

```
Set-Cookie: session_id=abc123;
  HttpOnly;          // Not accessible via JavaScript (XSS protection)
  Secure;            // Only sent over HTTPS
  SameSite=Strict;   // Only sent for same-site requests (CSRF protection)
  Max-Age=86400;     // 24 hour lifetime
  Path=/;            // Available site-wide
```

## SameSite Comparison

| Value | Top-level Navigation | Same-site Request | Cross-site Request |
|-------|---------------------|-------------------|-------------------|
| Strict | ✅ | ✅ | ❌ |
| Lax | ✅ | ✅ | ❌ (only GET) |
| None | ✅ | ✅ | ✅ (requires Secure) |

## Critical Flags

| Flag | Purpose | Mitigation |
|------|---------|------------|
| HttpOnly | Block JS access | XSS |
| Secure | HTTPS only | Network eavesdropping |
| SameSite | Restrict cross-site | CSRF |
| Domain | Restrict to domain | Subdomain hijacking |
| Path | Restrict to path | Path traversal |
| Max-Age | Lifetime | Session fixation |
