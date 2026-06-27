# Auth Security Review Checklist

## Password & Credential Storage
- [ ] Passwords hashed with bcrypt (cost 12+) or argon2id
- [ ] No plaintext or reversible encryption
- [ ] No hardcoded credentials in code
- [ ] Secrets managed via vault/secret manager

## Transport Security
- [ ] TLS 1.2+ enforced (no SSL, no TLS 1.0/1.1)
- [ ] HSTS header set (`max-age=31536000; includeSubDomains`)
- [ ] Valid TLS certificates from trusted CA

## Session Management
- [ ] HttpOnly, Secure, SameSite cookie flags
- [ ] Session ID regenerated on login
- [ ] Idle timeout implemented
- [ ] Absolute session timeout implemented
- [ ] Server-side session destruction on logout
- [ ] Concurrent session limit enforced

## Token Security
- [ ] JWT signed with RS256/ES256 (asymmetric)
- [ ] Short expiration for access tokens (≤ 15 min)
- [ ] Refresh token rotation implemented
- [ ] Token revocation capability
- [ ] JWKS properly managed and rotated

## Endpoint Protection
- [ ] Rate limiting on login/register/reset endpoints
- [ ] Account lockout after N failed attempts
- [ ] CAPTCHA on public auth forms
- [ ] CORS properly restricted
- [ ] Input validation on all inputs

## Authentication
- [ ] MFA available (required for admin roles)
- [ ] Registration email verification
- [ ] Password reset with secure tokens (not email-based reset links without expiry)
- [ ] No user enumeration (same message for user found/not found)

## Authorization
- [ ] Access control on every protected endpoint
- [ ] Least privilege principle applied
- [ ] No IDOR (Insecure Direct Object Reference)

## Monitoring & Logging
- [ ] Auth events logged (login, logout, failures, MFA)
- [ ] No secrets/tokens in logs
- [ ] Alerts on suspicious patterns (many failures, impossible travel)
- [ ] Audit trail for privilege changes

## Dependency Security
- [ ] Auth libraries up to date
- [ ] Known vulnerability scanning in CI/CD
- [ ] Minimal dependency footprint
