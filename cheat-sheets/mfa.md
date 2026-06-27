# MFA — Cheat Sheet

## Factors

| Factor | Examples |
|--------|----------|
| Knowledge | Password, PIN, security question |
| Possession | TOTP app, SMS code, hardware key |
| Inherence | Fingerprint, Face ID, voice |

## TOTP (RFC 6238)

```
Secret  →  Time-based HMAC  →  6-digit code (30s window)
```

### Setup
```
Server:  Generate secret → QR URI → User scans
Client:  authenticator.app/otpauth://totp/...
```

### Verification
```
Server:  TOTP(secret, time_window) == user_code
         (allow ±1 window for clock drift)
```

## Recovery Codes

| Property | Value |
|----------|-------|
| Count | 5-10 codes |
| Length | 8-16 chars (hex) |
| Storage | SHA-256 hashed in DB |
| Usage | Single-use, shown once |

## Security

- Rate-limit TOTP attempts (3-5 per window)
- SMS is deprecated by NIST (SIM swap risk)
- WebAuthn is phishing-resistant
- Backup codes bypass MFA — store securely
