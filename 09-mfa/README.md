# 09 — Multi-Factor Authentication (MFA)

MFA requires the user to present evidence from **two or more distinct categories** of authentication factors. It is the single most effective control against credential theft.

---

## 1. Factor Categories

```
FACTOR CATEGORIES
══════════════════

┌────────────────────┐
│  KNOWLEDGE         │
│  (something you    │      Password, PIN, security question
│   know)            │
└────────┬───────────┘
         │
         │  ALONE: insufficient (phishable, guessable)
         │
┌────────▼───────────┐
│  POSSESSION        │
│  (something you    │      TOTP app, SMS code, hardware key
│   have)            │
└────────┬───────────┘
         │
         │  ALONE: good (but device can be lost/stolen)
         │
┌────────▼───────────┐
│  INHERENCE         │
│  (something you    │      Fingerprint, Face ID, voice
│   are)             │
└────────────────────┘
```

---

## 2. TOTP — Complete Algorithm Specification

RFC 6238 defines Time-Based One-Time Password algorithm:

```
TOTP(K, T) = HOTP(K, floor((T - T0) / X))

Where:
  K  = shared secret (base32-encoded, ≥ 128 bits)
  T  = current Unix time (seconds since epoch)
  T0 = starting time (0 = Unix epoch)
  X  = time step (30 seconds recommended)
```

### Implementation

```python
import hmac, hashlib, struct, time, base64

def generate_totp(secret_b32: str, time_step: int = 30, digits: int = 6) -> str:
    # Decode base32 secret
    key = base64.b32decode(secret_b32, casefold=True)

    # Counter
    counter = struct.pack(">Q", int(time.time() / time_step))

    # HMAC-SHA1
    hs = hmac.new(key, counter, hashlib.sha1).digest()

    # Dynamic truncation (RFC 4226)
    offset = hs[-1] & 0x0f
    code = ((hs[offset] & 0x7f) << 24 |
            (hs[offset + 1] & 0xff) << 16 |
            (hs[offset + 2] & 0xff) << 8 |
            (hs[offset + 3] & 0xff))

    # Modulo for requested digits
    return str(code % (10 ** digits)).zfill(digits)
```

### TOTP Validation Window

```
Current time window:
  |  Δ = -2  |  Δ = -1  |  Δ = 0   |  Δ = +1  |  Δ = +2  |
  |----------|----------|----------|----------|----------|
              ↑          ↑                    ↑
           past codes  current code        future codes
                        (accepted)           (rejected)

Standard validation window: ±1 step (3 windows total: -1, 0, +1)
Extended window: ±2 steps (5 windows — generous clock skew allowance)
```

---

## 3. MFA Methods — Risk Analysis

| Method | Phishing Resistant | SIM Swap | Cost | UX | Recovery |
|--------|-------------------|----------|------|----|----------|
| **TOTP** | No | N/A | Free | Good (scan + 6 digits) | Recovery codes |
| **SMS** | No | **Yes** | $0.01/msg | Excellent | SIM reissue |
| **Push** | No | N/A | Free | Excellent | App reinstall |
| **WebAuthn** | **Yes** | N/A | Free | Excellent (biometric + key) | Platform sync |
| **YubiKey** | **Yes** | N/A | $50–$70 | Good (plug + touch) | Backup key |
| **Email OTP** | No | N/A | Free | Fair | Email access |
| **Backup codes** | In-band | N/A | Free | Poor | — |

---

## 4. Recovery Codes

```
Generated: 10 codes, single-use, presented at MFA enrollment
Format:    xxxx-xxxx-xxxx (12 chars base62)
Storage:   bcrypt hash (one code = one db row)

Example codes:
  a3B7-k9M2-pQ5R
  x1Y8-z4N6-cW2E
  ...

Enforcement:
  - Each code consumed on use
  - Track remaining codes; warn when < 3
  - Regenerate invalidates old set
```

---

## 5. Code Examples

### Java (TOTP with Google Authenticator compatibility)

```java
// build.gradle: implementation 'com.google.guava:guava:33.0.0'

public class TotpService {

    private static final int TIME_STEP = 30;
    private static final int DIGITS = 6;
    private static final int VALIDATION_WINDOW = 1;  // ±1 step

    public String generateSecret() {
        byte[] key = new byte[20];  // 160 bits
        new SecureRandom().nextBytes(key);
        return Base32.getEncoder().encodeToString(key);
    }

    public String generateTotp(String secret) {
        return generateTotp(secret, Instant.now());
    }

    public String generateTotp(String secret, Instant time) {
        long counter = time.getEpochSecond() / TIME_STEP;

        byte[] key = Base32.getDecoder().decode(secret);
        byte[] msg = ByteBuffer.allocate(8).putLong(counter).array();
        byte[] hmac = Hmac.hmacSha1(key, msg);

        int offset = hmac[hmac.length - 1] & 0x0f;
        int code = ((hmac[offset] & 0x7f) << 24)
                 | ((hmac[offset + 1] & 0xff) << 16)
                 | ((hmac[offset + 2] & 0xff) << 8)
                 | (hmac[offset + 3] & 0xff);

        return String.format("%06d", code % (int) Math.pow(10, DIGITS));
    }

    public boolean validateTotp(String secret, String code) {
        Instant now = Instant.now();
        for (int i = -VALIDATION_WINDOW; i <= VALIDATION_WINDOW; i++) {
            String expected = generateTotp(secret, now.plusSeconds(i * TIME_STEP));
            if (MessageDigest.isEqual(
                    code.getBytes(), expected.getBytes())) {
                return true;
            }
        }
        return false;
    }
}
```

### Python (pyotp)

```python
import pyotp

# Generate secret
secret = pyotp.random_base32()  # 16 chars (80 bits) — use 32 chars for 160 bits
# "JBSWY3DPEHPK3PXP"

# Generate TOTP object
totp = pyotp.TOTP(secret, interval=30, digits=6)

# Generate code
code = totp.now()  # "482936"

# Validate
totp.verify("482936", valid_window=1)  # True

# Provisioning URI (for QR code)
uri = totp.provisioning_uri(
    name="user@example.com",
    issuer_name="Auth Series"
)
# "otpauth://totp/Auth+Series:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Auth+Series"
```

---

## 6. References

- [RFC 6238 — TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
- [RFC 4226 — HOTP](https://datatracker.ietf.org/doc/html/rfc4226)
- [NIST SP 800-63B — Authenticator Assurance](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [WebAuthn Level 2 (W3C)](https://www.w3.org/TR/webauthn-2/)
- [FIDO Alliance](https://fidoalliance.org/)
