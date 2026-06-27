# API Keys — Cheat Sheet

## Key Format

```
prefix_secret_suffix
user_stripe_key_example
```

## Generation

```
prefix  = "user_stripe_key_"   (2-8 chars, identifies service)
secret  = random_bytes(32)      (high entropy)
suffix  = hash(secret)[:8]       (for key lookup)

full_key = prefix + base64(secret) + suffix
```

## Storage

```
Stored (DB):   SHA-256(full_key) → { user, scopes, expires, revoked }
Given (user):  prefix + base64(secret) + suffix
```

## Security

| Practice | Why |
|----------|-----|
| Hash the full key | Never store raw credentials |
| Prefix + suffix | Identify key type + look up without full key |
| Scopes | Limit what each key can do |
| Expiry | Rotate keys automatically |
| Revocation | Instant invalidation |

## cURL

```bash
# Header
curl -H "Authorization: Bearer user_stripe_key_..." https://api.example.com/data

# Query param
curl "https://api.example.com/data?api_key=user_stripe_key_..."
```
