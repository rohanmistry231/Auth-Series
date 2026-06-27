# Python — MFA / TOTP

## Requirements

- Python 3.10+
- `pip install "fastapi[standard]" uvicorn httpx pyotp`

## Run the Server

```bash
export ALICE_PASSWORD="super-secret"

python server.py
```

## Run the Client

```bash
python client.py
```

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/setup` | POST | Generate TOTP secret + QR URI |
| `/mfa/verify` | POST | Verify TOTP → activate MFA + backup codes |
| `/login` | POST | Password + TOTP login |
| `/recovery` | POST | Backup code login |

## Files

| File | Purpose |
|------|---------|
| `server.py` | FastAPI server with TOTP MFA |
| `client.py` | Demonstrates full MFA lifecycle |
