# Python — Security Best Practices

## Requirements

- Python 3.10+
- `pip install "fastapi[standard]" uvicorn httpx`

## Run the Server

```bash
python server.py
```

## Run the Client

```bash
python client.py
```

## Features

| Component | Description |
|-----------|-------------|
| **Rate Limiter** | Sliding window by IP, 5/min login, 20/min page |
| **Security Headers** | HSTS, X-Content-Type-Options, X-Frame-Options, etc. |
| **Audit Logger** | Structured JSON logging of auth events |
| **CSRF Protection** | Token-based CSRF for state-changing requests (ready) |

## Files

| File | Purpose |
|------|---------|
| `server.py` | All security components as middleware + routes |
| `client.py` | Demonstrates rate limiting, login, audit log |
