# Python — Digest Access Auth

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

## Files

| File | Purpose |
|------|---------|
| `server.py` | FastAPI digest auth server with challenge-response |
| `client.py` | Performs the full challenge-response dance |
