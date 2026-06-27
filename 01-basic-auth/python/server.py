"""HTTP Basic Auth server using FastAPI."""

import os
import secrets

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

app = FastAPI(title="Basic Auth Example")
security = HTTPBasic(auto_error=False)

USERS = {
    "alice": os.environ.get("ALICE_PASSWORD", "password-alice"),
    "bob":   os.environ.get("BOB_PASSWORD", "password-bob"),
}

class UserResponse(BaseModel):
    username: str
    message: str

@app.get("/public")
def public_endpoint() -> dict:
    return {"message": "This is public — no auth required"}

def authenticate(credentials: HTTPBasicCredentials | None) -> str:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Basic"},
        )

    expected = USERS.get(credentials.username)
    if expected is None or not secrets.compare_digest(expected, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username

@app.get("/protected", response_model=UserResponse)
def protected_endpoint(username: str = Depends(authenticate)) -> UserResponse:
    return UserResponse(username=username, message="Authenticated via Basic Auth")

if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
