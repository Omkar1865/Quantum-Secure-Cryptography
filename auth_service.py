import os
import time
import secrets
import bcrypt
import jwt
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

JWT_SECRET = os.getenv("JWT_SECRET", "quantum_demo_jwt_secret_dev_only_change_in_prod")
JWT_ALGORITHM = "HS256"
SESSION_EXPIRY_SECONDS = 86400  # 24 hours

# Pre-hashed default user for evaluation demo (password: "QuantumAdmin2026!")
# bcrypt hash for "QuantumAdmin2026!"
DEMO_USERNAME = os.getenv("DEMO_ADMIN_USER", "admin")
DEMO_PASSWORD = os.getenv("DEMO_ADMIN_PASSWORD", "QuantumAdmin2026!")
_DEFAULT_HASH = bcrypt.hashpw(DEMO_PASSWORD.encode(), bcrypt.gensalt()).decode()

USERS_DB: Dict[str, Dict[str, Any]] = {
    DEMO_USERNAME: {
        "username": DEMO_USERNAME,
        "password_hash": _DEFAULT_HASH,
        "role": "admin"
    }
}

security_bearer = HTTPBearer(auto_error=False)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
    except Exception:
        return False


def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()


def create_access_token(username: str, role: str = "user") -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + SESSION_EXPIRY_SECONDS
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except (jwt.PyJWTError, Exception):
        return None


def get_current_user(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)) -> Dict[str, Any]:
    token = None
    # 1. Bearer header
    if creds and creds.credentials:
        token = creds.credentials
    # 2. Or cookie
    if not token and "access_token" in request.cookies:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(status_code=401, detail="Authentication credentials required")

    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")

    username = payload.get("sub")
    if not username or username not in USERS_DB:
        # Check if bootstrap admin
        if username == DEMO_USERNAME:
            return {"username": DEMO_USERNAME, "role": payload.get("role", "admin")}
        raise HTTPException(status_code=401, detail="User account not found")

    return {"username": username, "role": payload.get("role", "user")}
