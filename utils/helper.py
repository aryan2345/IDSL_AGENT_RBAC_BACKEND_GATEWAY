import os
import jwt
import datetime
import hashlib
import logging
from typing import Optional
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from database.postgres import PostgresSQL

logger = logging.getLogger(__name__)

# JWT and DB Setup
SECRET_KEY = os.getenv("SECRET_KEY", "Thebrownfoxjumpsoverthereiver")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
db = PostgresSQL()

# HTTP Bearer Auth Scheme
bearer_scheme = HTTPBearer()

# 🔐 Password Hashing
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# 🔑 Token Creation (includes role in payload)
def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    expire = datetime.datetime.now() + (
        expires_delta or datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, expire

# 📋 Audit Logging
def log_audit(user_id: str, endpoint: str, status_code: int, summary: str = ""):
    if not user_id:
        raise Exception("user_id is required to log audit entries (NOT NULL constraint)")

    try:
        db.execute_query(
            "INSERT INTO audit (user_id, endpoint, status_code, timestamp, response_summary) "
            "VALUES (%s, %s, %s, CURRENT_TIMESTAMP, %s)",
            (user_id, endpoint, status_code, summary)
        )
    except Exception as e:
        logger.error(f"Failed to log audit entry: {e}")

# ✅ Token Validation using HTTPBearer
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials

    # Check if token exists in user_sessions
    user_session = db.fetch_one("SELECT * FROM user_sessions WHERE token = %s", (token,))
    if not user_session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Check expiration
    if user_session['expiry_timestamp'] < datetime.datetime.now():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")

    # Decode JWT
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        username: str = payload.get("username")
        role: str = payload.get("role")

        if not user_id or not username or not role:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

        # Override with system_admin for hardcoded admin user
        final_role = "system_admin" if username == "admin" else role

        return {
            "user_id": user_id,
            "username": username,
            "role": final_role
        }

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token - {e}")
