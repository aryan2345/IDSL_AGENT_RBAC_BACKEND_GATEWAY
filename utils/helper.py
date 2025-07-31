import os
import uuid

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
        role: str = payload.get("role", None)  # role might be missing in MEDRAX tokens

        if not user_id or not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

        # Fallback for MEDRAX: inject default role
        final_role = "system_admin" if username == "admin" else (role or "medrax_user")

        return {
            "user_id": user_id,
            "username": username,
            "role": final_role
        }

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token - {e}")


def create_user_base(username, password, project_id):
    # ❌ Step 0: Check if username exists for this project already
    existing = db.fetch_one("""
        SELECT u.user_id 
        FROM users u
        JOIN user_projects up ON u.user_id = up.user_id
        WHERE u.username = %s AND up.project_id = %s
    """, (username, project_id))

    if existing:
        raise HTTPException(status_code=400, detail="Username already exists for this project")

    # ✅ Step 1: Check if global user with this username exists
    user = db.fetch_one("SELECT user_id FROM users WHERE username = %s", (username,))

    if user:
        user_id = user["user_id"]
    else:
        user_id = str(uuid.uuid4())
        password_hash_val = hash_password(password)
        db.execute_query(
            "INSERT INTO users (user_id, username, password_hash) VALUES (%s, %s, %s)",
            (user_id, username, password_hash_val)
        )

    # ✅ Step 2: Link to project
    db.execute_query(
        "INSERT INTO user_projects (user_id, project_id) VALUES (%s, %s)",
        (user_id, project_id)
    )

    return user_id



def create_medrax_token(user_id: str, username: str, expires_delta: Optional[datetime.timedelta] = None):
    """Generates JWT access token for MEDRAX users without including a 'role' claim."""
    to_encode = {
        "sub": user_id,
        "username": username
    }

    expire = datetime.datetime.now() + (
        expires_delta or datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, expire


