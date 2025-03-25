import os
import jwt
import datetime
import hashlib
from typing import Optional
from fastapi import HTTPException, status, Request
from jose import jwt, JWTError
from database.postgres import PostgresSQL

SECRET_KEY = os.getenv("SECRET_KEY", "Thebrownfoxjumpsoverthereiver")  # Use a more secure key in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 5
db = PostgresSQL()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now() + expires_delta

    else:
        expire = datetime.datetime.now() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt, expire


def verify_token(request: Request):
    # Extract the token from the Authorization header
    token = request.headers.get("Authorization")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not provided")

    # Remove the "Bearer " prefix to get the actual token
    token = token.replace("Bearer ", "")

    # Check if the token exists in the user_sessions table and is not expired
    user_session = db.fetch_one(
        "SELECT * FROM user_sessions WHERE token = %s", (token,)
    )

    if not user_session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Check if the token has expired
    if user_session['expiry_timestamp'] < datetime.datetime.now():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")

    # Decode the token to extract the payload (user info)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        role: str = payload.get("role")

        if user_id is None or role is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        return {"user_id": user_id, "role": role}  # Return user info

    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
