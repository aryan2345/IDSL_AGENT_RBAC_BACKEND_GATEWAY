import uuid

from fastapi import APIRouter, HTTPException, status
from schema.models import UserLogin
from database.postgres import PostgresSQL
from utils.helper import hash_password, create_access_token

login_router = APIRouter(tags=["login"])
db = PostgresSQL()

@login_router.post("/login")
async def login(user: UserLogin):
    # Validate user
    user_data = db.fetch_one("SELECT * FROM users WHERE username = %s AND role != 'deactivated'", (user.username,))
    if not user_data or user_data['password_hash'] != hash_password(user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Generate JWT token
    access_token, expire = create_access_token(data={"sub": user_data['user_id'], "role": user_data['role']})

    # Store the token and its expiration in the database
    session_id = str(uuid.uuid4())
    db.execute_query(
        "INSERT INTO user_sessions (session_id, user_id, token, expiry_timestamp) VALUES (%s, %s, %s, %s)",
        (session_id, user_data['user_id'], access_token, expire)
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user_data['user_id'],
        "role": user_data['role'],
        "username": user.username,
    }