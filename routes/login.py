import uuid
from fastapi import APIRouter, HTTPException, status
from schema.models import UserLogin
from database.postgres import PostgresSQL
from utils.helper import hash_password, create_access_token, log_audit

login_router = APIRouter(tags=["login"])
db = PostgresSQL()

@login_router.post("/login")
async def login(user: UserLogin):
    # Step 1: Validate credentials
    user_data = db.fetch_one("SELECT * FROM users WHERE username = %s", (user.username,))

    if not user_data or user_data['password_hash'] != hash_password(user.password):
        db_user = db.fetch_one("SELECT user_id FROM users WHERE username = %s", (user.username,))
        if db_user:
            log_audit(db_user["user_id"], "/login", 401, "Invalid credentials")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user_id = user_data["user_id"]

    # Step 2: Generate token (encode only sub and username)
    access_token, expire = create_access_token(data={"sub": user_id, "username": user.username})

    # Step 3: Store session
    session_id = str(uuid.uuid4())
    db.execute_query(
        "INSERT INTO user_sessions (session_id, user_id, token, expiry_timestamp) VALUES (%s, %s, %s, %s)",
        (session_id, user_id, access_token, expire)
    )

    # Step 4: Log audit
    log_audit(user_id, "/login", 200, "Login successful")

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user_id,
        "username": user.username
    }
