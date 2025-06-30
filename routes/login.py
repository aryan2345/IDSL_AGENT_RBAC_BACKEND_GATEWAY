import uuid
from fastapi import APIRouter, HTTPException, status
from schema.models import UserLogin
from database.postgres import PostgresSQL
from utils.helper import hash_password, create_access_token, log_audit

login_router = APIRouter(tags=["login"])
db = PostgresSQL()


@login_router.post("/login")
async def login(user: UserLogin):
    try:
        # Step 1: Fetch user by username
        user_data = db.fetch_one(
            "SELECT user_id, username, password_hash, requires_password_reset FROM users WHERE username = %s",
            (user.username,)
        )

        # Step 2: Validate credentials
        if not user_data or user_data["password_hash"] != hash_password(user.password):
            user_id_for_log = user_data["user_id"] if user_data else None
            if not user_id_for_log:
                found = db.fetch_one("SELECT user_id FROM users WHERE username = %s", (user.username,))
                user_id_for_log = found["user_id"] if found else None

            if user_id_for_log:
                log_audit(user_id_for_log, "/login", 401, "Invalid credentials")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

        user_id = user_data["user_id"]

        # Step 3: Determine role
        if user.username.strip().lower() == "admin":
            role = "system_admin"
        else:
            role = None
        print(role)
        if role is None:
            role_row = db.fetch_one("SELECT role FROM IDSL_users WHERE user_id = %s", (user_id,))
            if not role_row:
                raise HTTPException(status_code=404, detail="User role not found")
            role = role_row["role"]

        # Step 4: Generate access token
        access_token, expiry = create_access_token(data={
            "sub": user_id,
            "username": user.username,
            "role": role
        })
        print(f"[INFO] Token generated for user '{user_data['username']}' with role '{role}'. Token: {access_token}")

        # Step 5: Store session
        session_id = str(uuid.uuid4())
        db.execute_query(
            "INSERT INTO user_sessions (session_id, user_id, token, expiry_timestamp) VALUES (%s, %s, %s, %s)",
            (session_id, user_id, access_token, expiry)
        )

        # Step 6: First-time login check (only for group_admin and user)
        if role in ["group_admin", "user"] and user_data["requires_password_reset"] == 1:
            log_audit(user_id, "/login", 200, "First-time login - password reset required")
            return {
                "message": "Go to /data/change_password to reset your password",
                "access_token": access_token,
                "token_type": "bearer",
                "user_id": user_id,
                "username": user.username,
                "role": role
            }

        # Step 7: Normal login response
        log_audit(user_id, "/login", 200, "Login successful")
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": user_id,
            "username": user.username,
            "role": role
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Login failed: " + str(e))
