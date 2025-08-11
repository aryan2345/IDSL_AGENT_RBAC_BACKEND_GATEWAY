import uuid
from fastapi import APIRouter, HTTPException, status
from schema.models import UserLogin
from database.postgres import PostgresSQL
from utils.helper import (
    hash_password,
    create_access_token,
    create_medrax_token,
    log_audit
)

login_router = APIRouter(tags=["login"])
db = PostgresSQL()


@login_router.post("/login")
async def login(user: UserLogin):
    try:
        # Step 1: Fetch user (+ restrict_access)
        user_data = db.fetch_one(
            """
            SELECT 
                u.user_id, u.username, u.password_hash,
                u.requires_password_reset, u.restrict_access,   -- ← added
                p.project_name
            FROM users u
            JOIN user_projects up ON u.user_id = up.user_id
            JOIN project p ON up.project_id = p.project_id
            WHERE u.username = %s
            ORDER BY p.project_name ASC
            LIMIT 1
            """,
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
        project_name = user_data["project_name"].strip().lower()
        restrict_access = int(user_data.get("restrict_access", 0))  # 0/1

        # (Optional but recommended) Block restricted non-admin accounts at login
        if user.username.strip().lower() != "admin" and restrict_access == 1:
            log_audit(user_id, "/login", 403, "Restricted user blocked at login")
            raise HTTPException(status_code=403, detail="You are restricted")

        # Step 3: Determine role if needed
        role = None
        if user.username.strip().lower() == "admin":
            role = "system_admin"
        elif project_name == "idsl":
            role_row = db.fetch_one("SELECT role FROM IDSL_users WHERE user_id = %s", (user_id,))
            if not role_row:
                raise HTTPException(status_code=404, detail="User role not found")
            role = role_row["role"]

        # Step 4: Generate appropriate token
        if project_name == "medrax":
            access_token, expiry = create_medrax_token(user_id, user.username)
        else:
            access_token, expiry = create_access_token(data={
                "sub": user_id,
                "username": user.username,
                "role": role
            })

        # Step 5: Store session
        session_id = str(uuid.uuid4())
        db.execute_query(
            "INSERT INTO user_sessions (session_id, user_id, token, expiry_timestamp) VALUES (%s, %s, %s, %s)",
            (session_id, user_id, access_token, expiry)
        )

        # Step 6/7: Build response (include restrict_access + convenient boolean)
        base_resp = {
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": user_id,
            "username": user.username,
            "requires_password_reset": user_data["requires_password_reset"],
            "project_name": project_name,
            "restrict_access": restrict_access,        # ← added
            "restricted": bool(restrict_access),       # ← added
        }
        if role:
            base_resp["role"] = role

        if user_data["requires_password_reset"] == 0:
            log_audit(user_id, "/login", 200, "First-time login - password reset required")
            return {
                "message": "Go to /data/change_password to reset your password",
                **base_resp
            }

        log_audit(user_id, "/login", 200, "Login successful")
        return base_resp

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Login failed: " + str(e))

