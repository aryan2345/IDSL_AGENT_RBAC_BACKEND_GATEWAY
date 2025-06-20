import uuid
from typing import List
from fastapi import APIRouter, HTTPException, status, Depends, Request
from utils.helper import verify_token, db, hash_password, log_audit
from schema.models import (
    User, Group, AddGroupRequest, AddUserRequest,
    UpdateUserRoleRequest, DeleteUserRequest, DeleteGroupRequest,
    DeleteProjectRequest, ProjectRequest,
    ProjectUserRequest, ProjectUserUpdateRequest
)

data_router = APIRouter()


def is_admin_user(current_user: dict):
    return current_user.get("username") == "admin"

@data_router.get("/data/get_users")
async def get_users(request: Request, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/get_users", 403, "Forbidden access")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    try:
        query = """
        SELECT u.user_id, u.username, 
               COALESCE(g.group_name, '') AS group_name
        FROM users u
        LEFT JOIN user_groups ug ON u.user_id = ug.user_id
        LEFT JOIN groups g ON ug.group_id = g.group_id
        """
        result = db.fetch_all(query)
        log_audit(current_user["user_id"], "/data/get_users", 200, "Fetched all users")
        return result
    except Exception as e:
        log_audit(current_user["user_id"], "/data/get_users", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching users")

@data_router.get("/data/get_groups")
async def get_all_groups(request: Request, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/get_groups", 403, "Forbidden access")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    try:
        query = """
        SELECT g.group_id, g.group_name, 
               (SELECT u.username FROM users u 
                JOIN user_groups ug ON u.user_id = ug.user_id 
                WHERE ug.group_id = g.group_id AND ug.is_admin = TRUE LIMIT 1) AS admin_username,
               STRING_AGG(u.username, ', ') AS users
        FROM groups g
        LEFT JOIN user_groups ug ON g.group_id = ug.group_id
        LEFT JOIN users u ON ug.user_id = u.user_id
        GROUP BY g.group_id, g.group_name
        """
        result = db.fetch_all(query)
        log_audit(current_user["user_id"], "/data/get_groups", 200, "Fetched all groups")
        return result
    except Exception as e:
        log_audit(current_user["user_id"], "/data/get_groups", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching groups")

@data_router.post("/data/add_group", status_code=status.HTTP_201_CREATED)
async def add_group(request: AddGroupRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/add_group", 403, "Forbidden access")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    group_id = str(uuid.uuid4())
    try:
        db.execute_query("INSERT INTO groups (group_id, group_name) VALUES (%s, %s)", (group_id, request.group_name))
        log_audit(current_user["user_id"], "/data/add_group", 201, f"Group '{request.group_name}' added")
        return {"message": "Group added successfully", "group_id": group_id, "group_name": request.group_name}
    except Exception as e:
        log_audit(current_user["user_id"], "/data/add_group", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error adding group")

@data_router.post("/data/add_user", status_code=status.HTTP_201_CREATED)
async def add_user(request: AddUserRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        try:
            log_audit(current_user["user_id"], "/data/add_user", 403, "Forbidden access")
        except:
            pass
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    user_id = str(uuid.uuid4())
    password_hash_val = hash_password(request.password)

    try:
        # First, check if the group exists
        group_check = db.fetch_one("SELECT group_id FROM groups WHERE group_id = %s", (request.group_id,))
        if not group_check:
            try:
                log_audit(current_user["user_id"], "/data/add_user", 400, f"Group {request.group_id} does not exist")
            except:
                pass
            raise HTTPException(status_code=400, detail="Invalid group_id: Group does not exist")

        # Check if username already exists
        username_check = db.fetch_one("SELECT user_id FROM users WHERE username = %s", (request.username,))
        if username_check:
            try:
                log_audit(current_user["user_id"], "/data/add_user", 400, f"Username '{request.username}' already exists")
            except:
                pass
            raise HTTPException(status_code=400, detail="Username already exists")

        # Insert user first
        db.execute_query(
            "INSERT INTO users (user_id, username, password_hash) VALUES (%s, %s, %s)",
            (user_id, request.username, password_hash_val)
        )

        # Then add to user_groups
        db.execute_query(
            "INSERT INTO user_groups (user_id, group_id, is_admin) VALUES (%s, %s, %s)",
            (user_id, request.group_id, request.is_admin)
        )

        try:
            log_audit(current_user["user_id"], "/data/add_user", 201, f"User '{request.username}' added")
        except:
            pass

        return {"message": "User added successfully", "user_id": user_id}

    except HTTPException:
        # Re-raise HTTP exceptions (like validation errors)
        raise
    except Exception as e:
        try:
            log_audit(current_user["user_id"], "/data/add_user", 500, f"Database error: {str(e)}")
        except:
            pass
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@data_router.post("/data/update_user", status_code=status.HTTP_201_CREATED)
async def update_user(request: UpdateUserRoleRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/update_user", 403, "Forbidden access")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    try:
        db.execute_query("UPDATE IDSL_users SET role = %s WHERE user_id = %s", (request.role, request.user_id))
        log_audit(current_user["user_id"], "/data/update_user", 201, f"Updated role for user {request.user_id}")
        return {"message": "User role updated successfully", "user_id": request.user_id, "new_role": request.role}
    except Exception as e:
        log_audit(current_user["user_id"], "/data/update_user", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error updating user role")

@data_router.post("/data/delete_user", status_code=status.HTTP_201_CREATED)
async def delete_user(request: DeleteUserRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/delete_user", 403, "Forbidden access")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    try:
        db.execute_query("DELETE FROM user_groups WHERE user_id = %s", (request.user_id,))
        db.execute_query("DELETE FROM IDSL_users WHERE user_id = %s", (request.user_id,))
        db.execute_query("DELETE FROM users WHERE user_id = %s", (request.user_id,))
        log_audit(current_user["user_id"], "/data/delete_user", 201, f"Deleted user {request.user_id}")
        return {"message": "User deleted successfully", "user_id": request.user_id}
    except Exception as e:
        log_audit(current_user["user_id"], "/data/delete_user", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error deleting user")

@data_router.post("/data/delete_group", status_code=status.HTTP_201_CREATED)
async def delete_group(request: DeleteGroupRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/delete_group", 403, "Forbidden access")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    try:
        db.execute_query("DELETE FROM user_groups WHERE group_id = %s", (request.group_id,))
        db.execute_query("DELETE FROM IDSL_users WHERE group_id = %s", (request.group_id,))
        db.execute_query("DELETE FROM groups WHERE group_id = %s", (request.group_id,))
        log_audit(current_user["user_id"], "/data/delete_group", 201, f"Deleted group {request.group_id}")
        return {"message": "Group deleted successfully", "group_id": request.group_id}
    except Exception as e:
        log_audit(current_user["user_id"], "/data/delete_group", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error deleting group")

@data_router.get("/data/fetch_user_information")
async def fetch_user_information(current_user: dict = Depends(verify_token)):
    try:
        query = """
        SELECT ug.group_id
        FROM user_groups ug
        WHERE ug.user_id = %s
        """
        group_records = db.fetch_all(query, (current_user["user_id"],))
        group_ids = [record["group_id"] for record in group_records] if group_records else []

        log_audit(current_user["user_id"], "/data/fetch_user_information", 200, "Fetched user group info")
        return {"user_id": current_user["user_id"], "group_ids": group_ids}
    except Exception as e:
        log_audit(current_user["user_id"], "/data/fetch_user_information", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error fetching user information: {str(e)}")


# ---------- Project & IDSL_users APIs ----------

@data_router.get("/data/get_projects")
async def get_projects(current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        raise HTTPException(status_code=403, detail="Unauthorized")
    return db.fetch_all("SELECT * FROM project")
