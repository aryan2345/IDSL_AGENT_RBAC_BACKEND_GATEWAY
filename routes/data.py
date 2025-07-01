import uuid
from typing import List
from fastapi import APIRouter, HTTPException, status, Depends, Request
from utils.helper import verify_token, db, hash_password, log_audit, create_user_base
from schema.models import (
    User, Group, AddGroupRequest, AddUserRequest,
    UpdateUserRoleRequest, DeleteUserRequest, DeleteGroupRequest,
    DeleteProjectRequest, ProjectRequest,
    ProjectUserRequest, ProjectUserUpdateRequest, ChangePasswordRequest,
    AddMedraxUserRequest, AddIDSLUserRequest
)

data_router = APIRouter()

def is_admin_user(current_user: dict):
    return current_user.get("username") == "admin"

@data_router.post("/data/change_password")
async def change_password(
    request: ChangePasswordRequest,
    current_user: dict = Depends(verify_token)
):
    try:
        if current_user["username"] != request.username:
            log_audit(current_user["user_id"], "/data/change_password", 403, "Cannot change another user's password")
            raise HTTPException(status_code=403, detail="You can only change your own password")

        user_data = db.fetch_one("SELECT user_id, password_hash, requires_password_reset FROM users WHERE username = %s", (request.username,))
        if not user_data:
            raise HTTPException(status_code=404, detail="User not found")

        if user_data["password_hash"] != hash_password(request.old_password):
            raise HTTPException(status_code=401, detail="Incorrect old password")

        new_hash = hash_password(request.new_password)
        db.execute_query(
            "UPDATE users SET password_hash = %s, requires_password_reset = 0 WHERE username = %s",
            (new_hash, request.username)
        )

        log_audit(user_data["user_id"], "/data/change_password", 200, "Password changed successfully")
        return {"message": "Password updated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        log_audit(current_user["user_id"], "/data/change_password", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to change password")

@data_router.get("/data/get_users")
async def get_users(request: Request, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/get_users", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        query = """
        SELECT u.user_id, u.username, u.project_id,
               COALESCE(g.group_name, '') AS group_name,
               iu.role
        FROM users u
        LEFT JOIN user_groups ug ON u.user_id = ug.user_id
        LEFT JOIN groups g ON ug.group_id = g.group_id
        LEFT JOIN IDSL_users iu ON u.user_id = iu.user_id
        """
        result = db.fetch_all(query)
        log_audit(current_user["user_id"], "/data/get_users", 200, "Fetched all users")
        return result
    except Exception as e:
        log_audit(current_user["user_id"], "/data/get_users", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching users")

@data_router.get("/data/get_groups")
async def get_groups(current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/get_groups", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

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

@data_router.post("/data/add_group", status_code=201)
async def add_group(request: AddGroupRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/add_group", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    group_id = str(uuid.uuid4())
    try:
        db.execute_query(
            "INSERT INTO groups (group_id, group_name) VALUES (%s, %s)",
            (group_id, request.group_name)
        )
        log_audit(current_user["user_id"], "/data/add_group", 201, f"Group '{request.group_name}' added")
        return {"message": "Group added successfully", "group_id": group_id}
    except Exception as e:
        log_audit(current_user["user_id"], "/data/add_group", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error adding group")

@data_router.post("/data/add_user_idsl", status_code=201)
async def add_user_idsl(request: AddIDSLUserRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/add_user_idsl", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        group_record = db.fetch_one("SELECT group_id FROM groups WHERE group_name = %s", (request.group_name,))
        if not group_record:
            raise HTTPException(status_code=400, detail="Invalid group name")
        group_id = group_record["group_id"]

        project_record = db.fetch_one(
            "SELECT project_id FROM project WHERE LOWER(project_name) = LOWER(%s)",
            ("idsl",)
        )

        if not project_record:
            raise HTTPException(status_code=500, detail="IDSL project not found in the database")
        project_id = project_record["project_id"]

        user_id = create_user_base(request.username, request.password, project_id)

        db.execute_query(
            "INSERT INTO user_groups (user_id, group_id, is_admin) VALUES (%s, %s, %s)",
            (user_id, group_id, request.is_admin)
        )

        db.execute_query(
            "INSERT INTO IDSL_users (user_id, group_id, role) VALUES (%s, %s, %s)",
            (user_id, group_id, 'group_admin' if request.is_admin else 'user')
        )

        log_audit(current_user["user_id"], "/data/add_user_idsl", 201, f"IDSL user '{request.username}' added")
        return {"message": "IDSL user added successfully", "user_id": user_id}

    except Exception as e:
        log_audit(current_user["user_id"], "/data/add_user_idsl", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error: " + str(e))

@data_router.post("/data/add_user_medrax", status_code=201)
async def add_user_medrax(request: AddMedraxUserRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/add_user_medrax", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        project_record = db.fetch_one(
            "SELECT project_id FROM project WHERE LOWER(project_name) = LOWER(%s)",
            ("medrax",)
        )
        if not project_record:
            raise HTTPException(status_code=500, detail="Medrax project not found in the database")

        project_id = project_record["project_id"]
        user_id = create_user_base(request.username, request.password, project_id)

        db.execute_query(
            "INSERT INTO MEDRAX_users (user_id) VALUES (%s)",
            (user_id,)
        )

        log_audit(current_user["user_id"], "/data/add_user_medrax", 201, f"MEDRAX user '{request.username}' added")
        return {"message": "MEDRAX user added successfully", "user_id": user_id}

    except Exception as e:
        log_audit(current_user["user_id"], "/data/add_user_medrax", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error: " + str(e))

@data_router.post("/data/update_user", status_code=201)
async def update_user_role(request: UpdateUserRoleRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/update_user", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        if request.role not in ["group_admin", "user"]:
            raise HTTPException(status_code=400, detail="Invalid role")

        db.execute_query(
            "UPDATE IDSL_users SET role = %s WHERE user_id = %s",
            (request.role, request.user_id)
        )
        log_audit(current_user["user_id"], "/data/update_user", 201, f"Updated role for user {request.user_id}")
        return {"message": "User role updated", "user_id": request.user_id}
    except HTTPException:
        raise
    except Exception as e:
        log_audit(current_user["user_id"], "/data/update_user", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update user role")

@data_router.get("/data/get_projects")
async def get_projects(current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/get_projects", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        query = """
        SELECT 
            p.project_id,
            p.project_name,
            COUNT(DISTINCT u.user_id) AS total_users,
            COUNT(DISTINCT ug.group_id) AS total_groups,
            STRING_AGG(DISTINCT g.group_name, ', ') AS group_names
        FROM project p
        LEFT JOIN users u ON p.project_id = u.project_id
        LEFT JOIN user_groups ug ON u.user_id = ug.user_id
        LEFT JOIN groups g ON ug.group_id = g.group_id
        GROUP BY p.project_id
        """
        result = db.fetch_all(query)
        log_audit(current_user["user_id"], "/data/get_projects", 200, "Fetched all projects")
        return {"projects": result}
    except Exception as e:
        log_audit(current_user["user_id"], "/data/get_projects", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching projects")


@data_router.post("/data/delete_user", status_code=status.HTTP_201_CREATED)
async def delete_user(request: DeleteUserRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    user = db.fetch_one("SELECT * FROM users WHERE user_id = %s", (request.user_id,))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        # Only delete from users table; all related records will be deleted automatically
        db.execute_query("DELETE FROM users WHERE user_id = %s", (request.user_id,))

        log_audit(current_user["user_id"], "/data/delete_user", 201, f"Deleted user {request.user_id}")
        return {"message": "User deleted successfully", "user_id": request.user_id}

    except Exception as e:
        log_audit(current_user["user_id"], "/data/delete_user", 500, f"Error deleting user: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete user")

@data_router.post("/data/delete_group", status_code=status.HTTP_201_CREATED)
async def delete_group(request: DeleteGroupRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # Check if the group exists
    group = db.fetch_one("SELECT * FROM groups WHERE group_id = %s", (request.group_id,))
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    try:
        # Only delete from groups table; ON DELETE CASCADE takes care of child tables
        db.execute_query("DELETE FROM groups WHERE group_id = %s", (request.group_id,))

        log_audit(current_user["user_id"], "/data/delete_group", 201, f"Deleted group {request.group_id}")
        return {"message": "Group deleted successfully", "group_id": request.group_id}

    except Exception as e:
        log_audit(current_user["user_id"], "/data/delete_group", 500, f"Error deleting group: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete group")


