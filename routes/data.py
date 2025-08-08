import uuid
from typing import List
from fastapi import APIRouter, HTTPException, status, Depends, Request
from utils.helper import verify_token, db, hash_password, log_audit, create_user_base
from schema.models import (
    AddGroupRequest, DeleteUserRequest, DeleteGroupRequest, ResetPasswordRequest,
    AddMedraxUserRequest, AddIDSLUserRequest, UpdateGroupRequest, UpdateUserGroupRequest
)
import secrets
import string
from schema.models import GeneratePasswordRequest
from fastapi import Query
data_router = APIRouter()

from schema.models import ToggleAccessRequest


def is_admin_user(current_user: dict):
    return current_user.get("username") == "admin"

@data_router.post("/data/change_password")
async def change_password(
    request: ResetPasswordRequest,
    current_user: dict = Depends(verify_token)
):
    try:
        # Step 1: Check passwords match
        if request.new_password != request.confirm_new_password:
            log_audit(current_user["user_id"], "/data/change_password", 400, "Passwords do not match")
            raise HTTPException(status_code=400, detail="Passwords do not match")

        # Step 2: Fetch user from DB
        user_data = db.fetch_one(
            "SELECT user_id FROM users WHERE username = %s",
            (current_user["username"],)
        )

        if not user_data:
            raise HTTPException(status_code=404, detail="User not found")

        # Step 3: Hash new password and update
        new_hash = hash_password(request.new_password)

        db.execute_query(
            "UPDATE users SET password_hash = %s, requires_password_reset = 1 WHERE username = %s",
            (new_hash, current_user["username"])
        )

        log_audit(user_data["user_id"], "/data/change_password", 200, "Password set by user")
        return {"message": "Password updated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        log_audit(current_user["user_id"], "/data/change_password", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to change password")


@data_router.get("/data/get_users_idsl")
async def get_users_idsl(current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/get_users_idsl", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        query = """
        SELECT 
            u.user_id, u.username, p.project_name,
            COALESCE(g.group_name, '') AS group_name,
            iu.role,
            up.flag
        FROM users u
        INNER JOIN user_projects up ON u.user_id = up.user_id
        INNER JOIN project p ON up.project_id = p.project_id
        INNER JOIN IDSL_users iu ON u.user_id = iu.user_id
        LEFT JOIN user_groups ug ON u.user_id = ug.user_id
        LEFT JOIN groups g ON ug.group_id = g.group_id
        WHERE LOWER(p.project_name) = 'idsl' AND up.flag = 0
        """

        result = db.fetch_all(query)
        log_audit(current_user["user_id"], "/data/get_users_idsl", 200, "Fetched IDSL users")
        return result
    except Exception as e:
        log_audit(current_user["user_id"], "/data/get_users_idsl", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching IDSL users")

@data_router.get("/data/get_users_medrax")
async def get_users_medrax(current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/get_users_medrax", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        query = """
        SELECT 
            u.user_id, u.username, p.project_name
        FROM users u
        INNER JOIN user_projects up ON u.user_id = up.user_id
        INNER JOIN project p ON up.project_id = p.project_id
        INNER JOIN MEDRAX_users mu ON u.user_id = mu.user_id
        WHERE LOWER(p.project_name) = 'medrax' AND up.flag = 0
        """
        result = db.fetch_all(query)
        log_audit(current_user["user_id"], "/data/get_users_medrax", 200, "Fetched MEDRAX users")
        return result
    except Exception as e:
        log_audit(current_user["user_id"], "/data/get_users_medrax", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching MEDRAX users")

@data_router.get("/data/get_groups")
async def get_groups(current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/get_groups", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        query = """
        SELECT g.group_id, g.group_name,
               (SELECT u.username FROM users u
                JOIN IDSL_users iu ON u.user_id = iu.user_id
                JOIN user_groups ug ON u.user_id = ug.user_id
                WHERE ug.group_id = g.group_id AND iu.role = 'group_admin' LIMIT 1) AS admin_username,
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
        if "duplicate key value violates unique constraint" in str(e):
            log_audit(current_user["user_id"], "/data/add_group", 400, f"Group '{request.group_name}' already exists")
            raise HTTPException(status_code=400, detail="Group already exists")
        log_audit(current_user["user_id"], "/data/add_group", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error adding group")


@data_router.post("/data/add_user_idsl", status_code=201)
async def add_user_idsl(request: AddIDSLUserRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/add_user_idsl", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        # Check if group exists
        group_record = db.fetch_one("SELECT group_id FROM groups WHERE group_name = %s", (request.group_name,))
        if not group_record:
            raise HTTPException(status_code=400, detail="Invalid group name")
        group_id = group_record["group_id"]

        # Get IDSL project_id
        project_record = db.fetch_one(
            "SELECT project_id FROM project WHERE LOWER(project_name) = LOWER(%s)",
            ("idsl",)
        )
        if not project_record:
            raise HTTPException(status_code=500, detail="IDSL project not found in the database")
        project_id = project_record["project_id"]

        # Check if user already exists
        existing_user = db.fetch_one(
            "SELECT user_id FROM users WHERE username = %s",
            (request.username,)
        )
        
        if existing_user:
            user_id = existing_user["user_id"]
            
            # Check if user already exists in IDSL project
            idsl_user_exists = db.fetch_one(
                "SELECT 1 FROM IDSL_users WHERE user_id = %s",
                (user_id,)
            )
            
            if idsl_user_exists:
                raise HTTPException(status_code=400, detail=f"User '{request.username}' already exists in IDSL project")
            
            # Add user to IDSL project (user_projects table)
            db.execute_query(
                "INSERT INTO user_projects (user_id, project_id, flag) VALUES (%s, %s, 0)",
                (user_id, project_id)
            )
            
            # Add to user_groups
            db.execute_query(
                "INSERT INTO user_groups (user_id, group_id, is_admin) VALUES (%s, %s, %s)",
                (user_id, group_id, request.is_admin)
            )

            # Add to IDSL_users
            db.execute_query(
                "INSERT INTO IDSL_users (user_id, group_id, role) VALUES (%s, %s, %s)",
                (user_id, group_id, 'group_admin' if request.is_admin else 'user')
            )

            log_audit(current_user["user_id"], "/data/add_user_idsl", 201, f"Existing user '{request.username}' added to IDSL project")
            return {
                "message": "User added to IDSL project successfully",
                "user_id": user_id,
                "existing_user": True
            }
        
        else:
            # Create new user entirely
            # Generate a secure password
            alphabet = string.ascii_letters + string.digits
            generated_password = ''.join(secrets.choice(alphabet) for _ in range(12))

            user_id = create_user_base(request.username, generated_password, project_id)

            db.execute_query(
                "INSERT INTO user_groups (user_id, group_id, is_admin) VALUES (%s, %s, %s)",
                (user_id, group_id, request.is_admin)
            )

            db.execute_query(
                "INSERT INTO IDSL_users (user_id, group_id, role) VALUES (%s, %s, %s)",
                (user_id, group_id, 'group_admin' if request.is_admin else 'user')
            )

            log_audit(current_user["user_id"], "/data/add_user_idsl", 201, f"New IDSL user '{request.username}' created")
            return {
                "message": "IDSL user created successfully",
                "user_id": user_id,
                "generated_password": generated_password,
                "existing_user": False
            }

    except HTTPException:
        raise
    except Exception as e:
        log_audit(current_user["user_id"], "/data/add_user_idsl", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error: " + str(e))


@data_router.post("/data/add_user_medrax", status_code=201)
async def add_user_medrax(request: AddMedraxUserRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/add_user_medrax", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        # Check if user already exists in any project
        existing_user = db.fetch_one(
            "SELECT user_id FROM users WHERE username = %s",
            (request.username,)
        )
        
        if existing_user:
            user_id = existing_user["user_id"]
            
            # Check if user already exists in Medrax project
            medrax_user_exists = db.fetch_one(
                "SELECT 1 FROM MEDRAX_users WHERE user_id = %s",
                (user_id,)
            )
            
            if medrax_user_exists:
                raise HTTPException(status_code=400, detail=f"User '{request.username}' already exists in Medrax project")
            
            # Get Medrax project_id
            project_record = db.fetch_one(
                "SELECT project_id FROM project WHERE LOWER(project_name) = LOWER(%s)",
                ("medrax",)
            )
            if not project_record:
                raise HTTPException(status_code=500, detail="Medrax project not found in the database")
            project_id = project_record["project_id"]
            
            # Add user to Medrax project (user_projects table)
            db.execute_query(
                "INSERT INTO user_projects (user_id, project_id, flag) VALUES (%s, %s, 0)",
                (user_id, project_id)
            )
            
            # Add user to MEDRAX_users table
            db.execute_query(
                "INSERT INTO MEDRAX_users (user_id) VALUES (%s)",
                (user_id,)
            )
            
            log_audit(current_user["user_id"], "/data/add_user_medrax", 201, f"Existing user '{request.username}' added to MEDRAX project")
            return {
                "message": "User added to MEDRAX project successfully",
                "user_id": user_id,
                "existing_user": True
            }
        
        else:
            # Create new user entirely
            project_record = db.fetch_one(
                "SELECT project_id FROM project WHERE LOWER(project_name) = LOWER(%s)",
                ("medrax",)
            )
            if not project_record:
                raise HTTPException(status_code=500, detail="Medrax project not found in the database")

            project_id = project_record["project_id"]

            # Generate a secure password
            alphabet = string.ascii_letters + string.digits
            generated_password = ''.join(secrets.choice(alphabet) for _ in range(12))

            user_id = create_user_base(request.username, generated_password, project_id)

            db.execute_query(
                "INSERT INTO MEDRAX_users (user_id) VALUES (%s)",
                (user_id,)
            )

            log_audit(current_user["user_id"], "/data/add_user_medrax", 201, f"New MEDRAX user '{request.username}' created")
            return {
                "message": "MEDRAX user created successfully",
                "user_id": user_id,
                "generated_password": generated_password,
                "existing_user": False
            }

    except HTTPException:
        raise
    except Exception as e:
        log_audit(current_user["user_id"], "/data/add_user_medrax", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error: " + str(e))


@data_router.post("/data/update_user_group", status_code=200)
async def update_user_group(request: UpdateUserGroupRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/update_user_group", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        # 1. Verify user exists
        user = db.fetch_one("SELECT user_id FROM users WHERE user_id = %s", (request.user_id,))
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # 2. Get new group_id
        group = db.fetch_one("SELECT group_id FROM groups WHERE group_name = %s", (request.new_group_name,))
        if not group:
            raise HTTPException(status_code=400, detail="Group not found")
        new_group_id = group["group_id"]

        # 3. Update user_groups table
        db.execute_query(
            "UPDATE user_groups SET group_id = %s WHERE user_id = %s",
            (new_group_id, request.user_id)
        )

        # 4. Update IDSL_users table: set both group_id and role
        db.execute_query(
            "UPDATE IDSL_users SET group_id = %s, role = %s WHERE user_id = %s",
            (new_group_id, request.new_role, request.user_id)
        )

        log_audit(current_user["user_id"], "/data/update_user_group", 200,
                  f"Updated group and role for user {request.user_id} to {request.new_group_name}, {request.new_role}")
        return {
            "message": "User group and role updated successfully",
            "user_id": request.user_id,
            "new_group_name": request.new_group_name,
            "new_role": request.new_role
        }

    except HTTPException:
        raise
    except Exception as e:
        log_audit(current_user["user_id"], "/data/update_user_group", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update user group and role")

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
        LEFT JOIN user_projects up ON p.project_id = up.project_id
        LEFT JOIN users u ON up.user_id = u.user_id
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


@data_router.post("/data/update_group", status_code=200)
async def update_group(request: UpdateGroupRequest, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/update_group", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        # Check if group exists
        group = db.fetch_one("SELECT group_id FROM groups WHERE group_name = %s", (request.current_group_name,))
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Check if the new name already exists
        existing = db.fetch_one("SELECT group_id FROM groups WHERE group_name = %s", (request.new_group_name,))
        if existing:
            raise HTTPException(status_code=400, detail="New group name already exists")

        db.execute_query(
            "UPDATE groups SET group_name = %s WHERE group_name = %s",
            (request.new_group_name, request.current_group_name)
        )

        log_audit(current_user["user_id"], "/data/update_group", 200,
                  f"Group renamed from {request.current_group_name} to {request.new_group_name}")
        return {"message": "Group name updated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        log_audit(current_user["user_id"], "/data/update_group", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update group name")


@data_router.post("/data/generate_password", status_code=200)
async def generate_password_for_user(
    request: GeneratePasswordRequest,
    current_user: dict = Depends(verify_token)
):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/generate_password", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        # Fetch user to ensure they exist
        user = db.fetch_one("SELECT user_id FROM users WHERE username = %s", (request.username,))
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Generate a secure random password
        alphabet = string.ascii_letters + string.digits
        new_password = ''.join(secrets.choice(alphabet) for _ in range(request.length))

        # Hash it
        hashed = hash_password(new_password)

        # Update the password in the database
        db.execute_query(
            "UPDATE users SET password_hash = %s, requires_password_reset = 0 WHERE username = %s",
            (hashed, request.username)
        )

        log_audit(current_user["user_id"], "/data/generate_password", 200, f"Generated new password for {request.username}")
        return {
            "username": request.username,
            "generated_password": new_password
        }

    except Exception as e:
        log_audit(current_user["user_id"], "/data/generate_password", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate password")


@data_router.get("/data/get_all_user_projects")
async def get_all_user_projects(current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/get_all_user_projects", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        query = """
        SELECT u.user_id, u.username, p.project_name
        FROM users u
        LEFT JOIN user_projects up ON u.user_id = up.user_id AND up.flag = 0
        LEFT JOIN project p ON up.project_id = p.project_id
        WHERE LOWER(u.username) != 'admin'
        ORDER BY u.username
        """
        rows = db.fetch_all(query)

        # Group by user, keep id
        tmp = {}
        for r in rows:
            uid = r["user_id"]
            uname = r["username"]
            proj = r["project_name"]
            if uname not in tmp:
                tmp[uname] = {"user_id": uid, "username": uname, "projects": []}
            if proj:
                tmp[uname]["projects"].append(proj)

        result = list(tmp.values())
        log_audit(current_user["user_id"], "/data/get_all_user_projects", 200, "Fetched all user projects")
        return result

    except Exception as e:
        log_audit(current_user["user_id"], "/data/get_all_user_projects", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch user projects")


@data_router.get("/data/get_my_projects")
async def get_my_projects(current_user: dict = Depends(verify_token)):
    """
    Get projects for the currently authenticated user
    Returns only the projects that the current user has active access to (flag = 0)
    """
    try:
        user_id = current_user["user_id"]
        username = current_user["username"]
        
        # Fetch projects for the current user only WHERE flag = 0 (active access)
        query = """
        SELECT p.project_name
        FROM users u
        JOIN user_projects up ON u.user_id = up.user_id
        JOIN project p ON up.project_id = p.project_id
        WHERE u.user_id = %s AND up.flag = 0
        """
        records = db.fetch_all(query, (user_id,))
        
        # Extract project names
        projects = [row["project_name"] for row in records]
        
        result = {
            "username": username,
            "projects": projects
        }
        
        log_audit(user_id, "/data/get_my_projects", 200, f"Fetched active projects for user {username}")
        return result

    except Exception as e:
        log_audit(current_user["user_id"], "/data/get_my_projects", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch user projects")

@data_router.post("/data/toggle_user_access")
async def toggle_user_access(
    request: ToggleAccessRequest,
    current_user: dict = Depends(verify_token)
):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/toggle_user_access", 403, "Unauthorized access")
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        # Verify user exists
        user_exists = db.fetch_one("SELECT 1 FROM users WHERE user_id = %s", (request.user_id,))
        if not user_exists:
            raise HTTPException(status_code=404, detail="User not found")

        # Get project_id from project_name
        project_record = db.fetch_one(
            "SELECT project_id FROM project WHERE LOWER(project_name) = LOWER(%s)",
            (request.project_name.lower(),)
        )
        if not project_record:
            raise HTTPException(status_code=404, detail="Project not found")
        project_id = project_record["project_id"]

        # Check if mapping exists
        existing = db.fetch_one(
            "SELECT flag FROM user_projects WHERE user_id = %s AND project_id = %s",
            (request.user_id, project_id)
        )
        if not existing:
            raise HTTPException(status_code=404, detail="User is not assigned to this project")

        # Toggle flag: 0 = access granted, 1 = revoked
        flag_value = 0 if request.access else 1
        db.execute_query(
            "UPDATE user_projects SET flag = %s WHERE user_id = %s AND project_id = %s",
            (flag_value, request.user_id, project_id)
        )

        action = "granted" if request.access else "revoked"
        msg = f"Access {action} for user {request.user_id} in project {request.project_name}"
        log_audit(current_user["user_id"], "/data/toggle_user_access", 200, msg)
        
        return {
            "message": f"Access {action} successfully",
            "user_id": request.user_id,
            "project_name": request.project_name,
            "access": request.access
        }

    except HTTPException:
        raise
    except Exception as e:
        log_audit(current_user["user_id"], "/data/toggle_user_access", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to toggle user access")
    
@data_router.get("/data/get_user_by_username/{username}")
async def get_user_by_username(username: str, current_user: dict = Depends(verify_token)):
    if not is_admin_user(current_user):
        log_audit(current_user["user_id"], "/data/get_user_by_username", 403, "Forbidden access")
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    try:
        # Get basic user info
        user = db.fetch_one("SELECT user_id FROM users WHERE username = %s", (username,))
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        user_id = user["user_id"]
        
        # Check if user exists in IDSL project
        idsl_exists = db.fetch_one(
            "SELECT 1 FROM IDSL_users WHERE user_id = %s", 
            (user_id,)
        )
        
        # Check if user exists in MEDRAX project
        medrax_exists = db.fetch_one(
            "SELECT 1 FROM MEDRAX_users WHERE user_id = %s", 
            (user_id,)
        )
        
        result = {
            "user_id": user_id,
            "username": username,
            "has_idsl_access": bool(idsl_exists),
            "has_medrax_access": bool(medrax_exists)
        }
        
        log_audit(current_user["user_id"], "/data/get_user_by_username", 200, f"Fetched user info for {username}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        log_audit(current_user["user_id"], "/data/get_user_by_username", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching user information")