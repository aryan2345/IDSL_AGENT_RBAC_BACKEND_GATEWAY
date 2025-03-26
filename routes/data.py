import uuid
from typing import List
from fastapi import APIRouter, HTTPException, status, Depends, Request
from utils.helper import verify_token, db, hash_password
from schema.models import User, Group, AddGroupRequest, AddUserRequest, UpdateUserRoleRequest, DeleteUserRequest, \
    DeleteGroupRequest

data_router = APIRouter()

@data_router.get("/data/get_users")
async def get_users(request: Request, current_user: dict = Depends(verify_token)):
    if current_user["role"] != "system_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    # Fetch all users from the database
    query = """
    SELECT u.user_id, u.username, u.role, COALESCE(g.group_name, '') AS group_name
    FROM users u
    LEFT JOIN groups g ON u.group_id = g.group_id
    WHERE u.role != 'deactivated'
    """
    users = db.fetch_all(query)

    return users

@data_router.get("/data/get_groups")
async def get_all_groups(request: Request, current_user: dict = Depends(verify_token)):
    # Check if the current user has an 'admin' role
    if current_user["role"] != "system_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    # Fetch all groups with their admin and users using JOIN
    query = """
    SELECT g.group_id, g.group_name, 
           (SELECT u.username FROM users u 
            JOIN user_groups ug ON u.user_id = ug.user_id 
            WHERE ug.group_id = g.group_id AND ug.is_admin = TRUE) AS admin_username,
           STRING_AGG(u.username, ', ') AS users
    FROM groups g
    LEFT JOIN user_groups ug ON g.group_id = ug.group_id
    LEFT JOIN users u ON ug.user_id = u.user_id
    GROUP BY g.group_id, g.group_name
    """
    groups = db.fetch_all(query)

    return groups

@data_router.post("/data/add_group", status_code=status.HTTP_201_CREATED)
async def add_group(request: AddGroupRequest, current_user: dict = Depends(verify_token)):
    # Check if the current user has an 'admin' role
    if current_user["role"] != "system_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    # Generate a unique group_id using UUID
    group_id = str(uuid.uuid4())

    # Insert the new group into the database
    try:
        db.execute_query(
            "INSERT INTO groups (group_id, group_name) VALUES (%s, %s)",
            (group_id, request.group_name)
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error adding group")

    return {"message": "Group added successfully", "group_id": group_id, "group_name": request.group_name}

@data_router.post("/data/add_user", status_code=status.HTTP_201_CREATED)
async def add_user(request: AddUserRequest, current_user: dict = Depends(verify_token)):
    # Check if the current user has an 'admin' role
    if current_user["role"] != "system_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    user_id = str(uuid.uuid4())
    password_hash = hash_password(request.password)

    try:
        db.execute_query(
            "INSERT INTO users (user_id, username, password_hash, role, group_id) VALUES (%s, %s, %s, %s, %s)",
            (user_id, request.username, password_hash, request.role, request.group_id)
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error adding user")

    try:
        db.execute_query(
            "INSERT INTO user_groups (user_id, group_id, is_admin) VALUES (%s, %s, %s)",
            (user_id, request.group_id, request.is_admin)
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error adding user to group")

    return {"message": "User added successfully", "user_id": user_id, "username": request.username}

@data_router.post("/data/update_user", status_code=status.HTTP_201_CREATED)
async def update_user(request: UpdateUserRoleRequest, current_user: dict = Depends(verify_token)):
    # Check if the current user has an 'admin' role
    if current_user["role"] != "system_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    # Check if the provided user_id exists in the users table
    user = db.fetch_one("SELECT * FROM users WHERE user_id = %s", (request.user_id,))
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    try:
        db.execute_query(
            "UPDATE users SET role = %s WHERE user_id = %s",
            (request.role, request.user_id)
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error updating user role")

    return {"message": "User role updated successfully", "user_id": request.user_id, "new_role": request.role}

@data_router.post("/data/delete_user", status_code=status.HTTP_201_CREATED)
async def delete_user(request: DeleteUserRequest, current_user: dict = Depends(verify_token)):
    # Check if the current user has an 'admin' role
    if current_user["role"] != "system_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    # Check if the user to be deactivated exists in the users table
    user = db.fetch_one("SELECT * FROM users WHERE user_id = %s", (request.user_id,))
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Remove the user from the user_groups table
    try:
        db.execute_query("DELETE FROM user_groups WHERE user_id = %s", (request.user_id,))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Error removing user from groups")

    # Update the user's role to 'deactivated' in the users table (soft delete)
    try:
        db.execute_query("UPDATE users SET role = %s WHERE user_id = %s", ("deactivated", request.user_id))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error deactivating user")

    return {"message": "User deactivated successfully", "user_id": request.user_id}

@data_router.post("/data/delete_group", status_code=status.HTTP_201_CREATED)
async def delete_group(request: DeleteGroupRequest, current_user: dict = Depends(verify_token)):
    # Check if the current user has an 'admin' role
    if current_user["role"] != "system_admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    # Check if the provided group_id exists in the groups table
    group = db.fetch_one("SELECT * FROM groups WHERE group_id = %s", (request.group_id,))
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")

    # Remove all entries from the user_groups table where group_id matches the given group_id
    try:
        db.execute_query("DELETE FROM user_groups WHERE group_id = %s", (request.group_id,))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Error removing users from group")

    # Set group_id to NULL for all users that belong to this group
    try:
        db.execute_query("UPDATE users SET group_id = NULL WHERE group_id = %s", (request.group_id,))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error updating users")

    # Now, delete the group from the groups table
    try:
        db.execute_query("DELETE FROM groups WHERE group_id = %s", (request.group_id,))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error deleting group")

    return {"message": "Group deleted successfully", "group_id": request.group_id}