from typing import List, Dict

from pydantic import BaseModel

class UserLogin(BaseModel):
    username: str
    password: str

class User(BaseModel):
    user_id: str
    username: str
    role: str
    group_name: str

class Group(BaseModel):
    group_id: str
    group_name: str
    admin_username: str
    users: str

class ChatRequest(BaseModel):
    chat_id: str
    chat_name: str

class UpdateChatRequest(BaseModel):
    chat_id: str
    chat: List[Dict[str, str]]

class AddGroupRequest(BaseModel):
    group_name: str

class AddUserRequest(BaseModel):
    username: str
    password: str
    group_name: str  # Changed from group_id to group_name
    is_admin: bool

class UpdateUserRoleRequest(BaseModel):
    user_id: str
    role: str

class DeleteUserRequest(BaseModel):
    user_id: str

class DeleteGroupRequest(BaseModel):
    group_id: str

class ProjectRequest(BaseModel):
    project_name: str

class DeleteProjectRequest(BaseModel):
    project_id: int

class ProjectUserRequest(BaseModel):
    user_id: str
    project_id: int
    group_id: str
    role: str

class ProjectUserUpdateRequest(BaseModel):
    user_id: str
    project_id: int
    group_id: str
    role: str
