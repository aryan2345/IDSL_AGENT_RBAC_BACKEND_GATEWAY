from typing import List, Dict

from pydantic import BaseModel


class UserLogin(BaseModel):
    username: str
    password: str


class ChatRequest(BaseModel):
    chat_id: str
    chat_name: str

class UpdateChatRequest(BaseModel):
    chat_id: str
    chat: List[Dict[str, str]]

class AddGroupRequest(BaseModel):
    group_name: str

class UpdateUserGroupRequest(BaseModel):
    user_id: str
    new_group_name: str


class DeleteUserRequest(BaseModel):
    user_id: str

class DeleteGroupRequest(BaseModel):
    group_id: str

class ChangePasswordRequest(BaseModel):
    username: str
    old_password: str
    new_password: str

class AddMedraxUserRequest(BaseModel):
    username: str
    password: str

class AddIDSLUserRequest(BaseModel):
    username: str
    password: str
    group_name: str
    is_admin: bool

class UpdateGroupRequest(BaseModel):
    current_group_name: str
    new_group_name: str

class GeneratePasswordRequest(BaseModel):
    username: str
    length: int = 12
