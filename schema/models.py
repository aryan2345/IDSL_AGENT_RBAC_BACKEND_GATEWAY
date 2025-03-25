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

class AddGroupRequest(BaseModel):
    group_name: str

class AddUserRequest(BaseModel):
    username: str
    password: str
    role: str
    group_id: str
    is_admin: bool
