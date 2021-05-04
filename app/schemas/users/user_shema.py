from typing import List, Optional
from pydantic import BaseModel

class UserBase(BaseModel):
    email: str
    username: str
    is_active: Optional[bool] = True
    is_admin: Optional[bool] = False
    is_superuser: Optional[bool] = False

class UserCreate(UserBase):
    password: str


class UserGet(UserBase):
    password: str
    

class SingleUserGet(UserBase):
    user_id: int
    password: str


class AllUsersGet(BaseModel):
    users: list
