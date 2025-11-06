from datetime import datetime
from typing import Optional
from pydantic import BaseModel

class UserBase(BaseModel):
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: str = "user"

class UserCreate(UserBase):
    password: str
    is_temporary_password: bool = False

class User(UserBase):
    disabled: bool = False
    created_at: Optional[datetime] = None

class UserInDB(User):
    hashed_password: str

class TokenData(BaseModel):
    user_id: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str

class TokenRefreshRequest(BaseModel):
    access_token: str

class EmailPasswordRequestForm(BaseModel):
    email: str
    password: str
