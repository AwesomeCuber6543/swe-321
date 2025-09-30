from datetime import datetime, timedelta
from typing import Optional
import time
import secrets
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from .settings import get_settings
from .schemas.settings import Settings
from .schemas.models import *
from .database import Database, get_db

settings: Settings = get_settings()

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = settings.REFRESH_TOKEN_EXPIRE_DAYS

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_user(email: str, db: Database):
    response = db.users.get_item(Key={'email': email})
    if 'Item' not in response:
        return None
    return UserInDB(**response['Item'])

async def get_user_by_email(email: str, db: Database):
    return db.users.get_item(Key={'email': email})

async def authenticate_user(email: str, password: str, db: Database):
    response = await get_user_by_email(email, db)
    if 'Item' not in response:
        return False
    user = UserInDB(**response['Item'])
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token():
    return secrets.token_urlsafe(32)

async def store_tokens(user_id: str, access_token: str, refresh_token: str, db: Database):
    expires_at = int((datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)).timestamp())
    
    db.tokens.put_item(
        Item={
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user_id': user_id,
            'expires_at': expires_at,
            'token_type': 'bearer'
        }
    )

async def get_current_user(token: str = Depends(oauth2_scheme), db_connection = Depends(get_db)):
    db = Database(db_connection)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id)
    except JWTError:
        raise credentials_exception
        
    user = await get_user(token_data.user_id, db)
    if user is None:
        raise credentials_exception
    return user
