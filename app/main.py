from datetime import datetime, timedelta
from typing import Optional
import uuid
import time
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from celery import Celery
from app.auth import *
from app.schemas.models import *
from .database import Database, get_db
from app.settings import get_settings

settings: Settings = get_settings()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/register", response_model=User)
async def register_user(user: UserCreate, db_connection = Depends(get_db)):
    db = Database(db_connection)
    existing_user = await get_user_by_email(user.email, db)
    
    if existing_user and 'Item' in existing_user:
        raise HTTPException(
            status_code=400,
            detail="An account with this email already exists. Please login."
        )
    
    user.role = "user"
    
    hashed_password = get_password_hash(user.password)
    user_dict = {
        'email': user.email,
        'role': user.role,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'hashed_password': hashed_password,
        'is_temporary_password': user.is_temporary_password,
        'disabled': False,
        'created_at': datetime.now().isoformat()
    }
    
    db.users.put_item(Item=user_dict)
    return User(**user_dict)

@app.post("/refresh", response_model=Token)
async def refresh_token(current_token: TokenRefreshRequest, db_connection = Depends(get_db)):
    db = Database(db_connection)
    response = db.tokens.get_item(Key={'access_token': current_token.access_token})
    
    if 'Item' not in response:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token"
        )
    
    token_data = response['Item']
    if int(time.time()) > token_data['expires_at']:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": token_data['user_id']}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token()
    
    await store_tokens(token_data['user_id'], access_token, refresh_token, db)
    
    db.tokens.delete_item(Key={'access_token': current_token.access_token})
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=refresh_token
    )

@app.post("/login", response_model=Token)
async def login_for_access_token(
    form_data: EmailPasswordRequestForm,
    db_connection = Depends(get_db)
):
    db = Database(db_connection)
    user = await authenticate_user(form_data.email, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token()
    
    await store_tokens(user.email, access_token, refresh_token, db)
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=refresh_token
    )

@app.get("/hello")
async def hello_world(current_user: User = Depends(get_current_user)):
    return {
        "message": f"Hello, {current_user.first_name or current_user.email}!",
        "user_email": current_user.email,
        "user_role": current_user.role
    }

@app.get("/")
async def root():
    return {"message": "Welcome to the OAuth API with MySQL!"}