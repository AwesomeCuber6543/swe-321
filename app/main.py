from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from typing import Optional
from .auth import *
from app.schemas.models import *
from .database import Database, get_db
from app.settings import get_settings
import uuid
from fastapi.middleware.cors import CORSMiddleware
from celery import Celery

settings: Settings = get_settings()


app = FastAPI()



app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)





# API ROUTES
@app.post("/register", response_model=User)
async def register_user(user: UserCreate, db: Database = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Check if user exists

    if current_user.role != "super_admin":
        raise HTTPException(status_code=403, detail="You need to be a super admin to register another user")

    existing_user = await get_user_by_email(user.email, db)
    
    # Only raise the exception if an Item was actually found
    if existing_user and 'Item' in existing_user:
        raise HTTPException(
            status_code=400,
            detail="An account with this email already exists. Please login."
        )
    user.role = "user"
    # Create new user
    hashed_password = get_password_hash(user.password)
    user_dict = {
        'email': user.email,
        'role': user.role,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'school_id': user.school_id,
        'hashed_password': hashed_password,
        'is_temporary_password': user.is_temporary_password,
        'disabled': False,
        'created_at': datetime.now().isoformat()
    }
    
    db.users.put_item(Item=user_dict)
    return User(**user_dict)






@app.post("/refresh", response_model=Token)
async def refresh_token(current_token: TokenRefreshRequest, db: Database = Depends(get_db)):
    # Get token from DynamoDB
    response = db.tokens.get_item(Key={'access_token': current_token.access_token})
    
    print("REFRESH TOKEN RESPONSE: ", response)
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
    
    # Create new tokens
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": token_data['user_id']}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token()
    
    # Store new tokens
    await store_tokens(token_data['user_id'], access_token, refresh_token, db)
    
    # Delete old token
    db.tokens.delete_item(Key={'access_token': current_token.access_token})
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=refresh_token
    )

@app.post("/login", response_model=Token)
async def login_for_access_token(
    form_data: EmailPasswordRequestForm,
    db: Database = Depends(get_db)
):
    user = await authenticate_user(form_data.email, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    #ADD CHECKING IF PASSWORD IS TEMPORARY
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token()
    
    # Store tokens in DynamoDB
    await store_tokens(user.email, access_token, refresh_token, db)
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=refresh_token
    )
    
