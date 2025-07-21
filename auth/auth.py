from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional, Union, Any
from uuid import uuid4
import os

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import EmailStr
from sqlmodel import Session, select
from dotenv import load_dotenv

from db_connect.settings import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    ALGORITHM,
    REFRESH_TOKEN_EXPIRE_MINUTES,
    SECRET_KEY,
    JWT_REFRESH_SECRET_KEY
)
from db_connect.db import get_session
from models.user_model import (
    LoginResponse,
    TokenData,
    User,
    UserCreate,
    UserLogin,
    UserResponse,
    UserUpdate,
    UserRole,
    AdminUserUpdate,
    RefreshToken,
    PasswordResetToken,
    PasswordResetRequest,
    PasswordReset
)

# Load environment variables
load_dotenv()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/login-swagger")

# Exceptions
credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

# Utility Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_by_username(db: Session, username: str) -> User:
    user = db.exec(select(User).where(User.username == username)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def get_user_by_email(db: Session, user_email: EmailStr) -> User:
    user = db.exec(select(User).where(User.email == user_email)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def get_user_by_id(db: Session, userid: int) -> User:
    user = db.get(User, userid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: Union[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES))
    to_encode = {"exp": expire, "sub": str(data)}
    return jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        return jwt.decode(token, JWT_REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

def verify_refresh_token(db: Session, token: str) -> User:
    try:
        payload = jwt.decode(token, JWT_REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")

        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")

        stored_token = db.exec(select(RefreshToken).where(RefreshToken.token == token)).first()
        if not stored_token or stored_token.expires_at < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Refresh token expired or invalid")

        return get_user_by_username(db, user_id)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def revoke_refresh_token(db: Session, token: str):
    stored_token = db.exec(select(RefreshToken).where(RefreshToken.token == token)).first()
    if stored_token:
        db.delete(stored_token)
        db.commit()

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Annotated[Session, Depends(get_session)]) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        exp = payload.get("exp")

        if username is None or datetime.now(timezone.utc).timestamp() > exp:
            raise credentials_exception

        return get_user_by_username(db, username)
    except JWTError:
        raise credentials_exception

def authenticate_user(db: Session, username: str, password: str) -> User:
    user = get_user_by_username(db, username)
    if not verify_password(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return user

# Authorization checks
async def check_admin(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only administrators can access this resource")
    return current_user

async def check_admin_or_teacher(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    if current_user.role not in [UserRole.ADMIN, UserRole.TEACHER]:
        raise HTTPException(status_code=403, detail="Only administrators and teachers can access this resource")
    return current_user

async def check_authenticated_user(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    return current_user

# User Operations
def user_login(db: Session, form_data: UserLogin | OAuth2PasswordRequestForm) -> LoginResponse:
    user = authenticate_user(db, form_data.username, form_data.password)

    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data=user.username)

    user_response = UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        designation=user.designation
    )

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        token_type="bearer",
        user=user_response
    )

async def signup_user(user: UserCreate, db: Session) -> User:
    try:
        normalized_role = UserRole(user.role.upper()) if isinstance(user.role, str) else user.role

        if db.exec(select(User).where(User.email == user.email)).first():
            raise HTTPException(status_code=409, detail="Email already registered")

        if db.exec(select(User).where(User.username == user.username)).first():
            raise HTTPException(status_code=409, detail="Username already exists")

        new_user = User(
            username=user.username,
            email=user.email,
            password=get_password_hash(user.password),
            role=normalized_role
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating user: {str(e)}")

def update_user(user: UserUpdate, session: Session, current_user: User) -> User:
    updated_user = session.exec(select(User).where(User.id == current_user.id)).first()
    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = user.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        value = value if key != "password" else get_password_hash(value)
        setattr(updated_user, key, value)

    session.commit()
    session.refresh(updated_user)
    return updated_user

def delete_user(session: Session, username: str) -> dict[str, str]:
    user = session.exec(select(User).where(User.username == username)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    session.delete(user)
    session.commit()
    return {"message": f"User {username} deleted successfully"}

async def admin_update_user(username: str, user_update: AdminUserUpdate, db: Session, current_user: Annotated[User, Depends(check_admin)]) -> User:
    user_to_update = db.exec(select(User).where(User.username == username)).first()
    if not user_to_update:
        raise HTTPException(status_code=404, detail=f"User {username} not found")

    if user_to_update.username == current_user.username:
        raise HTTPException(status_code=403, detail="Admin cannot change their own role")

    try:
        new_role = UserRole(user_update.role.upper()) if isinstance(user_update.role, str) else user_update.role
        user_to_update.role = new_role
        db.commit()
        db.refresh(user_to_update)
        return user_to_update
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating user role: {str(e)}")

async def request_password_reset(email: EmailStr, db: Session) -> None:
    user = db.exec(select(User).where(User.email == email)).first()
    if not user:
        return  # Silently return to avoid exposing user existence

    # Generate reset token
    reset_token = str(uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

    # Store reset token in the database
    password_reset_token = PasswordResetToken(
        user_id=user.id,
        token=reset_token,
        expires_at=expires_at
    )
    db.add(password_reset_token)
    db.commit()

    # Mock sending email (replace with actual email service in production)
    print(f"Password reset token for {email}: {reset_token}")
    # Example: send_email(to=email, subject="Password Reset", body=f"Reset your password: /reset-password?token={reset_token}")

async def reset_password(token: str, new_password: str, db: Session) -> None:
    reset_token = db.exec(select(PasswordResetToken).where(PasswordResetToken.token == token)).first()
    if not reset_token or reset_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    user = db.get(User, reset_token.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update user password
    user.password = get_password_hash(new_password)
    db.add(user)

    # Delete the used reset token
    db.delete(reset_token)
    db.commit()