from datetime import timedelta
from typing import Annotated
from fastapi import Cookie, FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlmodel import select
import auth
from auth.auth import check_admin, create_access_token, delete_user, request_password_reset, reset_password, signup_user, update_user, user_login, verify_token, revoke_refresh_token,get_current_user
from db_connect.db import get_session
from db_connect.settings import ACCESS_TOKEN_EXPIRE_MINUTES
from models.user_model import (
    LoginResponse,
    PasswordReset,
    PasswordResetRequest,
    Token, 
    TokenData, 
    User, 
    UserCreate,
    UserLogin, 
    UserResponse, 
    UserUpdate,
    UserRole,
    AdminUserUpdate
)


from asyncio.log import logger
from typing import Annotated, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from auth.auth import oauth2_scheme


# from db import get_session
# from schemas.class_names_model import ClassNames, ClassNamesCreate, ClassNamesResponse
# from user.user_crud import check_admin, check_authenticated_user
# from user.user_models import User

user_router = APIRouter(
    prefix="/user",
    tags=["User"],
    responses={404: {"Description": "Not found"}}
)



@user_router.post("/signup", response_model=UserResponse, tags=["User"])
async def signup(
    user: UserCreate,
    db: Session = Depends(get_session)
):
    try:
        new_user = await signup_user(user, db)
        return UserResponse(
            username=new_user.username,
            email=new_user.email,
            role=new_user.role,
            id=new_user.id
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Signup failed: {str(e)}"
        )

# 1️⃣ Swagger UI Login (OAuth2PasswordRequestForm expects form-data)
@user_router.post("/login-swagger", response_model=LoginResponse, tags=["User"])
async def login_for_swagger(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_session)
):
    return user_login(db, form_data)

@user_router.post("/frontend/login", response_model=LoginResponse, tags=["User"])
async def login_for_frontend(
    login_data: UserLogin,
    db: Session = Depends(get_session)
):
    try:
        return user_login(db, login_data)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

# 4️⃣ Get current user
@user_router.get("/users/me", response_model=User, tags=["User"])
async def read_users_me(token: Annotated[str, Depends(oauth2_scheme)], db: Annotated[Session, Depends(get_session)]) -> User:
    user = await get_current_user(token, db)
    return user


@user_router.post("/logout", tags=["User"])
async def logout(
    refresh_token: str = Cookie(None),  # Refresh token from HTTP-only cookie
    db: Session = Depends(get_session)
):
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No refresh token provided"
        )
    
    try:
        revoke_refresh_token(db, refresh_token)
        return {"message": "User logged out successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error during logout: {str(e)}"
        )

@user_router.patch("/admins-update-user/{username}", response_model=dict, tags=["User"])
def update_user_role(
    username: str,
    user: AdminUserUpdate,
    session: Session = Depends(get_session),
    current_user: User = Depends(check_admin)
):
    db_user = session.exec(select(User).where(User.username == username)).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    user_dict_data = user.model_dump(exclude_unset=True)
    updated_fields = []
    for key, value in user_dict_data.items():
        setattr(db_user, key, value)
        updated_fields.append(key)

    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    user_response = {
        "id": db_user.id,
        "username": db_user.username,
        "email": db_user.email,
        "role": db_user.role,
        "designation": db_user.designation,
        "created_at": db_user.created_at,
        "updated_at": db_user.updated_at,
    }

    return {
        "message": f"Updated fields: {', '.join(updated_fields)}",
        "user": user_response
    }

@user_router.patch("/update-profile", response_model=dict, tags=["User"])
def update_profile(
    user_update: UserUpdate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
):
    db_user = session.exec(select(User).where(User.id == current_user.id)).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = user_update.model_dump(exclude_unset=True)
    updated_fields = []
    for key, value in update_data.items():
        if key == "password" and value:
            from auth.auth import get_password_hash
            value = get_password_hash(value)
        setattr(db_user, key, value)
        updated_fields.append(key)

    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    # Prepare UserResponse
    user_response = {
        "id": db_user.id,
        "username": db_user.username,
        "email": db_user.email,
        "role": db_user.role,
        "designation": db_user.designation,
        "created_at": db_user.created_at,
        "updated_at": db_user.updated_at,
    }

    return {
        "message": f"Updated fields: {', '.join(updated_fields)}",
        "user": user_response
    }

#_________________________________________________________________________________


@user_router.get("/users", response_model=list[User], tags=["User"])
def read_users(db: Annotated[Session, Depends(get_session)], user: Annotated[User, Depends(check_admin)]) -> list[User]:
    return db.exec(select(User)).all()

@user_router.delete("/delete-user/{username}", response_model=User, tags=["User"])
def user_delete(session: Annotated[Session, Depends(get_session)], username: str, user: Annotated[User, Depends(check_admin)]):
    deleted_user = delete_user(session, username)
    return deleted_user



@user_router.post("/forgot-password", response_model=dict, tags=["User"])
async def forgot_password(
    reset_request: PasswordResetRequest,
    db: Session = Depends(get_session)
):
    try:
        await request_password_reset(reset_request.email, db)
        return {"message": "Password reset email sent successfully"}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Password reset request failed: {str(e)}"
        )

@user_router.post("/reset-password", response_model=dict, tags=["User"])
async def reset_password_endpoint(
    reset_data: PasswordReset,
    db: Session = Depends(get_session)
):
    try:
        await reset_password(reset_data.token, reset_data.new_password, db)
        return {"message": "Password reset successfully"}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Password reset failed: {str(e)}"
        )