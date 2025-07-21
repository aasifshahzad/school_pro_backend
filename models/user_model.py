from sqlmodel import DateTime, SQLModel, Field, Enum, Column
from typing import Optional
from datetime import timedelta, datetime
from sqlalchemy.sql import func
import enum

class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    TEACHER = "TEACHER"
    STUDENT = "STUDENT"
    PARENT = "PARENT"
    ACCOUNTANT = "ACCOUNTANT"
    USER = "USER"

class UserDesignation(str, enum.Enum):
    PRINCIPAL = "PRINCIPAL"
    CLASS_TEACHER = "CLASS_TEACHER"
    CLASS_MONITOR = "CLASS_MONITOR"
    SENIOR_ADMIN = "SENIOR_ADMIN"
    JUNIOR_ADMIN = "JUNIOR_ADMIN"
    SENIOR_ACCOUNTANT = "SENIOR_ACCOUNTANT"
    JUNIOR_ACCOUNTANT = "JUNIOR_ACCOUNTANT"


class Token(SQLModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class TokenData(SQLModel):
    username: str
    exp: Optional[int] = None

class UserBase(SQLModel):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: Optional[datetime] = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, default=func.now()))
    updated_at: Optional[datetime] = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime, default=func.now(), onupdate=func.now()))

class User(UserBase,table=True):
    username: str = Field(nullable=False)
    email: str = Field(index=True, unique=True, nullable=False)
    password: str = Field(nullable=False)
    role: UserRole = Field(default=UserRole.USER)
    designation: Optional[UserDesignation] = Field(default = None)

class UserLogin(SQLModel):
    username: str
    password: str


class UserUpdate(SQLModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None

class AdminUserUpdate(SQLModel):
    role: UserRole = Field(description="Must be one of: ADMIN, TEACHER, STUDENT, PARENT, ACCOUNTANT, USER")
    designation: UserDesignation = Field(description="Must be one of: PRINCIPAL, CLASS_TEACHER, CLASS_MONITOR, etc.")

class UserCreate(SQLModel):
    username: str
    email: str
    password: str
    role: UserRole = UserRole.USER

class UserResponse(UserBase):
    username: str
    email: str
    role: UserRole
    designation: Optional[UserDesignation] = None


class LoginResponse(SQLModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse

class RefreshToken(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, nullable=False)
    token: str = Field(nullable=False, unique=True)
    expires_at: datetime = Field(nullable=False)


class PasswordResetToken(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, nullable=False)
    token: str = Field(nullable=False, unique=True)
    expires_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )

class PasswordResetRequest(SQLModel):
    email: str

class PasswordReset(SQLModel):
    token: str
    new_password: str