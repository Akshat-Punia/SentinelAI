import re
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Alphanumeric username")
    email: str = Field(..., description="Valid email address")

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        if not re.match(pattern, v):
            raise ValueError("Invalid email address format")
        return v.lower()


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, description="Minimum 8 characters")
    role: Optional[str] = Field(default="Viewer", description="Admin, Security Analyst, or Viewer")


class UserLogin(BaseModel):
    username: str
    password: str


class UserUpdateRole(BaseModel):
    role: str = Field(..., description="New role: Admin, Security Analyst, or Viewer")


class UserResponse(UserBase):
    id: int
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True
