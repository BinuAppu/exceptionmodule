from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=256)


class BreakGlassRecoveryRequest(BaseModel):
    username: str = Field(min_length=3, max_length=320)
    recovery_code: str = Field(min_length=10, max_length=200)
    new_password: str = Field(min_length=14, max_length=256)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=14, max_length=256)


class UserSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    public_id: str
    display_name: str
    email: str
    department: str | None
    job_title: str | None
    must_change_password: bool = False
    is_break_glass: bool = False


class SessionResponse(BaseModel):
    user: UserSummary
    roles: list[str]
    permissions: list[str]
    csrf_token: str
    idle_expires_at: datetime
    absolute_expires_at: datetime


class LogoutResponse(BaseModel):
    message: str = "Signed out"
