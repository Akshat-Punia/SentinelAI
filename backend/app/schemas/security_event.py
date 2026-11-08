from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from app.schemas.alert import AlertResponse


class SecurityEventBase(BaseModel):
    event_type: str = Field(..., description="e.g. LOGIN_FAILED, LOGIN_SUCCESS, PRIVILEGE_ESCALATION, SUSPICIOUS_REQUEST")
    source_ip: str = Field(..., description="IPv4 or IPv6 client address")
    user_identifier: Optional[str] = Field(default=None, description="Username or email involved")
    location: Optional[str] = Field(default=None, description="Geographic location e.g. London, UK")
    device_info: Optional[str] = Field(default=None, description="Browser / OS user-agent")
    failed_attempts: int = Field(default=0, ge=0, description="Consecutive failure count")
    raw_payload: Optional[str] = Field(default=None, description="Raw JSON or log telemetry")


class SecurityEventCreate(SecurityEventBase):
    timestamp: Optional[datetime] = None


class SecurityEventResponse(SecurityEventBase):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True


class EventIngestResponse(BaseModel):
    message: str
    event: SecurityEventResponse
    threat_detected: bool
    alerts: List[AlertResponse]

