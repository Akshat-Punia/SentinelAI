from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    username: Optional[str] = None
    action: str
    resource: str
    ip_address: Optional[str] = None
    status: str
    details: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True
