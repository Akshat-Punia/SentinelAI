from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class AlertBase(BaseModel):
    title: str
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW")
    status: str = Field(default="NEW", description="NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE")
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    rule_triggered: str
    ai_explanation: Optional[str] = None
    recommended_action: Optional[str] = None


class AlertResponse(AlertBase):
    id: int
    event_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AlertUpdateStatus(BaseModel):
    status: str = Field(..., description="NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE")
    comment: Optional[str] = Field(default=None, description="Triage notes or mitigation details")


class AlertStats(BaseModel):
    total_alerts: int
    open_alerts: int
    investigating_alerts: int
    resolved_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
