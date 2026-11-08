from typing import List, Optional, Dict
from pydantic import BaseModel, Field


class AssistantChatRequest(BaseModel):
    message: str = Field(..., description="User query or question to the security assistant")
    alert_id: Optional[int] = Field(default=None, description="Optional alert ID to ground analysis in evidence")
    context: Optional[str] = Field(default=None, description="Optional additional log context")


class AssistantChatResponse(BaseModel):
    reply: str
    alert_id: Optional[int] = None
    evidence_grounding: List[str]
    mitre_attack_tactics: List[str]
    recommended_actions: List[str]
    model_provider: str


class AlertAnalysisResponse(BaseModel):
    alert_id: int
    title: str
    severity: str
    risk_score: float
    executive_summary: str
    technical_root_cause: str
    blast_radius: str
    mitre_reference: str
    defensive_runbook: List[str]

