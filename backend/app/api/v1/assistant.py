from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.schemas.assistant import AssistantChatRequest, AssistantChatResponse, AlertAnalysisResponse
from app.services.assistant_service import GenAIAssistantService
from app.api.deps import get_current_user

router = APIRouter(prefix="/assistant", tags=["GenAI Security Assistant"])


@router.post("/chat", response_model=AssistantChatResponse)
def chat_with_assistant(
    request_in: AssistantChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Conversational interface to Sentinel AI Copilot.
    Provides evidence-grounded threat explanation and remediation recommendations.
    """
    alert = None
    event = None
    if request_in.alert_id:
        alert = db.query(Alert).filter(Alert.id == request_in.alert_id).first()
        if alert and alert.event_id:
            event = db.query(SecurityEvent).filter(SecurityEvent.id == alert.event_id).first()

    return GenAIAssistantService.chat_response(
        message=request_in.message,
        alert=alert,
        event=event
    )


@router.get("/analyze/{alert_id}", response_model=AlertAnalysisResponse)
def analyze_specific_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generates a structured incident brief for an alert, including blast radius and MITRE ATT&CK alignment.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert #{alert_id} not found."
        )

    event = None
    if alert.event_id:
        event = db.query(SecurityEvent).filter(SecurityEvent.id == alert.event_id).first()

    return GenAIAssistantService.analyze_alert(alert=alert, event=event)

