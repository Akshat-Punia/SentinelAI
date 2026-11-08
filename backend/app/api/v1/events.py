from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.security_event import SecurityEvent
from app.models.user import User, UserRole
from app.schemas.security_event import SecurityEventCreate, SecurityEventResponse, EventIngestResponse
from app.services.detection_engine import ThreatDetectionEngine
from app.api.deps import require_roles, get_current_user

router = APIRouter(prefix="/events", tags=["Security Events & Telemetry"])


@router.post("/ingest", response_model=EventIngestResponse, status_code=status.HTTP_201_CREATED)
def ingest_event(
    event_in: SecurityEventCreate,
    db: Session = Depends(get_db)
):
    """
    High-throughput security log ingestion endpoint.
    Saves the event and immediately evaluates it through the real-time Threat Detection Engine.
    """
    event_time = event_in.timestamp or datetime.utcnow()
    event = SecurityEvent(
        event_type=event_in.event_type,
        source_ip=event_in.source_ip,
        user_identifier=event_in.user_identifier,
        location=event_in.location,
        device_info=event_in.device_info,
        failed_attempts=event_in.failed_attempts,
        raw_payload=event_in.raw_payload,
        timestamp=event_time
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    # Evaluate event through threat detection engine
    generated_alerts = ThreatDetectionEngine.evaluate_event(db=db, event=event)
    threat_detected = len(generated_alerts) > 0

    message = (
        f"Event ingested successfully. Triggered {len(generated_alerts)} threat alert(s)!"
        if threat_detected
        else "Event ingested successfully. No immediate threats detected."
    )

    return {
        "message": message,
        "event": event,
        "threat_detected": threat_detected,
        "alerts": generated_alerts
    }


@router.get("", response_model=List[SecurityEventResponse])
def list_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    user_identifier: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve chronological security events with optional filtering."""
    query = db.query(SecurityEvent)

    if event_type and isinstance(event_type, str):
        query = query.filter(SecurityEvent.event_type == event_type)
    if source_ip and isinstance(source_ip, str):
        query = query.filter(SecurityEvent.source_ip == source_ip)
    if user_identifier and isinstance(user_identifier, str):
        query = query.filter(SecurityEvent.user_identifier == user_identifier)

    offset_val = skip if isinstance(skip, int) else 0
    limit_val = limit if isinstance(limit, int) else 50
    return query.order_by(SecurityEvent.timestamp.desc()).offset(offset_val).limit(limit_val).all()


@router.get("/{event_id}", response_model=SecurityEventResponse)
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve details of a single security event."""
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event with ID {event_id} was not found"
        )
    return event
