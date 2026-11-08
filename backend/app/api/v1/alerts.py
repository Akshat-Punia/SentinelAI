from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.models.user import User, UserRole
from app.schemas.alert import AlertResponse, AlertUpdateStatus, AlertStats
from app.api.deps import require_roles, get_current_user, record_audit_log

router = APIRouter(prefix="/alerts", tags=["Alerts & Threat Intelligence"])


@router.get("/stats", response_model=AlertStats)
def get_alert_statistics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Provides high-level alert summary metrics for SOC operations & dashboards."""
    total = db.query(Alert).count()
    open_count = db.query(Alert).filter(Alert.status == "NEW").count()
    investigating = db.query(Alert).filter(Alert.status == "INVESTIGATING").count()
    resolved = db.query(Alert).filter(Alert.status == "RESOLVED").count()

    critical = db.query(Alert).filter(Alert.severity == "CRITICAL").count()
    high = db.query(Alert).filter(Alert.severity == "HIGH").count()
    medium = db.query(Alert).filter(Alert.severity == "MEDIUM").count()
    low = db.query(Alert).filter(Alert.severity == "LOW").count()

    return {
        "total_alerts": total,
        "open_alerts": open_count,
        "investigating_alerts": investigating,
        "resolved_alerts": resolved,
        "critical_alerts": critical,
        "high_alerts": high,
        "medium_alerts": medium,
        "low_alerts": low
    }


@router.get("", response_model=List[AlertResponse])
def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    min_risk_score: Optional[float] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve security alerts filtered by severity, status, or minimum risk score."""
    query = db.query(Alert)

    if severity and isinstance(severity, str):
        query = query.filter(Alert.severity == severity.upper())
    if status_filter and isinstance(status_filter, str):
        query = query.filter(Alert.status == status_filter.upper())
    if min_risk_score is not None and isinstance(min_risk_score, (int, float)):
        query = query.filter(Alert.risk_score >= min_risk_score)

    offset_val = skip if isinstance(skip, int) else 0
    limit_val = limit if isinstance(limit, int) else 50
    return query.order_by(Alert.created_at.desc()).offset(offset_val).limit(limit_val).all()


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve detailed investigation information for a specific threat alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert with ID {alert_id} was not found"
        )
    return alert


@router.patch("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(
    alert_id: int,
    status_in: AlertUpdateStatus,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value]))
):
    """
    Security Analyst or Admin triage endpoint.
    Updates the operational status of an incident (NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE).
    """
    valid_statuses = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    new_status = status_in.status.upper()
    if new_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid alert status. Permitted values: {valid_statuses}"
        )

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert with ID {alert_id} was not found"
        )

    old_status = alert.status
    alert.status = new_status
    alert.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)

    client_ip = request.client.host if request.client else "unknown"
    record_audit_log(
        db=db,
        action="ALERT_STATUS_UPDATED",
        resource="DETECTION_ENGINE",
        user_id=current_user.id,
        username=current_user.username,
        ip_address=client_ip,
        details=f"Analyst {current_user.username} updated Alert #{alert.id} status from '{old_status}' to '{new_status}'. Comment: {status_in.comment or 'None'}"
    )

    return alert
