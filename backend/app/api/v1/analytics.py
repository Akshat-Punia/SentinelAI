from datetime import datetime
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.session import get_db
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.services.report_generator import SecurityReportGenerator
from app.api.deps import get_current_user

router = APIRouter(prefix="/analytics", tags=["Analytics & Executive Reporting"])


@router.get("/overview")
def get_analytics_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Provides high-level intelligence metrics for SOC overview dashboards."""
    total_events = db.query(SecurityEvent).count()
    failed_logins = db.query(SecurityEvent).filter(SecurityEvent.event_type.in_(["LOGIN_FAILED", "AUTHENTICATION_FAILED"])).count()
    total_alerts = db.query(Alert).count()
    resolved_alerts = db.query(Alert).filter(Alert.status == "RESOLVED").count()

    avg_risk = db.query(func.avg(Alert.risk_score)).scalar() or 0.0

    return {
        "total_events_ingested": total_events,
        "failed_logins": failed_logins,
        "total_alerts": total_alerts,
        "resolved_alerts": resolved_alerts,
        "resolution_rate_percent": round((resolved_alerts / total_alerts * 100), 1) if total_alerts > 0 else 100.0,
        "average_alert_risk_score": round(float(avg_risk), 1)
    }


@router.get("/threat-distribution")
def get_threat_distribution(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Categorizes threats by detection rule and severity for visualization charts."""
    rules_breakdown = (
        db.query(Alert.rule_triggered, func.count(Alert.id))
        .group_by(Alert.rule_triggered)
        .all()
    )

    severity_breakdown = (
        db.query(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
        .all()
    )

    return {
        "by_rule": [{"rule": r[0], "count": r[1]} for r in rules_breakdown],
        "by_severity": [{"severity": s[0], "count": s[1]} for s in severity_breakdown]
    }


@router.get("/reports/pdf")
def download_executive_pdf_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generates and downloads an executive PDF compliance and incident report."""
    total_alerts = db.query(Alert).count()
    open_count = db.query(Alert).filter(Alert.status == "NEW").count()
    resolved_count = db.query(Alert).filter(Alert.status == "RESOLVED").count()
    critical_count = db.query(Alert).filter(Alert.severity == "CRITICAL").count()
    high_count = db.query(Alert).filter(Alert.severity == "HIGH").count()

    stats = {
        "total_alerts": total_alerts,
        "open_alerts": open_count,
        "resolved_alerts": resolved_count,
        "critical_alerts": critical_count,
        "high_alerts": high_count
    }

    recent_alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(15).all()
    total_events = db.query(SecurityEvent).count()

    pdf_bytes = SecurityReportGenerator.generate_pdf_report(
        stats=stats,
        alerts=recent_alerts,
        events_count=total_events
    )

    filename = f"Sentinel_AI_Security_Report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

