from app.models.alert import Alert
from app.services.assistant_service import GenAIAssistantService
from app.services.report_generator import SecurityReportGenerator


def test_copilot_mitre_mapping():
    alert = Alert(
        id=1,
        title="Brute Force Burst",
        severity="HIGH",
        risk_score=85.0,
        rule_triggered="RULE_BRUTE_FORCE_BURST",
        ai_explanation="Multiple failed logins observed."
    )
    analysis = GenAIAssistantService.analyze_alert(alert=alert, event=None)
    assert "T1110" in analysis["mitre_reference"]
    assert len(analysis["defensive_runbook"]) >= 2
    assert "blast_radius" in analysis


def test_pdf_report_binary_generation():
    stats = {
        "total_alerts": 5,
        "open_alerts": 2,
        "critical_alerts": 1,
        "high_alerts": 1,
        "resolved_alerts": 3
    }
    alerts = [
        Alert(id=1, title="Test Incident", severity="HIGH", risk_score=75.0, rule_triggered="TEST_RULE", status="NEW")
    ]
    pdf = SecurityReportGenerator.generate_pdf_report(stats=stats, alerts=alerts, events_count=42)
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-1.4")
    assert len(pdf) > 500
