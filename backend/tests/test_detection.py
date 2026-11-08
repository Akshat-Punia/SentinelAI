from datetime import datetime, timedelta
from app.schemas.security_event import SecurityEventCreate
from app.api.v1.events import ingest_event
from app.models.alert import Alert


def test_benign_event_no_alert(db_session):
    event_in = SecurityEventCreate(
        event_type="LOGIN_SUCCESS",
        source_ip="192.168.1.100",
        user_identifier="regular_user",
        location="London, UK",
        failed_attempts=0
    )
    res = ingest_event(event_in=event_in, db=db_session)
    assert res["threat_detected"] is False
    assert len(res["alerts"]) == 0


def test_brute_force_detection(db_session):
    event_in = SecurityEventCreate(
        event_type="LOGIN_FAILED",
        source_ip="203.0.113.88",
        user_identifier="target_user",
        location="Unknown",
        failed_attempts=6
    )
    res = ingest_event(event_in=event_in, db=db_session)
    assert res["threat_detected"] is True
    alert = res["alerts"][0]
    assert alert.rule_triggered == "RULE_BRUTE_FORCE_BURST"
    assert alert.severity in ["HIGH", "CRITICAL"]
    assert alert.risk_score >= 80.0


def test_credential_spraying_detection(db_session):
    ip = "198.51.100.99"
    # Target 3 different users from same IP
    ingest_event(SecurityEventCreate(event_type="LOGIN_FAILED", source_ip=ip, user_identifier="user1"), db=db_session)
    ingest_event(SecurityEventCreate(event_type="LOGIN_FAILED", source_ip=ip, user_identifier="user2"), db=db_session)
    res3 = ingest_event(SecurityEventCreate(event_type="LOGIN_FAILED", source_ip=ip, user_identifier="user3"), db=db_session)

    assert res3["threat_detected"] is True
    spray_alert = next((a for a in res3["alerts"] if a.rule_triggered == "RULE_IP_SPRAY_ATTACK"), None)
    assert spray_alert is not None
    assert spray_alert.severity == "CRITICAL"


def test_impossible_travel_detection(db_session):
    user = "globetrotter"
    t1 = datetime.utcnow()
    t2 = t1 + timedelta(minutes=10)

    # First login from New York
    ingest_event(SecurityEventCreate(event_type="LOGIN_SUCCESS", source_ip="1.1.1.1", user_identifier=user, location="New York, US", timestamp=t1), db=db_session)
    # Second login from Tokyo 10 minutes later
    res2 = ingest_event(SecurityEventCreate(event_type="LOGIN_SUCCESS", source_ip="2.2.2.2", user_identifier=user, location="Tokyo, JP", timestamp=t2), db=db_session)

    assert res2["threat_detected"] is True
    geo_alert = next((a for a in res2["alerts"] if a.rule_triggered == "RULE_IMPOSSIBLE_TRAVEL"), None)
    assert geo_alert is not None
    assert geo_alert.severity == "HIGH"
