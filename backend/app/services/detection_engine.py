from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.security_event import SecurityEvent
from app.models.alert import Alert


class ThreatDetectionEngine:
    """
    Real-Time Rule-Based Threat Detection Engine.
    Evaluates ingested security events and identifies malicious patterns.
    """

    @classmethod
    def evaluate_event(cls, db: Session, event: SecurityEvent) -> List[Alert]:
        """Runs all detection rules against the event and returns generated alerts."""
        generated_alerts: List[Alert] = []

        # Rule 1: Brute-Force / Credential Abuse
        brute_alert = cls._check_brute_force(db, event)
        if brute_alert:
            generated_alerts.append(brute_alert)

        # Rule 2: Multi-Account Credential Spraying
        spray_alert = cls._check_ip_spray(db, event)
        if spray_alert:
            generated_alerts.append(spray_alert)

        # Rule 3: Off-Hours Activity
        off_hours_alert = cls._check_off_hours(db, event)
        if off_hours_alert:
            generated_alerts.append(off_hours_alert)

        # Rule 4: Impossible Travel / Geographic Velocity Anomaly
        geo_alert = cls._check_impossible_travel(db, event)
        if geo_alert:
            generated_alerts.append(geo_alert)

        # Persist alerts to DB
        for alert in generated_alerts:
            alert.event_id = event.id
            db.add(alert)

        if generated_alerts:
            db.commit()
            for alert in generated_alerts:
                db.refresh(alert)

        return generated_alerts

    @staticmethod
    def _check_brute_force(db: Session, event: SecurityEvent) -> Optional[Alert]:
        """Detects high-frequency failed login bursts."""
        # Direct failed count on event
        if event.failed_attempts >= 10:
            return Alert(
                title=f"Critical Brute Force Attack ({event.user_identifier or event.source_ip})",
                severity="CRITICAL",
                status="NEW",
                risk_score=95.0,
                rule_triggered="RULE_BRUTE_FORCE_BURST",
                ai_explanation=f"Exceeded 10 failed authentication attempts for target '{event.user_identifier}' from IP {event.source_ip}.",
                recommended_action="Immediately enforce account lockout and block source IP on edge firewall."
            )
        elif event.failed_attempts >= 5:
            return Alert(
                title=f"Suspicious Repeated Failed Logins ({event.user_identifier or event.source_ip})",
                severity="HIGH",
                status="NEW",
                risk_score=85.0,
                rule_triggered="RULE_BRUTE_FORCE_BURST",
                ai_explanation=f"Observed {event.failed_attempts} consecutive failed logins from IP {event.source_ip}.",
                recommended_action="Prompt user with CAPTCHA and require MFA challenge on next attempt."
            )

        # Check rolling 5-minute historical failures
        five_mins_ago = event.timestamp - timedelta(minutes=5)
        query = db.query(SecurityEvent).filter(
            SecurityEvent.event_type.in_(["LOGIN_FAILED", "AUTHENTICATION_FAILED"]),
            SecurityEvent.timestamp >= five_mins_ago,
            SecurityEvent.id != event.id
        )

        if event.user_identifier:
            user_failures = query.filter(SecurityEvent.user_identifier == event.user_identifier).count()
            if user_failures >= 4:
                return Alert(
                    title=f"Brute Force Pattern on User: {event.user_identifier}",
                    severity="HIGH",
                    status="NEW",
                    risk_score=88.0,
                    rule_triggered="RULE_BRUTE_FORCE_WINDOW",
                    ai_explanation=f"User '{event.user_identifier}' has suffered {user_failures + 1} failed logins in the past 5 minutes.",
                    recommended_action="Notify user via out-of-band channel (SMS/Email) and review source IP telemetry."
                )

        return None

    @staticmethod
    def _check_ip_spray(db: Session, event: SecurityEvent) -> Optional[Alert]:
        """Detects single IP attempting authentication across multiple distinct user accounts."""
        ten_mins_ago = event.timestamp - timedelta(minutes=10)
        distinct_users = (
            db.query(SecurityEvent.user_identifier)
            .filter(
                SecurityEvent.source_ip == event.source_ip,
                SecurityEvent.timestamp >= ten_mins_ago,
                SecurityEvent.user_identifier.isnot(None)
            )
            .distinct()
            .count()
        )

        if distinct_users >= 3:
            return Alert(
                title=f"Credential Spray Attack from IP: {event.source_ip}",
                severity="CRITICAL",
                status="NEW",
                risk_score=92.0,
                rule_triggered="RULE_IP_SPRAY_ATTACK",
                ai_explanation=f"Source IP {event.source_ip} targeted {distinct_users} distinct user accounts within 10 minutes.",
                recommended_action=f"Blacklist IP {event.source_ip} at network perimeter and audit affected accounts for unauthorized access."
            )

        return None

    @staticmethod
    def _check_off_hours(db: Session, event: SecurityEvent) -> Optional[Alert]:
        """Detects privileged or successful login activity during anomalous off-hours (01:00 - 05:00 UTC)."""
        hour = event.timestamp.hour
        is_off_hour = 1 <= hour <= 4

        if is_off_hour and event.event_type in ["LOGIN_SUCCESS", "PRIVILEGE_ESCALATION"]:
            return Alert(
                title=f"Off-Hours Administrative Access: {event.user_identifier}",
                severity="MEDIUM",
                status="NEW",
                risk_score=60.0,
                rule_triggered="RULE_OFF_HOURS_ACTIVITY",
                ai_explanation=f"Authentication occurred at {event.timestamp.strftime('%H:%M:%S UTC')}, which is outside standard operational business hours.",
                recommended_action="Verify with employee whether after-hours access was planned; check associated session commands."
            )

        return None

    @staticmethod
    def _check_impossible_travel(db: Session, event: SecurityEvent) -> Optional[Alert]:
        """Detects impossible geographical travel velocity for a user within a short time window."""
        if not event.location or not event.user_identifier:
            return None

        two_hours_ago = event.timestamp - timedelta(hours=2)
        previous_event = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.user_identifier == event.user_identifier,
                SecurityEvent.location.isnot(None),
                SecurityEvent.location != "",
                SecurityEvent.id != event.id,
                SecurityEvent.timestamp >= two_hours_ago,
                SecurityEvent.timestamp <= event.timestamp
            )
            .order_by(SecurityEvent.timestamp.desc())
            .first()
        )

        if previous_event and previous_event.location.lower() != event.location.lower():
            return Alert(
                title=f"Impossible Travel Anomaly for {event.user_identifier}",
                severity="HIGH",
                status="NEW",
                risk_score=82.0,
                rule_triggered="RULE_IMPOSSIBLE_TRAVEL",
                ai_explanation=f"User active in '{event.location}' shortly after activity in '{previous_event.location}'. Physical transit within this time window is improbable.",
                recommended_action="Revoke active OAuth tokens, invalidate existing sessions, and prompt for identity verification."
            )

        return None
