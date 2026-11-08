from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime
from app.db.session import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)  # "FAILED_LOGIN", "SUSPICIOUS_IP", "PRIVILEGE_ESCALATION"
    source_ip = Column(String(45), nullable=False, index=True)
    user_identifier = Column(String(100), nullable=True, index=True)
    location = Column(String(100), nullable=True)  # e.g., "Moscow, Russia"
    device_info = Column(String(255), nullable=True)  # e.g., "Mozilla/5.0..."
    failed_attempts = Column(Integer, default=0)
    raw_payload = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self):
        return f"<SecurityEvent {self.event_type} from {self.source_ip}>"
