from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, ForeignKey
from app.db.session import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("security_events.id"), nullable=True, index=True)
    title = Column(String(150), nullable=False)
    severity = Column(String(20), nullable=False, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(20), nullable=False, default="NEW")  # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    risk_score = Column(Float, default=0.0)  # 0.0 - 100.0
    rule_triggered = Column(String(100), nullable=False)
    ai_explanation = Column(Text, nullable=True)
    recommended_action = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<Alert [{self.severity}] {self.title} (Score: {self.risk_score})>"
