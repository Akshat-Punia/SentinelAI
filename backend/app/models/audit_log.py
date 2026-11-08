from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from app.db.session import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    username = Column(String(50), nullable=True)
    action = Column(String(100), nullable=False)  # e.g., "LOGIN_SUCCESS", "ROLE_UPDATED", "USER_CREATED"
    resource = Column(String(100), nullable=False)  # e.g., "AUTH", "IAM", "DETECTION_ENGINE"
    ip_address = Column(String(45), nullable=True)
    status = Column(String(20), default="SUCCESS")  # "SUCCESS", "FAILURE", "DENIED"
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self):
        return f"<AuditLog {self.action} by {self.username} at {self.timestamp}>"
