import datetime
import uuid

from sqlalchemy import Column, DateTime, String

from sovascan.models.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    action = Column(String(255), nullable=False)
    operator = Column(String(100), nullable=False)  # Key name or System
    target = Column(String(255), nullable=True)
    justification = Column(String(500), nullable=True)
    status = Column(String(50), default="success")  # success | warning | error
