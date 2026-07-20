import datetime
from sqlalchemy import Column, String, DateTime, Boolean
from sovascan.models.base import Base

class ApiKey(Base):
    """SQLAlchemy model representing API Keys used for authentication."""
    __tablename__ = "api_keys"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    key_hash = Column(String, nullable=False, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_used = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
