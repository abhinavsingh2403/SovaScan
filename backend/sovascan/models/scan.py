"""Scan SQLAlchemy model — tracks a single security scan execution."""

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Enum, Integer, String, Text
from sqlalchemy.orm import relationship

from sovascan.models.base import Base


class ScanStatus(str, enum.Enum):
    """Possible lifecycle states for a Scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Scan(Base):
    """Represents a single security scan execution.

    Attributes:
        id: Unique identifier (UUID).
        target: The file path or URL that was scanned.
        status: Current lifecycle state.
        scan_type: The kind of scan (full, dependencies, secrets, misconfig).
        total_findings: Aggregate count of findings produced.
        critical_count: Number of critical-severity findings.
        high_count: Number of high-severity findings.
        medium_count: Number of medium-severity findings.
        low_count: Number of low-severity findings.
        started_at: When the scan execution began.
        completed_at: When the scan execution finished.
        created_at: Row creation timestamp.
        metadata_json: Free-form JSON string for extra context.
        findings: Relationship to child Finding rows.
    """

    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String(1024), nullable=False, index=True)
    status = Column(
        Enum(ScanStatus),
        nullable=False,
        default=ScanStatus.PENDING,
    )
    scan_type = Column(String(64), nullable=False, default="full")
    total_findings = Column(Integer, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    metadata_json = Column(Text, nullable=True)

    # One-to-many relationship with Finding
    findings = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id!r} target={self.target!r} status={self.status!r}>"
