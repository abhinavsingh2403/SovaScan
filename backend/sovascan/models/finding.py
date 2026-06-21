"""Finding SQLAlchemy model — a single security issue discovered during a scan."""

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from sovascan.models.base import Base


class Severity(str, enum.Enum):
    """Severity rating for a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(Base):
    """A single security finding produced by a scan.

    Attributes:
        id: Unique identifier (UUID).
        scan_id: Foreign key to the parent Scan.
        rule_id: Identifier of the detection rule (e.g. SOVA-CRYPTO-001).
        title: Short human-readable title.
        description: Detailed explanation of the issue.
        severity: Severity classification.
        category: Broad category (cve, misconfiguration, secret, config_drift).
        file_path: Path to the affected file.
        line_number: Line number in the file, if applicable.
        evidence: Raw evidence / code snippet.
        remediation: Suggested fix description.
        cve_id: Associated CVE identifier, if any.
        cvss_score: CVSS v3 score, if available.
        is_fixed: Whether this finding has been remediated.
        created_at: Row creation timestamp.
        scan: Relationship back to parent Scan.
    """

    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    rule_id = Column(String(64), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum(Severity), nullable=False, default=Severity.INFO)
    category = Column(String(64), nullable=False, default="misconfiguration")
    file_path = Column(String(1024), nullable=False, default="")
    line_number = Column(Integer, nullable=True)
    evidence = Column(Text, nullable=True, default="")
    remediation = Column(Text, nullable=True, default="")
    cve_id = Column(String(32), nullable=True)
    cvss_score = Column(Float, nullable=True)
    is_fixed = Column(Boolean, nullable=False, default=False)
    created_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Many-to-one relationship with Scan
    scan = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding id={self.id!r} rule={self.rule_id!r} severity={self.severity!r}>"
