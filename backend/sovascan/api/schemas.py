"""Pydantic v2 request / response schemas for the SovaScan API."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_serializer

# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Request body for creating a new scan."""

    target: str = Field(
        ...,
        description="File path or URL to scan",
        min_length=1,
        max_length=2048,
        examples=["/home/user/project", "https://github.com/org/repo"],
    )
    scan_type: str = Field(
        default="full",
        description="Type of scan to perform",
        examples=["full", "dependencies", "secrets", "misconfig"],
    )
    options: dict[str, Any] | None = Field(
        default=None,
        description="Optional key-value scan options",
    )


class FixRequest(BaseModel):
    """Request body for auto-fix generation."""

    finding_id: str = Field(
        ...,
        description="UUID of the finding to fix",
    )
    auto_apply: bool = Field(
        default=False,
        description="Whether to automatically apply the fix",
    )
    custom_replacement: str | None = Field(
        default=None,
        description="Optional custom code replacement text provided by the user via the sandbox editor",
    )
    context_replacement: str | None = Field(
        default=None,
        description="The full edited block of 10-15 lines of context from the frontend sandbox",
    )
    context_start_line: int | None = Field(
        default=None,
        description="The 1-based start line of the context block in the original file",
    )
    context_end_line: int | None = Field(
        default=None,
        description="The 1-based end line of the context block in the original file",
    )
    justification: str | None = Field(
        default=None,
        description="Optional justification reason for this remediation (Required for bank audits)",
    )


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class ScanResponse(BaseModel):
    """Response schema for a single scan."""

    id: str
    target: str
    status: str
    scan_type: str
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime | None = None

    @field_serializer("started_at", "completed_at", "created_at")
    def serialize_datetime(self, dt: datetime | None) -> str | None:
        if dt is None:
            return None
        tz_aware = dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        return tz_aware.isoformat().replace("+00:00", "Z")

    model_config = {"from_attributes": True}


class ScanCancelResponse(BaseModel):
    """Response schema for cancelling an in-progress scan."""

    scan_id: str
    status: str = "cancelled"
    message: str = "Scan cancellation request accepted."


class FindingResponse(BaseModel):
    """Response schema for a single finding."""

    id: str
    scan_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    category: str
    file_path: str = ""
    line_number: int | None = None
    evidence: str | None = None
    remediation: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    is_fixed: bool = False
    created_at: datetime | None = None

    @field_serializer("created_at")
    def serialize_datetime(self, dt: datetime | None) -> str | None:
        if dt is None:
            return None
        tz_aware = dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        return tz_aware.isoformat().replace("+00:00", "Z")

    model_config = {"from_attributes": True}


class FindingsListResponse(BaseModel):
    """Paginated list of findings."""

    findings: list[FindingResponse]
    total: int
    page: int
    per_page: int


class PackageInfo(BaseModel):
    """A single package entry in an SBOM."""

    name: str
    version: str
    ecosystem: str = "pypi"
    license: str | None = None
    purl: str | None = None


class SBOMResponse(BaseModel):
    """Software Bill of Materials response."""

    format: str = "cyclonedx"
    packages: list[PackageInfo]
    generated_at: datetime

    @field_serializer("generated_at")
    def serialize_datetime(self, dt: datetime) -> str:
        tz_aware = dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        return tz_aware.isoformat().replace("+00:00", "Z")


class ComplianceControlResponse(BaseModel):
    id: str
    name: str
    category: str
    status: str
    findings: list[str] = []
    description: str = ""


class ComplianceResponse(BaseModel):
    """Compliance check result against a specific framework."""

    framework: str
    score: float
    total_controls: int
    passed: int
    failed: int
    findings: list[FindingResponse]
    controls: list[ComplianceControlResponse] = []


class TrendDataPoint(BaseModel):
    """Historical security trend data point (findings aggregated by day)."""

    date: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class TopVulnerability(BaseModel):
    """Aggregated vulnerability metrics grouped by rule/title."""

    id: str
    title: str
    severity: str
    count: int
    category: str


class DashboardSummary(BaseModel):
    """Aggregated statistics for the dashboard."""

    total_scans: int = 0
    total_findings: int = 0
    severity_distribution: dict[str, int] = Field(default_factory=dict)
    recent_scans: list[ScanResponse] = Field(default_factory=list)
    top_vulnerabilities: list[TopVulnerability] = Field(default_factory=list)
    risk_score: float = 0.0
    trend_data: list[TrendDataPoint] = Field(default_factory=list)


class FixResponse(BaseModel):
    """Response for an auto-fix request."""

    finding_id: str
    status: str
    patch: str
    description: str


class HealthResponse(BaseModel):
    """Health-check response."""

    status: str
    version: str
    database: str
    scanners: dict[str, bool]
    uptime: float


class ScanProgressEvent(BaseModel):
    """WebSocket event schema for real-time scan progress streaming."""
    type: str = Field(..., description="Event type: status_change, progress, finding_discovered, scan_complete, scan_failed")
    scan_id: str
    phase: str = ""
    percent: float = 0.0
    findings_count: int = 0
    finding: FindingResponse | None = None
    status: str = ""
    error: str = ""
    timestamp: datetime | None = None

    @field_serializer("timestamp")
    def serialize_datetime(self, dt: datetime | None) -> str | None:
        if dt is None:
            return None
        tz_aware = dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        return tz_aware.isoformat().replace("+00:00", "Z")


class ThreatIntelRecordResponse(BaseModel):
    cve_id: str
    known_exploited: bool
    epss_score: float | None = None
    epss_percentile: float | None = None
    priority: str
    summary: str
    remediation_urgency: str
    sources: list[str] = Field(default_factory=list)


class ThreatIntelScanResponse(BaseModel):
    scan_id: str
    generated_at: datetime

    @field_serializer("generated_at")
    def serialize_datetime(self, dt: datetime) -> str:
        tz_aware = dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        return tz_aware.isoformat().replace("+00:00", "Z")
    total_cves: int
    known_exploited_count: int
    high_priority_count: int
    records: list[ThreatIntelRecordResponse]


class FindingContextResponse(BaseModel):
    """Response schema for file context around a finding."""

    finding_id: str
    file_path: str
    start_line: int
    end_line: int
    target_line: int
    lines: list[dict[str, str | int]]
