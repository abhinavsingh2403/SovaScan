"""Pydantic v2 request / response schemas for the SovaScan API."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


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

    model_config = {"from_attributes": True}


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


class ComplianceResponse(BaseModel):
    """Compliance check result against a specific framework."""

    framework: str
    score: float
    total_controls: int
    passed: int
    failed: int
    findings: list[FindingResponse]


class DashboardSummary(BaseModel):
    """Aggregated statistics for the dashboard."""

    total_scans: int = 0
    total_findings: int = 0
    severity_distribution: dict[str, int] = Field(default_factory=dict)
    recent_scans: list[ScanResponse] = Field(default_factory=list)
    top_vulnerabilities: list[FindingResponse] = Field(default_factory=list)
    risk_score: float = 0.0


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
    uptime: float
