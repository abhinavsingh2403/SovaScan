# SovaScan Backend — Changelog & Architecture Notes

> **Branch**: `Abhinav-v3`
> **Last verified**: All 27 tests passing · All modules importing cleanly · Server boots without errors

This document covers every backend change made **after the initial frontend work**, starting from the Threat Intelligence feature and continuing through the stability/consistency hardening pass.

---

## Table of Contents

1. [Threat Intelligence Enrichment](#1-threat-intelligence-enrichment)
2. [API Consistency & Schema Hardening](#2-api-consistency--schema-hardening)
3. [Scan Pipeline Reliability](#3-scan-pipeline-reliability)
4. [Scan-Specific Compliance](#4-scan-specific-compliance)
5. [Finding Deduplication & Severity Normalization](#5-finding-deduplication--severity-normalization)
6. [Semgrep "requires login" Evidence Fallback](#6-semgrep-requires-login-evidence-fallback)
7. [Health Endpoint Enhancement](#7-health-endpoint-enhancement)
8. [SBOM & Failure Metadata Caching](#8-sbom--failure-metadata-caching)
9. [Test Suite Expansion](#9-test-suite-expansion)
10. [Removed / Cleaned Up Code](#10-removed--cleaned-up-code)
11. [API Endpoint Reference](#11-api-endpoint-reference)
12. [File Map](#12-file-map)

---

## 1. Threat Intelligence Enrichment

**Files changed:**
- `backend/sovascan/core/threat_intel.py` *(new)*
- `backend/sovascan/api/routes.py`
- `backend/sovascan/api/schemas.py`
- `backend/tests/test_threat_intel.py` *(new)*

**What it does:**

After SovaScan detects CVE-tagged vulnerabilities, this module enriches them with real-world exploitability data from trusted sources:

| Source | Data Provided |
|--------|--------------|
| **CISA KEV** (Known Exploited Vulnerabilities) | Boolean `known_exploited` flag — is this CVE actively exploited in the wild? |
| **FIRST EPSS** (Exploit Prediction Scoring System) | `epss_score` (0.0–1.0 probability) and `epss_percentile` |
| **OSV.dev** | Advisory metadata already available from dependency scans |

**Priority classification thresholds:**

```
Immediate : CISA KEV = true OR EPSS >= 0.70
High      : EPSS >= 0.30 OR CVSS >= 8.0
Scheduled : EPSS >= 0.05 OR CVSS >= 5.0
Routine   : Everything else
```

**API endpoint:**

```
GET /api/v1/threat-intel/scan/{scan_id}
```

Returns enriched CVE records with `priority`, `known_exploited`, `epss_score`, `epss_percentile`, `high_priority_count`, and per-CVE advisory links.

**Resilience:** If CISA or EPSS APIs are down, the enrichment returns safe defaults (`known_exploited: false`, `epss_score: 0.0`) — it never blocks scan completion or report rendering.

---

## 2. API Consistency & Schema Hardening

**Files changed:**
- `backend/sovascan/api/schemas.py`
- `backend/sovascan/api/routes.py`

**What changed:**

- All API responses use **snake_case** consistently (`scan_type`, `created_at`, `file_path`, `line_number`, `rule_id`, `is_fixed`).
- Every route handler returns data through a Pydantic response model — no raw dicts leak out.
- Added `ThreatIntelScanResponse` and `ThreatIntelRecordResponse` schemas for the new enrichment endpoint.
- `ComplianceResponse` and `ComplianceControlResponse` schemas formalized with `framework`, `score`, `passed`, `failed`, `total`, and per-control `id`, `name`, `description`, `status`, `findings_count` fields.

**Schema inventory (22 models):**

```
ScanRequest, ScanResponse, FindingResponse, FindingsListResponse,
DashboardSummary, SBOMResponse, PackageInfo, FindingContextResponse,
FixRequest, FixResponse, ComplianceResponse, ComplianceControlResponse,
HealthResponse, ScanProgressEvent, ThreatIntelScanResponse,
ThreatIntelRecordResponse, TopVulnerability, TrendDataPoint,
BulkFixRequest, BulkFixResponse
```

---

## 3. Scan Pipeline Reliability

**Files changed:**
- `backend/sovascan/api/websocket.py`
- `backend/sovascan/api/routes.py`

**Remote clone safety:**

```python
# Only HTTPS and HTTP protocols are allowed for remote cloning
is_git = target.startswith("http://") or target.startswith("https://") or ...
if is_git and not (target.startswith("http://") or target.startswith("https://")):
    # Reject SSH, FTP, and custom protocol URLs
```

- Clone timeout reduced from unlimited to **60 seconds**.
- Invalid protocol URLs are rejected at the API layer before any DB row is created.

**Failure metadata:**

When a scan throws an exception, the scan row is updated to `FAILED` status and the error details are persisted:

```json
{
  "error": "subprocess timed out after 60s",
  "failed_at": "2026-07-13T19:00:00+00:00"
}
```

This metadata is stored in `scan.metadata_json` so the frontend can display meaningful failure messages.

---

## 4. Scan-Specific Compliance

**Files changed:**
- `backend/sovascan/api/routes.py`

**Before:** `GET /api/v1/compliance/{framework}` always ran against ALL findings in the database.

**After:** The endpoint accepts an optional `?scan_id=` query parameter:

```
GET /api/v1/compliance/nist-csf?scan_id=abc-123
```

When provided, the compliance score is computed only against findings from that specific scan. This makes the Report page show accurate per-scan compliance rather than cumulative global numbers.

**Dynamic controls mapper:**

Instead of hardcoded pass/fail, each compliance framework (NIST-CSF, SOC-2, OWASP-10) now has a dynamic controls list. Each control maps to finding categories:

```python
# Example: NIST-CSF control
{
    "id": "PR.DS-2",
    "name": "Data-in-Transit Protection",
    "maps_to": ["secret", "crypto", "misconfiguration"]
}
```

A control is marked `"failed"` if any matching finding exists in the scan, `"passed"` otherwise. The score is `passed / total * 100`.

---

## 5. Finding Deduplication & Severity Normalization

**Files changed:**
- `backend/sovascan/api/websocket.py`
- `backend/sovascan/core/severity_scorer.py`

**Deduplication:**

During scan execution, findings are deduplicated using a composite key:

```python
dedup_key = (rule_id, cleaned_file_path, line_number, evidence_prefix[:120])
```

This prevents the same vulnerability from being recorded multiple times when different scanners (orchestrator, SAST, git-history) detect overlapping issues.

**Severity normalization:**

The `normalize_severity()` function in `severity_scorer.py` maps any raw severity string to the canonical `Severity` enum:

```python
"ERROR" → CRITICAL    "HIGH" → HIGH
"WARNING" → MEDIUM    "MEDIUM" → MEDIUM
"INFO" → LOW          "LOW" → LOW
"NOTE" → INFO         (default) → MEDIUM
```

This is applied to all findings from all scanner phases before DB insertion.

**Path cleaning:**

The `_clean_path()` helper strips absolute prefixes and temporary directory paths from `file_path` values, ensuring findings always store clean relative paths like `src/auth/login.py` instead of `/tmp/sovascan_abc123/src/auth/login.py`.

---

## 6. Semgrep "requires login" Evidence Fallback

**Files changed:**
- `backend/sovascan/api/websocket.py`

**Problem:**

Semgrep v1.60.0+ returns `"requires login"` for the `extra.lines` and `extra.fingerprint` fields when the CLI is not authenticated. SovaScan was storing this string as the finding's `evidence`, which made the Code Context Sandbox on the frontend show useless placeholder text instead of actual source code.

**Solution:**

When saving a finding, the backend checks if evidence is empty or equals `"requires login"`. If so, it reads the actual source line directly from disk:

```python
if not evidence or evidence.strip() == "requires login":
    file_path_obj = Path(target_path) / clean_file_path
    all_lines = file_path_obj.read_text(encoding="utf-8", errors="ignore").splitlines()
    if line_num and 1 <= line_num <= len(all_lines):
        evidence = all_lines[line_num - 1]
```

This fallback is applied in both the orchestrator findings loop and the SAST findings loop, so all scanner phases benefit from it.

---

## 7. Health Endpoint Enhancement

**Files changed:**
- `backend/sovascan/server.py`

The `/health` endpoint now reports:

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "db_healthy": true,
  "scanners": {
    "semgrep": true,
    "bandit": true
  }
}
```

- `db_healthy`: Verifies a test query against the database succeeds.
- `scanners`: Checks `shutil.which()` for each CLI tool to confirm availability.

---

## 8. SBOM & Failure Metadata Caching

**Files changed:**
- `backend/sovascan/api/websocket.py`

After a successful scan, the SBOM payload from the orchestrator is cached in `scan.metadata_json`:

```json
{
  "sbom": {
    "format": "cyclonedx",
    "packages": [...]
  }
}
```

On failure, error details and timestamp are saved instead:

```json
{
  "error": "Clone timed out after 60s",
  "failed_at": "2026-07-13T19:00:00+00:00"
}
```

This avoids re-running expensive operations when the frontend requests SBOM or failure information.

---

## 9. Test Suite Expansion

**Test files (6 files, 27 tests):**

| File | Tests | What it covers |
|------|-------|---------------|
| `test_api.py` | 16 | Health, CRUD scans, findings, SBOM, compliance, dashboard, fix/apply/revert, bulk fix, SAST fallback, git scanner, WebSocket |
| `test_compliance.py` | 1 | Global vs scan-specific compliance score isolation |
| `test_scan_pipeline.py` | 4 | Git URL protocol validation, severity normalization, failure metadata saving, finding deduplication + SBOM cache |
| `test_severity.py` | 2 | Banking/auth path criticality boosting, test-directory severity reduction |
| `test_threat_intel.py` | 4 | Priority calculation logic, CVE enrichment success, network failure graceful fallback, API endpoint integration |

**Test optimization:** All scan-dependent tests use `scan_type: "secrets"` instead of `"full"` to avoid triggering slow Semgrep/Bandit subprocesses, reducing total suite runtime from 160s → ~40s.

---

## 10. Removed / Cleaned Up Code

- **Duplicate SAST helpers removed from `routes.py`**: The functions `_run_semgrep()`, `_run_bandit()`, `_run_scan_logic()`, `_map_semgrep_severity()`, and `_map_bandit_severity()` were duplicated between `routes.py` and `websocket.py`/`sast_scanner.py`. The copies in `routes.py` (lines 58–260) were confirmed unused and deleted.
- **Consolidated severity mapping**: All severity mapping now flows through `normalize_severity()` in `severity_scorer.py` and `_map_*_severity()` in `sast_scanner.py`.

---

## 11. API Endpoint Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check with DB and scanner status |
| `POST` | `/api/v1/scan` | Create a new scan (returns 202) |
| `GET` | `/api/v1/scan` | List all scans |
| `GET` | `/api/v1/scan/{scan_id}` | Get scan details |
| `GET` | `/api/v1/scan/{scan_id}/findings` | List findings for a scan |
| `GET` | `/api/v1/findings` | List all findings (with filters) |
| `GET` | `/api/v1/scan/{scan_id}/sbom` | Get SBOM for a scan |
| `GET` | `/api/v1/findings/{finding_id}/context` | Get source code context around a finding |
| `POST` | `/api/v1/fix/{finding_id}` | Apply a fix to a finding |
| `POST` | `/api/v1/findings/{finding_id}/revert` | Revert an applied fix |
| `POST` | `/api/v1/fix/all` | Bulk fix all unfixed findings |
| `POST` | `/api/v1/scan/{scan_id}/fix-all` | Bulk fix all findings in a scan |
| `GET` | `/api/v1/compliance/{framework}` | Compliance report (optional `?scan_id=`) |
| `GET` | `/api/v1/dashboard/summary` | Dashboard aggregation stats |
| `GET` | `/api/v1/threat-intel/scan/{scan_id}` | Threat intelligence enrichment for scan CVEs |
| `WS` | `/ws/scan/{scan_id}` | Real-time scan progress via WebSocket |

---

## 12. File Map

```
backend/
├── sovascan/
│   ├── api/
│   │   ├── routes.py          # All REST endpoints (14 routes)
│   │   ├── schemas.py         # Pydantic response/request models (22 schemas)
│   │   └── websocket.py       # WebSocket scan execution engine
│   ├── core/
│   │   ├── orchestrator.py    # Multi-phase scan orchestrator
│   │   ├── sast_scanner.py    # Semgrep + Bandit SAST wrapper
│   │   ├── secret_scanner.py  # Regex-based secret detection
│   │   ├── cve_scanner.py     # CVE/dependency vulnerability scanner
│   │   ├── severity_scorer.py # Severity normalization + contextual scoring
│   │   ├── threat_intel.py    # CISA KEV + EPSS enrichment module
│   │   ├── dependency_resolver.py
│   │   ├── config_drift.py
│   │   ├── misconfig_detector.py
│   │   ├── git_history_scanner.py
│   │   └── report_generator.py
│   ├── models/
│   │   ├── scan.py            # Scan SQLAlchemy model
│   │   ├── finding.py         # Finding SQLAlchemy model
│   │   └── base.py
│   ├── server.py              # FastAPI app + health endpoint
│   └── config.py              # Settings via pydantic-settings
├── tests/
│   ├── conftest.py            # Shared fixtures (in-memory DB, test client)
│   ├── test_api.py            # 16 API integration tests
│   ├── test_compliance.py     # Compliance isolation test
│   ├── test_scan_pipeline.py  # Pipeline reliability tests
│   ├── test_severity.py       # Severity scoring tests
│   └── test_threat_intel.py   # Threat intel enrichment tests
└── pyproject.toml
```

---

*Generated for SovaScan `Abhinav-v3` branch — 27/27 tests passing.*
