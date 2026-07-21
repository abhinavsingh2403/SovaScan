"""WebSocket endpoint and async scan manager for real-time scan streaming.

Provides:
- ScanManager: singleton that runs scans in background threads and
  broadcasts progress events to connected WebSocket clients.
- scan_websocket: FastAPI WebSocket route handler.
"""

from __future__ import annotations

import asyncio
import json
import logging
import hashlib
import uuid
import httpx
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel
from sovascan.models.api_key import ApiKey
from sovascan.config import get_settings

from sovascan.core.git_history_scanner import GitHistoryScanner
from sovascan.core.orchestrator import ScanOrchestrator
from sovascan.core.sast_scanner import SASTScanner
from sovascan.core.severity_scorer import normalize_severity
from sovascan.models.base import SessionLocal
from sovascan.models.finding import Finding as FindingModel
from sovascan.models.finding import Severity
from sovascan.models.scan import Scan, ScanStatus

logger = logging.getLogger("sovascan.ws")

# Global SessionMaker alias to support override in test environment
SessionMaker = SessionLocal


def _clean_path(path_str: str, base_path: Path) -> str:
    """Strip base_path prefix from path_str to keep paths relative and clean."""
    if not path_str:
        return ""
    try:
        p = Path(path_str)
        if p.is_absolute():
            return str(p.relative_to(base_path))
    except Exception:
        pass
    base_str = str(base_path)
    if path_str.startswith(base_str):
        return path_str[len(base_str):].lstrip("\\/")
    return path_str


def is_allowed_git_url(target: str) -> bool:
    """Helper to validate if git target URL protocol is secure and allowed."""
    return target.startswith("https://") and " " not in target


def resolve_git_url_and_branch(target: str, options: dict[str, Any] | None = None) -> tuple[str, str | None, str | None]:
    """Parse a git target URL to extract the repository URL, branch name, and optional subpath.

    Returns:
        tuple: (repo_url, branch_name, subpath)
    """
    branch = options.get("branch") if options else None
    repo_url = target
    subpath = None

    for marker in ("/-/tree/", "/tree/", "/src/"):
        if marker in target:
            parts = target.split(marker, 1)
            repo_url = parts[0]
            if not repo_url.endswith(".git"):
                repo_url += ".git"

            rest = parts[1].strip("/")
            if branch:
                # If branch is explicitly provided in options, the rest is treated as subpath.
                # If rest starts with the branch name, strip it to get the relative subpath.
                if rest == branch:
                    subpath = None
                elif rest.startswith(branch + "/"):
                    subpath = rest[len(branch):].strip("/")
                else:
                    subpath = rest
            else:
                # Distinguish between branch name and subpath dynamically
                try:
                    import subprocess
                    proc = subprocess.run(
                        ["git", "ls-remote", "--heads", repo_url],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if proc.returncode == 0:
                        branches = []
                        for line in proc.stdout.splitlines():
                            if "\trefs/heads/" in line:
                                branches.append(line.split("\trefs/heads/")[1])

                        # Match the longest branch name prefix first
                        branches.sort(key=len, reverse=True)
                        matched_branch = None
                        for b in branches:
                            if rest == b:
                                matched_branch = b
                                break
                            elif rest.startswith(b + "/"):
                                matched_branch = b
                                subpath = rest[len(b):].strip("/")
                                break

                        if matched_branch:
                            branch = matched_branch
                        else:
                            branch = rest
                    else:
                        branch = rest
                except Exception:
                    branch = rest
            break

    return repo_url, branch, subpath



# ---------------------------------------------------------------------------
# Event schema
# ---------------------------------------------------------------------------

class ScanProgressEvent(BaseModel):
    """A single event sent over the WebSocket during a scan."""

    type: str  # status_change | progress | finding_discovered | scan_complete | scan_failed
    scan_id: str
    phase: str = ""
    percent: float = 0.0
    findings_count: int = 0
    finding: dict[str, Any] | None = None
    status: str = ""
    error: str = ""
    timestamp: str = ""

    def to_json(self) -> str:
        """Serialize to JSON string for WebSocket transmission."""
        return self.model_dump_json()

def send_slack_alert(scan_target: str, critical_count: int, high_count: int, scan_id: str):
    """Sends a real-time webhook alert to Slack/Teams when a scan finishes, ensuring SSRF protection."""
    from sovascan.config import get_settings, is_safe_webhook_url
    settings = get_settings()
    url = settings.SLACK_WEBHOOK_URL
    if not url:
        return
        
    # Enforce SSRF protection
    if not is_safe_webhook_url(url):
        logger.warning(f"Aborting Slack webhook dispatch: URL '{url}' is classified as unsafe (internal/loopback/non-HTTPS).")
        return
        
    payload = {
        "text": f"🚨 *SovaScan Security Alert*\n"
                "🛡️ *RBI CSF & PCI-DSS Audit Status*\n"
                f"*Target:* `{scan_target}`\n"
                f"*Critical Vulnerabilities:* `{critical_count}`\n"
                f"*High Vulnerabilities:* `{high_count}`\n"
                f"🔗 <http://localhost:8000/report/{scan_id}|View Audit Report>"
    }
    try:
        with httpx.Client(timeout=5.0) as client:
            client.post(url, json=payload)
    except Exception as e:
        logger.error(f"Failed to send Slack webhook alert: {e}")


# ---------------------------------------------------------------------------
# Scan Manager (singleton)
# ---------------------------------------------------------------------------

class ScanManager:
    """Manages background scan execution and WebSocket fan-out.

    Each running scan gets a list of asyncio.Queue objects (one per
    connected WebSocket client).  The scan executes in a thread via
    ``asyncio.to_thread`` and pushes events into all subscriber queues.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[asyncio.Queue[ScanProgressEvent]]] = {}
        self._active_tasks: dict[str, asyncio.Task[None]] = {}
        self._active_orchestrators: dict[str, ScanOrchestrator] = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    # -- subscriber management ---------------------------------------------

    def subscribe(self, scan_id: str) -> asyncio.Queue[ScanProgressEvent]:
        """Register a new subscriber for *scan_id* events."""
        queue: asyncio.Queue[ScanProgressEvent] = asyncio.Queue(maxsize=256)
        self._subscribers.setdefault(scan_id, []).append(queue)
        logger.debug("WS subscriber added for scan %s (total: %d)", scan_id, len(self._subscribers[scan_id]))
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue[ScanProgressEvent]) -> None:
        """Remove a subscriber queue for *scan_id*."""
        queues = self._subscribers.get(scan_id, [])
        if queue in queues:
            queues.remove(queue)
        if not queues:
            self._subscribers.pop(scan_id, None)
        logger.debug("WS subscriber removed for scan %s", scan_id)

    def _broadcast(self, scan_id: str, event: ScanProgressEvent) -> None:
        """Push *event* to all subscriber queues for *scan_id*.

        Called from the background thread — must be thread-safe.
        Uses ``call_soon_threadsafe`` to schedule queue puts on the
        event loop.
        """
        queues = self._subscribers.get(scan_id, [])
        loop = self._loop
        if loop is None:
            return
        for q in queues:
            try:
                loop.call_soon_threadsafe(q.put_nowait, event)
            except asyncio.QueueFull:
                logger.warning("WS queue full for scan %s — dropping event", scan_id)
            except RuntimeError:
                pass  # loop closed

    def _make_event(self, scan_id: str, **kwargs: Any) -> ScanProgressEvent:
        """Create a ScanProgressEvent with auto-populated timestamp."""
        return ScanProgressEvent(
            scan_id=scan_id,
            timestamp=datetime.now(UTC).isoformat(),
            **kwargs,
        )

    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an active scan if running or registered."""
        orchestrator = self._active_orchestrators.get(scan_id)
        if orchestrator:
            orchestrator.cancel()
            logger.info("Cancellation handle invoked for active orchestrator scan %s", scan_id)

        db = SessionMaker()
        try:
            scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan_row and scan_row.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
                scan_row.status = ScanStatus.FAILED
                scan_row.completed_at = datetime.now(UTC)
                metadata = {}
                if scan_row.metadata_json:
                    try:
                        metadata = json.loads(scan_row.metadata_json)
                    except Exception:
                        pass
                metadata["error"] = "Scan cancelled by user"
                scan_row.metadata_json = json.dumps(metadata)
                db.commit()
                self._broadcast(
                    scan_id,
                    self._make_event(
                        scan_id,
                        type="scan_complete",
                        status="failed",
                        phase="Cancelled",
                        error="Scan cancelled by user",
                    ),
                )
                return True
        except Exception as err:
            logger.error("Failed to update cancelled scan in DB: %s", err)
        finally:
            db.close()

        return orchestrator is not None

    # -- scan lifecycle ----------------------------------------------------

    async def start_scan(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        options: dict[str, Any] | None = None,
    ) -> None:
        """Launch a scan in a background thread.

        Returns immediately.  Progress events are pushed to subscribers.
        """
        self._loop = asyncio.get_running_loop()
        task = asyncio.create_task(
            asyncio.to_thread(
                self._execute_scan_sync,
                scan_id,
                target,
                scan_type,
                options,
            )
        )
        self._active_tasks[scan_id] = task

        # Auto-cleanup when the task completes
        def _cleanup(t: asyncio.Task[None]) -> None:
            self._active_tasks.pop(scan_id, None)

        task.add_done_callback(_cleanup)

    def _execute_scan_sync(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        options: dict[str, Any] | None,
    ) -> None:
        """Run the full scan pipeline synchronously in a worker thread.

        Opens its own DB session (thread-safe) and broadcasts progress
        events via the ScanManager.
        """
        db = SessionMaker()
        findings_count = 0
        temp_dir = None

        try:
            # -- Mark RUNNING ------------------------------------------------
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan is None:
                logger.error("Scan %s not found in DB", scan_id)
                return

            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(UTC)
            db.commit()

            self._broadcast(
                scan_id,
                self._make_event(scan_id, type="status_change", status="running", percent=0.0),
            )            # -- Validate and Resolve Target ---------------------------------
            is_git = target.startswith("http://") or target.startswith("https://") or "://" in target or target.startswith("git@")
            if is_git:
                if not is_allowed_git_url(target):
                    raise ValueError("Disallowed git URL protocol. Only HTTP/HTTPS protocols are allowed for remote scans.")
                
                repo_url, branch, subpath = resolve_git_url_and_branch(target, options)
                
                import subprocess
                import tempfile
                temp_dir = tempfile.TemporaryDirectory(prefix="sovascan-clone-")
                clone_path = Path(temp_dir.name)

                self._broadcast(
                    scan_id,
                    self._make_event(
                        scan_id,
                        type="progress",
                        phase=f"Cloning remote git repository branch '{branch or 'default'}'..." if branch else "Cloning remote git repository...",
                        percent=10.0,
                        findings_count=findings_count,
                    ),
                )
                
                clone_cmd = ["git", "clone", "--depth", "1"]
                if branch:
                    clone_cmd.extend(["--branch", branch])
                clone_cmd.extend([repo_url, str(clone_path)])
                
                proc = subprocess.run(
                    clone_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if proc.returncode != 0:
                    raise ValueError(f"Git clone failed: {proc.stderr or proc.stdout}")
                
                if subpath:
                    target_path = clone_path / subpath
                    if not target_path.exists():
                        raise ValueError(f"Subpath '{subpath}' does not exist in branch '{branch or 'default'}' of repository.")
                else:
                    target_path = clone_path
            else:
                if "://" in target:
                    raise ValueError("Invalid target syntax or unsupported URI protocol.")
                target_path = Path(target)
                if not target_path.exists():
                    raise FileNotFoundError(f"Target path does not exist: {target}")

            # -- Phase 1-4: Orchestrator pipeline ----------------------------
            def progress_cb(phase: str, pct: float) -> None:
                self._broadcast(
                    scan_id,
                    self._make_event(
                        scan_id,
                        type="progress",
                        phase=phase,
                        percent=pct,
                        findings_count=findings_count,
                    ),
                )

            orchestrator = ScanOrchestrator(
                target_path=target_path,
                scan_type=scan_type,
                progress_callback=progress_cb,
            )
            self._active_orchestrators[scan_id] = orchestrator
            try:
                result = orchestrator.run_scan()
            finally:
                self._active_orchestrators.pop(scan_id, None)

            # -- Store orchestrator findings ---------------------------------
            severity_counts: dict[str, int] = {
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
            }

            seen_findings = set()

            for sf in result.findings:
                sev = normalize_severity(sf.severity.value if hasattr(sf.severity, "value") else str(sf.severity))
                clean_file_path = _clean_path(sf.file_path, target_path)
                
                evidence = sf.evidence or ""
                if not evidence or evidence.strip() == "requires login":
                    try:
                        file_path_obj = Path(target_path) / clean_file_path
                        if file_path_obj.exists() and file_path_obj.is_file():
                            all_lines = file_path_obj.read_text(encoding="utf-8", errors="ignore").splitlines()
                            line_num = sf.line_number
                            if line_num and 1 <= line_num <= len(all_lines):
                                evidence = all_lines[line_num - 1]
                    except Exception as e:
                        logger.warning("Failed to fallback evidence reading: %s", e)

                evidence_prefix = evidence[:120]
                
                dedup_key = (
                    sf.id,
                    clean_file_path,
                    sf.line_number or 0,
                    evidence_prefix
                )
                if dedup_key in seen_findings:
                    continue
                seen_findings.add(dedup_key)

                finding = FindingModel(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    rule_id=sf.id,
                    title=sf.title,
                    description=sf.description,
                    severity=sev,
                    category=sf.category,
                    file_path=clean_file_path,
                    line_number=sf.line_number or 0,
                    evidence=evidence,
                    remediation=sf.remediation,
                    cve_id=sf.id if sf.category == "cve" else None,
                    cvss_score=sf.cvss_score or None,
                )
                db.add(finding)
                findings_count += 1

                field = _severity_to_field(sev)
                severity_counts[field] += 1

                # Broadcast each finding as it's discovered
                self._broadcast(
                    scan_id,
                    self._make_event(
                        scan_id,
                        type="finding_discovered",
                        phase="Core scan",
                        percent=80.0,
                        findings_count=findings_count,
                        finding={
                            "id": finding.id,
                            "rule_id": finding.rule_id,
                            "title": finding.title,
                            "severity": sev.value,
                            "category": finding.category,
                            "file_path": finding.file_path,
                        },
                    ),
                )

            db.flush()

            # -- Phase 5: SAST tools (only for full/sast) --------------------
            if scan_type in ("full", "sast"):
                self._broadcast(
                    scan_id,
                    self._make_event(
                        scan_id, type="progress", phase="Running SAST tools (Bandit + Semgrep)",
                        percent=85.0, findings_count=findings_count,
                    ),
                )
                sast = SASTScanner()
                for sast_finding_dict in self._run_sast_to_dicts(sast, target_path):
                    sev = normalize_severity(sast_finding_dict["severity"])
                    clean_file_path = _clean_path(sast_finding_dict.get("file_path", ""), target_path)
                    
                    evidence = sast_finding_dict.get("evidence", "") or ""
                    if not evidence or evidence.strip() == "requires login":
                        try:
                            file_path_obj = Path(target_path) / clean_file_path
                            if file_path_obj.exists() and file_path_obj.is_file():
                                all_lines = file_path_obj.read_text(encoding="utf-8", errors="ignore").splitlines()
                                line_num = sast_finding_dict.get("line_number")
                                if line_num and 1 <= line_num <= len(all_lines):
                                    evidence = all_lines[line_num - 1]
                        except Exception as e:
                            logger.warning("Failed to fallback evidence reading: %s", e)

                    evidence_prefix = evidence[:120]
                    
                    dedup_key = (
                        sast_finding_dict["rule_id"],
                        clean_file_path,
                        sast_finding_dict.get("line_number") or 0,
                        evidence_prefix
                    )
                    if dedup_key in seen_findings:
                        continue
                    seen_findings.add(dedup_key)

                    f = FindingModel(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        rule_id=sast_finding_dict["rule_id"],
                        title=sast_finding_dict["title"],
                        description=sast_finding_dict["description"],
                        severity=sev,
                        category=sast_finding_dict.get("category", "sast"),
                        file_path=clean_file_path,
                        line_number=sast_finding_dict.get("line_number") or 0,
                        evidence=evidence,
                        remediation=sast_finding_dict.get("remediation", ""),
                        cve_id=sast_finding_dict.get("cve_id"),
                        cvss_score=sast_finding_dict.get("cvss_score"),
                    )
                    db.add(f)
                    findings_count += 1
                    field = _severity_to_field(sev)
                    severity_counts[field] += 1

                    self._broadcast(
                        scan_id,
                        self._make_event(
                            scan_id, type="finding_discovered", phase="SAST analysis",
                            percent=88.0, findings_count=findings_count,
                            finding={"id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": sev.value, "category": f.category, "file_path": f.file_path},
                        ),
                    )

            # -- Phase 6: Git history (only for full/git-history) ------------
            if scan_type in ("full", "git-history"):
                max_commits = 500
                if options and "git_max_commits" in options:
                    max_commits = int(options["git_max_commits"])
                self._broadcast(
                    scan_id,
                    self._make_event(
                        scan_id, type="progress", phase="Scanning git history for leaked secrets",
                        percent=90.0, findings_count=findings_count,
                    ),
                )
                git_scanner = GitHistoryScanner(max_commits=max_commits)
                for gf in git_scanner.scan(target_path):
                    sev = normalize_severity(gf.severity)
                    clean_file_path = _clean_path(gf.file_path, target_path)
                    evidence_prefix = gf.evidence[:120] if gf.evidence else ""

                    dedup_key = (
                        gf.id,
                        clean_file_path,
                        gf.line_number or 0,
                        evidence_prefix
                    )
                    if dedup_key in seen_findings:
                        continue
                    seen_findings.add(dedup_key)

                    f = FindingModel(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        rule_id=gf.id,
                        title=gf.title,
                        description=gf.description,
                        severity=sev,
                        category=gf.category,
                        file_path=clean_file_path,
                        line_number=gf.line_number or 0,
                        evidence=gf.evidence,
                        remediation=gf.remediation,
                    )
                    db.add(f)
                    findings_count += 1
                    field = _severity_to_field(sev)
                    severity_counts[field] += 1

                    self._broadcast(
                        scan_id,
                        self._make_event(
                            scan_id, type="finding_discovered", phase="Git history analysis",
                            percent=93.0, findings_count=findings_count,
                            finding={"id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": sev.value, "category": f.category, "file_path": f.file_path},
                        ),
                    )

            # -- Finalize ----------------------------------------------------
            scan.total_findings = findings_count
            scan.critical_count = severity_counts["critical_count"]
            scan.high_count = severity_counts["high_count"]
            scan.medium_count = severity_counts["medium_count"]
            scan.low_count = severity_counts["low_count"]
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(UTC)

            # Cache SBOM in metadata_json
            metadata = {}
            if scan.metadata_json:
                try:
                    metadata = json.loads(scan.metadata_json)
                except Exception:
                    pass
            metadata["sbom"] = result.sbom
            scan.metadata_json = json.dumps(metadata)

            db.commit()

            # Trigger real-time Slack/Teams alerting
            try:
                send_slack_alert(scan.target, scan.critical_count, scan.high_count, scan.id)
            except Exception as e:
                logger.error(f"Slack notification error: {e}")

            self._broadcast(
                scan_id,
                self._make_event(
                    scan_id,
                    type="scan_complete",
                    status="completed",
                    percent=100.0,
                    findings_count=findings_count,
                    phase="Scan complete",
                ),
            )
            logger.info("Scan %s completed — %d findings", scan_id, findings_count)

        except Exception as exc:
            logger.exception("Scan %s failed: %s", scan_id, exc)
            try:
                scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan_row:
                    scan_row.status = ScanStatus.FAILED
                    scan_row.completed_at = datetime.now(UTC)
                    
                    metadata = {}
                    if scan_row.metadata_json:
                        try:
                            metadata = json.loads(scan_row.metadata_json)
                        except Exception:
                            pass
                    metadata["error"] = str(exc)
                    metadata["failed_at"] = datetime.now(UTC).isoformat()
                    scan_row.metadata_json = json.dumps(metadata)

                    db.commit()
            except Exception:
                logger.exception("Failed to update scan %s status to FAILED", scan_id)

            self._broadcast(
                scan_id,
                self._make_event(
                    scan_id,
                    type="scan_failed",
                    status="failed",
                    error=str(exc)[:500],
                    findings_count=findings_count,
                ),
            )
        finally:
            if temp_dir is not None:
                try:
                    temp_dir.cleanup()
                except Exception as cleanup_err:
                    logger.warning("Failed to clean up temporary directory: %s", cleanup_err)
            db.close()

    # -- SAST helper -------------------------------------------------------

    @staticmethod
    def _run_sast_to_dicts(sast: SASTScanner, target: Path) -> list[dict[str, Any]]:
        """Run SAST and convert Finding dataclass objects to DB-ready dicts."""
        raw = sast.scan(target)
        results: list[dict[str, Any]] = []
        for f in raw:
            sev_str = f.severity
            try:
                sev = Severity(sev_str)
            except ValueError:
                sev = Severity.MEDIUM
            results.append({
                "rule_id": f.id,
                "title": f.title,
                "description": f.description,
                "severity": sev,
                "category": f.category,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "cve_id": None,
                "cvss_score": f.cvss_score,
            })
        return results


def _severity_to_field(severity: Severity) -> str:
    """Map a Severity enum to the corresponding count field name on Scan."""
    return {
        Severity.CRITICAL: "critical_count",
        Severity.HIGH: "high_count",
        Severity.MEDIUM: "medium_count",
        Severity.LOW: "low_count",
        Severity.INFO: "low_count",
    }.get(severity, "low_count")


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

scan_manager = ScanManager()


# ---------------------------------------------------------------------------
# WebSocket route handler
# ---------------------------------------------------------------------------

async def scan_websocket(websocket: WebSocket, scan_id: str) -> None:
    """WebSocket endpoint for streaming scan progress.

    Clients connect to ``/api/v1/scan/{scan_id}/ws`` and receive
    JSON-encoded :class:`ScanProgressEvent` messages in real time.
    """
    api_key_str = websocket.query_params.get("api_key")
    db = SessionMaker()
    try:
        if not api_key_str:
            await websocket.accept()
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Missing API key")
            return

        key_hash = hashlib.sha256(api_key_str.encode("utf-8")).hexdigest()
        db_key = db.query(ApiKey).filter(
            ApiKey.key_hash == key_hash,
            ApiKey.is_active == True
        ).first()

        if not db_key:
            await websocket.accept()
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid API key")
            return
    except Exception as exc:
        logger.error("WebSocket auth error: %s", exc)
        await websocket.accept()
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        return
    finally:
        db.close()

    await websocket.accept()
    logger.info("WS client authenticated and connected for scan %s", scan_id)

    # Send current scan status as the first message
    db = SessionMaker()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            initial = ScanProgressEvent(
                type="status_change",
                scan_id=scan_id,
                status=scan.status.value if hasattr(scan.status, "value") else str(scan.status),
                percent=100.0 if scan.status == ScanStatus.COMPLETED else 0.0,
                findings_count=scan.total_findings,
                timestamp=datetime.now(UTC).isoformat(),
            )
            await websocket.send_text(initial.to_json())
    finally:
        db.close()

    # Subscribe to events
    queue = scan_manager.subscribe(scan_id)

    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=300.0)
                await websocket.send_text(event.to_json())

                # Close after terminal events
                if event.type in ("scan_complete", "scan_failed"):
                    break
            except TimeoutError:
                # Send keepalive ping
                try:
                    await websocket.send_text(
                        ScanProgressEvent(
                            type="keepalive",
                            scan_id=scan_id,
                            timestamp=datetime.now(UTC).isoformat(),
                        ).to_json()
                    )
                except Exception:
                    break
    except WebSocketDisconnect:
        logger.info("WS client disconnected for scan %s", scan_id)
    except Exception as exc:
        logger.exception("WS error for scan %s: %s", scan_id, exc)
    finally:
        scan_manager.unsubscribe(scan_id, queue)
        try:
            await websocket.close()
        except Exception:
            pass
