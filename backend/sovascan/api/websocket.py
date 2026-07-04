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
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from sovascan.core.orchestrator import ScanOrchestrator
from sovascan.core.sast_scanner import SASTScanner
from sovascan.core.git_history_scanner import GitHistoryScanner
from sovascan.models.base import SessionLocal
from sovascan.models.finding import Finding as FindingModel, Severity
from sovascan.models.scan import Scan, ScanStatus

logger = logging.getLogger("sovascan.ws")

# Global SessionMaker alias to support override in test environment
SessionMaker = SessionLocal


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
            )

            # -- Validate target ---------------------------------------------
            if target.startswith("http://") or target.startswith("https://"):
                raise ValueError("Remote URL scanning is not yet supported.")

            target_path = Path(target)
            if not target_path.exists():
                raise FileNotFoundError(f"Target path does not exist: {target}")

            # -- Phase 1-4: Orchestrator pipeline ----------------------------
            def progress_cb(phase: str, pct: float) -> None:
                nonlocal findings_count
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

            result = orchestrator.run_scan()

            # -- Store orchestrator findings ---------------------------------
            severity_counts: dict[str, int] = {
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
            }

            for sf in result.findings:
                sev = Severity(sf.severity.value)
                finding = FindingModel(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    rule_id=sf.id,
                    title=sf.title,
                    description=sf.description,
                    severity=sev,
                    category=sf.category,
                    file_path=sf.file_path,
                    line_number=sf.line_number,
                    evidence=sf.evidence,
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
                    sev = sast_finding_dict["severity"]
                    f = FindingModel(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        rule_id=sast_finding_dict["rule_id"],
                        title=sast_finding_dict["title"],
                        description=sast_finding_dict["description"],
                        severity=sev,
                        category=sast_finding_dict.get("category", "sast"),
                        file_path=sast_finding_dict.get("file_path", ""),
                        line_number=sast_finding_dict.get("line_number"),
                        evidence=sast_finding_dict.get("evidence", ""),
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
                    sev = Severity(gf.severity) if gf.severity in [s.value for s in Severity] else Severity.MEDIUM
                    f = FindingModel(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        rule_id=gf.id,
                        title=gf.title,
                        description=gf.description,
                        severity=sev,
                        category=gf.category,
                        file_path=gf.file_path,
                        line_number=gf.line_number,
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
            db.commit()

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
    await websocket.accept()
    logger.info("WS client connected for scan %s", scan_id)

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
            except asyncio.TimeoutError:
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
