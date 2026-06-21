"""Report Generator - produces structured reports in JSON, SARIF, and HTML formats.

Generates comprehensive security scan reports with summary statistics,
severity breakdowns, and detailed finding information.
"""

from __future__ import annotations

import html
import json
import logging
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates scan reports in multiple formats."""

    SUPPORTED_FORMATS = {"json", "sarif", "html"}

    def generate(
        self,
        findings: list,
        scan_metadata: dict[str, Any],
        fmt: str = "json",
    ) -> str | dict:
        """Generate a report in the specified format.

        Args:
            findings: List of ScoredFinding objects.
            scan_metadata: Dict with target_path, scan_type, duration, etc.
            fmt: Output format - 'json', 'sarif', or 'html'.

        Returns:
            Report as string (html, sarif) or dict (json).

        Raises:
            ValueError: If format is not supported.
        """
        fmt = fmt.lower().strip()
        if fmt not in self.SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported format '{fmt}'. Use: {', '.join(self.SUPPORTED_FORMATS)}")

        if fmt == "json":
            return self._generate_json(findings, scan_metadata)
        elif fmt == "sarif":
            return self._generate_sarif(findings, scan_metadata)
        else:
            return self._generate_html(findings, scan_metadata)

    # ── JSON Report ────────────────────────────────────────────────────

    def _generate_json(self, findings: list, metadata: dict) -> dict:
        """Generate a structured JSON report.

        Args:
            findings: List of ScoredFinding objects.
            metadata: Scan metadata dict.

        Returns:
            Report as a Python dict (JSON-serializable).
        """
        summary = self._compute_summary(findings)

        findings_data = []
        for f in findings:
            finding_dict = self._finding_to_dict(f)
            findings_data.append(finding_dict)

        report = {
            "schema_version": "1.0.0",
            "tool": {
                "name": "SovaScan",
                "version": "1.0.0",
                "description": "Security Vulnerability and Configuration Scanner",
            },
            "metadata": {
                "timestamp": datetime.now(UTC).isoformat(),
                "target": metadata.get("target_path", ""),
                "scan_type": metadata.get("scan_type", "full"),
                "duration_seconds": metadata.get("duration", 0),
                "files_scanned": metadata.get("files_scanned", 0),
                "dependencies_scanned": metadata.get("dependencies_scanned", 0),
            },
            "summary": summary,
            "findings": findings_data,
        }

        return report

    # ── SARIF Report ───────────────────────────────────────────────────

    def _generate_sarif(self, findings: list, metadata: dict) -> str:
        """Generate a SARIF 2.1.0 report.

        Produces a valid Static Analysis Results Interchange Format report
        compatible with GitHub Code Scanning and other SARIF consumers.

        Args:
            findings: List of ScoredFinding objects.
            metadata: Scan metadata dict.

        Returns:
            SARIF JSON string.
        """
        # Collect unique rules
        rules_map: dict[str, dict] = {}
        results: list[dict] = []

        severity_to_sarif = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }

        for f in findings:
            rule_id = getattr(f, "id", "UNKNOWN")
            severity_str = str(getattr(f, "severity", "info"))

            # Register rule if not seen
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": getattr(f, "title", rule_id),
                    "shortDescription": {
                        "text": getattr(f, "title", ""),
                    },
                    "fullDescription": {
                        "text": getattr(f, "description", ""),
                    },
                    "help": {
                        "text": getattr(f, "remediation", "No remediation available."),
                        "markdown": f"**Remediation:** {getattr(f, 'remediation', 'N/A')}",
                    },
                    "defaultConfiguration": {
                        "level": severity_to_sarif.get(severity_str, "note"),
                    },
                    "properties": {
                        "tags": getattr(f, "tags", []),
                        "category": getattr(f, "category", ""),
                    },
                }

            # Build result
            file_path = getattr(f, "file_path", "")
            line_number = max(1, getattr(f, "line_number", 1))

            result = {
                "ruleId": rule_id,
                "ruleIndex": list(rules_map.keys()).index(rule_id),
                "level": severity_to_sarif.get(severity_str, "note"),
                "message": {
                    "text": getattr(f, "description", ""),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path.replace("\\", "/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": line_number,
                                "startColumn": 1,
                            },
                        },
                    }
                ],
                "fingerprints": {
                    "sovascan/v1": f"{rule_id}:{file_path}:{line_number}",
                },
                "properties": {
                    "severity": severity_str,
                    "category": getattr(f, "category", ""),
                    "evidence": getattr(f, "evidence", ""),
                    "final_score": getattr(f, "final_score", 0.0),
                },
            }

            # Add fixes if remediation available
            remediation = getattr(f, "remediation", "")
            if remediation:
                result["fixes"] = [
                    {
                        "description": {
                            "text": remediation,
                        },
                    }
                ]

            results.append(result)

        sarif = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SovaScan",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/sovascan/sovascan",
                            "semanticVersion": "1.0.0",
                            "rules": list(rules_map.values()),
                        },
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": metadata.get(
                                "start_time",
                                datetime.now(UTC).isoformat(),
                            ),
                            "endTimeUtc": metadata.get(
                                "end_time",
                                datetime.now(UTC).isoformat(),
                            ),
                        }
                    ],
                    "columnKind": "utf16CodeUnits",
                }
            ],
        }

        return json.dumps(sarif, indent=2, default=str)

    # ── HTML Report ────────────────────────────────────────────────────

    def _generate_html(self, findings: list, metadata: dict) -> str:
        """Generate a standalone dark-themed HTML report.

        Args:
            findings: List of ScoredFinding objects.
            metadata: Scan metadata dict.

        Returns:
            Complete HTML document as string.
        """
        summary = self._compute_summary(findings)
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        target = html.escape(str(metadata.get("target_path", "")))
        duration = metadata.get("duration", 0)

        # Build severity pie chart as inline SVG
        pie_svg = self._build_pie_chart(summary["by_severity"])

        # Build findings table rows
        rows = self._build_html_table_rows(findings)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SovaScan Security Report</title>
<style>
  :root {{
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #21262d;
    --border: #30363d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --accent: #58a6ff;
    --critical: #f85149;
    --high: #f0883e;
    --medium: #d29922;
    --low: #3fb950;
    --info: #8b949e;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 2rem;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  .header {{
    text-align: center;
    padding: 2rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
  }}
  .header h1 {{ font-size: 2.5rem; color: var(--accent); margin-bottom: 0.5rem; }}
  .header .subtitle {{ color: var(--text-secondary); font-size: 1rem; }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .meta-card {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
    text-align: center;
  }}
  .meta-card .label {{ color: var(--text-secondary); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }}
  .meta-card .value {{ font-size: 1.8rem; font-weight: 700; margin-top: 0.25rem; }}
  .severity-section {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
    margin-bottom: 2rem;
    align-items: center;
  }}
  .severity-cards {{ display: flex; flex-direction: column; gap: 0.75rem; }}
  .severity-card {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.75rem 1.25rem;
  }}
  .severity-card .sev-label {{ font-weight: 600; }}
  .severity-card .sev-count {{ font-size: 1.5rem; font-weight: 700; }}
  .sev-critical {{ border-left: 4px solid var(--critical); }}
  .sev-critical .sev-count {{ color: var(--critical); }}
  .sev-high {{ border-left: 4px solid var(--high); }}
  .sev-high .sev-count {{ color: var(--high); }}
  .sev-medium {{ border-left: 4px solid var(--medium); }}
  .sev-medium .sev-count {{ color: var(--medium); }}
  .sev-low {{ border-left: 4px solid var(--low); }}
  .sev-low .sev-count {{ color: var(--low); }}
  .sev-info {{ border-left: 4px solid var(--info); }}
  .sev-info .sev-count {{ color: var(--info); }}
  .chart-container {{ display: flex; justify-content: center; align-items: center; }}
  .findings-section {{ margin-top: 2rem; }}
  .findings-section h2 {{
    font-size: 1.5rem;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--bg-secondary);
    border-radius: 8px;
    overflow: hidden;
  }}
  th {{
    background: var(--bg-tertiary);
    padding: 0.75rem 1rem;
    text-align: left;
    font-weight: 600;
    color: var(--text-secondary);
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  td {{
    padding: 0.75rem 1rem;
    border-top: 1px solid var(--border);
    font-size: 0.9rem;
    vertical-align: top;
  }}
  tr:hover {{ background: var(--bg-tertiary); }}
  .badge {{
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
  }}
  .badge-critical {{ background: rgba(248,81,73,.15); color: var(--critical); }}
  .badge-high {{ background: rgba(240,136,62,.15); color: var(--high); }}
  .badge-medium {{ background: rgba(210,153,34,.15); color: var(--medium); }}
  .badge-low {{ background: rgba(63,185,80,.15); color: var(--low); }}
  .badge-info {{ background: rgba(139,148,158,.15); color: var(--info); }}
  .category-badge {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    background: rgba(88,166,255,.15);
    color: var(--accent);
  }}
  .evidence {{ font-family: monospace; font-size: 0.8rem; color: var(--text-secondary); word-break: break-all; max-width: 300px; }}
  .footer {{
    text-align: center;
    margin-top: 3rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
    color: var(--text-secondary);
    font-size: 0.85rem;
  }}
  @media (max-width: 768px) {{
    .severity-section {{ grid-template-columns: 1fr; }}
    body {{ padding: 1rem; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🦉 SovaScan Report</h1>
    <div class="subtitle">Security Vulnerability &amp; Configuration Scan Results</div>
  </div>

  <div class="meta-grid">
    <div class="meta-card">
      <div class="label">Target</div>
      <div class="value" style="font-size:1rem;word-break:break-all;">{target}</div>
    </div>
    <div class="meta-card">
      <div class="label">Total Findings</div>
      <div class="value">{summary['total']}</div>
    </div>
    <div class="meta-card">
      <div class="label">Scan Duration</div>
      <div class="value">{duration:.1f}s</div>
    </div>
    <div class="meta-card">
      <div class="label">Timestamp</div>
      <div class="value" style="font-size:1rem;">{timestamp}</div>
    </div>
  </div>

  <div class="severity-section">
    <div class="severity-cards">
      <div class="severity-card sev-critical">
        <span class="sev-label">🔴 Critical</span>
        <span class="sev-count">{summary['by_severity'].get('critical', 0)}</span>
      </div>
      <div class="severity-card sev-high">
        <span class="sev-label">🟠 High</span>
        <span class="sev-count">{summary['by_severity'].get('high', 0)}</span>
      </div>
      <div class="severity-card sev-medium">
        <span class="sev-label">🟡 Medium</span>
        <span class="sev-count">{summary['by_severity'].get('medium', 0)}</span>
      </div>
      <div class="severity-card sev-low">
        <span class="sev-label">🟢 Low</span>
        <span class="sev-count">{summary['by_severity'].get('low', 0)}</span>
      </div>
      <div class="severity-card sev-info">
        <span class="sev-label">⚪ Info</span>
        <span class="sev-count">{summary['by_severity'].get('info', 0)}</span>
      </div>
    </div>
    <div class="chart-container">
      {pie_svg}
    </div>
  </div>

  <div class="findings-section">
    <h2>Findings ({summary['total']})</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>ID</th>
          <th>Title</th>
          <th>Category</th>
          <th>File</th>
          <th>Line</th>
          <th>Score</th>
          <th>Evidence</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Generated by SovaScan v1.0.0 &bull; {timestamp}
  </div>
</div>
</body>
</html>"""

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _compute_summary(findings: list) -> dict[str, Any]:
        """Compute summary statistics from findings."""
        summary: dict[str, Any] = {
            "total": len(findings),
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "by_category": {},
        }

        for f in findings:
            sev = str(getattr(f, "severity", "info")).lower()
            if sev in summary["by_severity"]:
                summary["by_severity"][sev] += 1
            else:
                summary["by_severity"]["info"] += 1

            cat = getattr(f, "category", "other")
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1

        return summary

    @staticmethod
    def _finding_to_dict(f: Any) -> dict:
        """Convert a finding (ScoredFinding or Finding) to a plain dict."""
        try:
            return asdict(f)
        except (TypeError, AttributeError):
            result: dict[str, Any] = {}
            for attr in [
                "id", "title", "description", "severity", "category",
                "file_path", "line_number", "evidence", "remediation",
                "references", "tags", "cvss_score", "metadata",
                "base_score", "final_score", "contextual_modifiers",
                "original_severity",
            ]:
                val = getattr(f, attr, None)
                if val is not None:
                    result[attr] = str(val) if hasattr(val, "value") else val
            return result

    @staticmethod
    def _build_pie_chart(by_severity: dict[str, int]) -> str:
        """Build an inline SVG pie chart for severity distribution."""
        total = sum(by_severity.values())
        if total == 0:
            return '<svg width="200" height="200"><text x="100" y="100" text-anchor="middle" fill="#8b949e">No findings</text></svg>'

        colors = {
            "critical": "#f85149",
            "high": "#f0883e",
            "medium": "#d29922",
            "low": "#3fb950",
            "info": "#8b949e",
        }

        cx, cy, r = 120, 120, 100
        start_angle = -90.0  # Start from top
        paths: list[str] = []

        import math

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = by_severity.get(sev, 0)
            if count == 0:
                continue

            fraction = count / total
            angle = fraction * 360.0

            if fraction >= 1.0:
                # Full circle
                paths.append(
                    f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{colors[sev]}" opacity="0.85"/>'
                )
                continue

            start_rad = math.radians(start_angle)
            end_rad = math.radians(start_angle + angle)

            x1 = cx + r * math.cos(start_rad)
            y1 = cy + r * math.sin(start_rad)
            x2 = cx + r * math.cos(end_rad)
            y2 = cy + r * math.sin(end_rad)

            large_arc = 1 if angle > 180 else 0

            path = (
                f'<path d="M {cx},{cy} L {x1:.2f},{y1:.2f} '
                f'A {r},{r} 0 {large_arc},1 {x2:.2f},{y2:.2f} Z" '
                f'fill="{colors[sev]}" opacity="0.85"/>'
            )
            paths.append(path)

            # Label
            mid_angle = math.radians(start_angle + angle / 2)
            label_r = r * 0.65
            lx = cx + label_r * math.cos(mid_angle)
            ly = cy + label_r * math.sin(mid_angle)
            if fraction >= 0.05:
                paths.append(
                    f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="middle" '
                    f'dominant-baseline="central" fill="#fff" font-size="12" '
                    f'font-weight="600">{count}</text>'
                )

            start_angle += angle

        svg_paths = "\n    ".join(paths)
        return f"""<svg width="240" height="240" viewBox="0 0 240 240" xmlns="http://www.w3.org/2000/svg">
    {svg_paths}
  </svg>"""

    @staticmethod
    def _build_html_table_rows(findings: list) -> str:
        """Build HTML table rows for findings."""
        if not findings:
            return '<tr><td colspan="8" style="text-align:center;padding:2rem;color:#8b949e;">No findings detected ✅</td></tr>'

        severity_badge = {
            "critical": "badge-critical",
            "high": "badge-high",
            "medium": "badge-medium",
            "low": "badge-low",
            "info": "badge-info",
        }

        rows: list[str] = []
        for f in findings:
            sev = str(getattr(f, "severity", "info")).lower()
            badge_class = severity_badge.get(sev, "badge-info")
            score = getattr(f, "final_score", getattr(f, "cvss_score", 0.0))
            file_path = html.escape(str(getattr(f, "file_path", "")))
            # Shorten path for display
            short_path = file_path.split("/")[-1] if "/" in file_path else file_path.split("\\")[-1] if "\\" in file_path else file_path
            evidence = html.escape(str(getattr(f, "evidence", ""))[:100])

            rows.append(f"""        <tr>
          <td><span class="badge {badge_class}">{html.escape(sev)}</span></td>
          <td>{html.escape(str(getattr(f, 'id', '')))}</td>
          <td>{html.escape(str(getattr(f, 'title', '')))}</td>
          <td><span class="category-badge">{html.escape(str(getattr(f, 'category', '')))}</span></td>
          <td title="{file_path}">{html.escape(short_path)}</td>
          <td>{getattr(f, 'line_number', 0)}</td>
          <td>{score}</td>
          <td><span class="evidence">{evidence}</span></td>
        </tr>""")

        return "\n".join(rows)
