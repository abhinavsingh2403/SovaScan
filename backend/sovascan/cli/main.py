"""SovaScan CLI - Command-Line Interface using Click and Rich.

Allows running security scans directly from the terminal with styled outputs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

from sovascan.core.orchestrator import ScanOrchestrator
from sovascan.core.report_generator import ReportGenerator

console = Console()

BANNER = """
   (O , O)
   (  _  )   SovaScan
   -"---"-
Intelligent Dependency & Config Security Analyzer
"""


@click.group()
@click.version_option(version="0.1.0")
def cli() -> None:
    """SovaScan - Static Security Analyzer for Dependencies & Configs."""
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path))
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["table", "json", "html", "sarif"], case_sensitive=False),
    default="table",
    help="Output format (default: table)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(writable=True, path_type=Path),
    help="Save report to this file path",
)
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
    help="Minimum severity level to report",
)
@click.option(
    "--scan-type",
    "-t",
    type=click.Choice(["full", "dependencies", "secrets", "misconfig"], case_sensitive=False),
    default="full",
    help="Scan scope (default: full)",
)
@click.option(
    "--rules-dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    help="Override default rules directory",
)
def scan(
    path: Path,
    fmt: str,
    output: Path | None,
    severity: str | None,
    scan_type: str,
    rules_dir: Path | None,
) -> None:
    """Scan a target path for vulnerabilities, secrets, and misconfigurations."""
    fmt = fmt.lower()
    
    if fmt == "table":
        console.print(Panel(BANNER, border_style="#6366f1"))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task(description="Initializing scan...", total=100)

        def progress_callback(phase: str, pct: float) -> None:
            progress.update(task, description=f"{phase}...", completed=pct)

        orchestrator = ScanOrchestrator(
            target_path=path,
            scan_type=scan_type,
            rules_dir=rules_dir,
            progress_callback=progress_callback,
        )

        try:
            result = orchestrator.run_scan()
        except Exception as exc:
            console.print(f"[red]Error executing scan: {exc}[/red]")
            sys.exit(1)

    # Filter findings by severity if requested
    findings = result.findings
    if severity:
        sev_levels = ["info", "low", "medium", "high", "critical"]
        min_idx = sev_levels.index(severity.lower())
        findings = [f for f in findings if sev_levels.index(f.severity.value) >= min_idx]

    # Output formatting
    if fmt == "table":
        _print_table_report(result, findings)
    else:
        # Generate structured report
        generator = ReportGenerator()
        scan_metadata = {
            "target_path": str(path),
            "scan_type": scan_type,
            "duration_seconds": result.duration,
            "findings_count": len(findings),
            **result.metadata
        }
        report = generator.generate(findings, scan_metadata, fmt)
        
        # Output to file or stdout
        if output:
            try:
                if isinstance(report, dict):
                    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
                else:
                    output.write_text(report, encoding="utf-8")
                console.print(f"[green]Successfully saved {fmt.upper()} report to: {output}[/green]")
            except OSError as exc:
                console.print(f"[red]Failed to save report: {exc}[/red]")
                sys.exit(1)
        else:
            if isinstance(report, dict):
                print(json.dumps(report, indent=2))
            else:
                print(report)

    # Exit code based on critical/high findings
    critical_high_count = sum(
        1 for f in findings if f.severity.value in ("critical", "high")
    )
    if critical_high_count > 0:
        sys.exit(1)
    sys.exit(0)


def _print_table_report(result: Any, findings: list[Any]) -> None:
    """Print findings to terminal in a clean table format."""
    console.print(f"\n[bold]Scan Target:[/bold] {result.target_path}")
    console.print(f"[bold]Scan Type:[/bold] {result.scan_type.upper()}")
    console.print(f"[bold]Duration:[/bold] {result.duration}s")
    console.print(f"[bold]Manifests Scanned:[/bold] {len(result.metadata.get('manifests_scanned', []))}")
    console.print(f"[bold]Dependencies Found:[/bold] {len(result.dependencies)}")

    if not findings:
        console.print("\n[bold green]No security issues detected![/bold green]\n")
        return

    table = Table(title="Security Findings", box=None, padding=(0, 1, 0, 1))
    table.add_column("Severity", width=10)
    table.add_column("ID", width=15)
    table.add_column("Category", width=15)
    table.add_column("Finding", width=40)
    table.add_column("Location")

    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim green",
    }

    for f in findings:
        sev = f.severity.value
        sev_color = severity_colors.get(sev, "white")
        
        location = f.file_path
        if f.line_number:
            location += f":{f.line_number}"

        table.add_row(
            f"[{sev_color}]{sev.upper()}[/{sev_color}]",
            f.id,
            f.category,
            f.title,
            location,
        )

    console.print("\n")
    console.print(table)
    console.print("\n")

    # Severity Breakdown Panel
    breakdown_text = ", ".join(
        f"{sev.upper()}: {count}" for sev, count in result.severity_counts.items() if count > 0
    )
    console.print(
        Panel(
            f"Total Findings: {result.total_findings} ({breakdown_text})",
            title="Breakdown Summary",
            border_style="#6366f1",
        )
    )
    console.print("\n")


if __name__ == "__main__":
    cli()
