"""SovaScan Core Scanning Engine - exports all core classes."""

from sovascan.core.orchestrator import ScanOrchestrator, ScanResult
from sovascan.core.dependency_resolver import DependencyResolver, Dependency
from sovascan.core.cve_scanner import CVEScanner
from sovascan.core.misconfig_detector import MisconfigDetector
from sovascan.core.secret_scanner import SecretScanner
from sovascan.core.config_drift import ConfigDriftAnalyzer
from sovascan.core.severity_scorer import SeverityScorer, ScoredFinding, Severity
from sovascan.core.report_generator import ReportGenerator

__all__ = [
    "ScanOrchestrator",
    "ScanResult",
    "DependencyResolver",
    "Dependency",
    "CVEScanner",
    "MisconfigDetector",
    "SecretScanner",
    "ConfigDriftAnalyzer",
    "SeverityScorer",
    "ScoredFinding",
    "Severity",
    "ReportGenerator",
]
