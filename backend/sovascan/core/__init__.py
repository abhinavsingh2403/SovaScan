"""SovaScan Core Scanning Engine - exports all core classes."""

from sovascan.core.config_drift import ConfigDriftAnalyzer
from sovascan.core.cve_scanner import CVEScanner
from sovascan.core.dependency_resolver import Dependency, DependencyResolver
from sovascan.core.git_history_scanner import GitHistoryScanner
from sovascan.core.misconfig_detector import MisconfigDetector
from sovascan.core.orchestrator import ScanOrchestrator, ScanResult
from sovascan.core.report_generator import ReportGenerator
from sovascan.core.sast_scanner import SASTScanner
from sovascan.core.secret_scanner import SecretScanner
from sovascan.core.severity_scorer import ScoredFinding, Severity, SeverityScorer

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
    "SASTScanner",
    "GitHistoryScanner",
]
