export type SeverityType = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';
export type ScanType = 'full' | 'dependencies' | 'secrets' | 'misconfig' | 'sast' | 'git-history';

export interface Scan {
  id: string;
  target: string;
  status: ScanStatus;
  scanType: ScanType;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  startedAt: string;
  completedAt: string | null;
  createdAt: string;
}

export interface Finding {
  id: string;
  scanId: string;
  ruleId: string;
  title: string;
  description: string;
  severity: SeverityType;
  category: string;
  filePath: string;
  lineNumber: number;
  evidence: string;
  remediation: string;
  cveId: string | null;
  cvssScore: number | null;
  isFixed: boolean;
  createdAt: string;
}

export interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface TopVulnerability {
  id: string;
  title: string;
  severity: SeverityType;
  count: number;
  category: string;
}

export interface TrendDataPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface DashboardSummary {
  totalScans: number;
  totalFindings: number;
  severityDistribution: SeverityDistribution;
  recentScans: Scan[];
  topVulnerabilities: TopVulnerability[];
  riskScore: number;
  trendData: TrendDataPoint[];
}

export interface ComplianceControl {
  id: string;
  name: string;
  description: string;
  status: 'passed' | 'failed' | 'not-applicable';
  category: string;
  findings: string[];
}

export interface ComplianceReport {
  framework: string;
  frameworkFullName: string;
  score: number;
  totalControls: number;
  passed: number;
  failed: number;
  notApplicable: number;
  controls: ComplianceControl[];
  lastAssessed: string;
}

export interface ScanProgressEvent {
  type: 'status_change' | 'progress' | 'finding_discovered' | 'scan_complete' | 'scan_failed' | 'keepalive';
  scan_id: string;
  phase: string;
  percent: number;
  findings_count: number;
  finding: {
    id: string;
    rule_id: string;
    title: string;
    severity: SeverityType;
    category: string;
    file_path: string;
  } | null;
  status: string;
  error: string;
  timestamp: string;
}
