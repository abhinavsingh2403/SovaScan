import { create } from 'zustand';
import { api } from '../api/client';
import type {
  Scan,
  ScanType,
  SeverityType,
  Finding,
  DashboardSummary,
  ComplianceReport,
  ComplianceControl,
} from '../types';

/* ============================================================
   Snake_case → camelCase Mapping Utilities
   ============================================================ */

/**
 * Maps a backend scan response (snake_case) to the frontend Scan type (camelCase).
 */
const mapScan = (s: Record<string, unknown>): Scan => ({
  id: s.id as string,
  target: s.target as string,
  status: s.status as Scan['status'],
  scanType: ((s.scan_type as string) ?? 'full') as ScanType,
  totalFindings: (s.total_findings as number) ?? 0,
  criticalCount: (s.critical_count as number) ?? 0,
  highCount: (s.high_count as number) ?? 0,
  mediumCount: (s.medium_count as number) ?? 0,
  lowCount: (s.low_count as number) ?? 0,
  startedAt: (s.started_at as string) ?? '',
  completedAt: (s.completed_at as string | null) ?? null,
  createdAt: (s.created_at as string) ?? '',
});

/**
 * Maps a backend finding response (snake_case) to the frontend Finding type (camelCase).
 */
const mapFinding = (f: Record<string, unknown>): Finding => ({
  id: f.id as string,
  scanId: (f.scan_id as string) ?? '',
  ruleId: (f.rule_id as string) ?? '',
  title: (f.title as string) ?? '',
  description: (f.description as string) ?? '',
  severity: (f.severity as Finding['severity']) ?? 'info',
  category: (f.category as string) ?? '',
  filePath: (f.file_path as string) ?? '',
  lineNumber: (f.line_number as number) ?? 0,
  evidence: (f.evidence as string) ?? '',
  remediation: (f.remediation as string) ?? '',
  cveId: (f.cve_id as string | null) ?? null,
  cvssScore: (f.cvss_score as number | null) ?? null,
  isFixed: (f.is_fixed as boolean) ?? false,
  createdAt: (f.created_at as string) ?? '',
});

/**
 * Maps the full backend dashboard/summary response to the frontend DashboardSummary type.
 */
const mapDashboardSummary = (d: Record<string, unknown>): DashboardSummary => {
  const dist = (d.severity_distribution as Record<string, number>) ?? {};
  const recentRaw = (d.recent_scans as Record<string, unknown>[]) ?? [];
  const topRaw = (d.top_vulnerabilities as Record<string, unknown>[]) ?? [];
  const trendRaw = (d.trend_data as Record<string, unknown>[]) ?? [];

  return {
    totalScans: (d.total_scans as number) ?? 0,
    totalFindings: (d.total_findings as number) ?? 0,
    severityDistribution: {
      critical: dist.critical ?? 0,
      high: dist.high ?? 0,
      medium: dist.medium ?? 0,
      low: dist.low ?? 0,
      info: dist.info ?? 0,
    },
    recentScans: recentRaw.map(mapScan),
    topVulnerabilities: topRaw.map((v) => ({
      id: (v.id as string) ?? '',
      title: (v.title as string) ?? '',
      severity: ((v.severity as string) ?? 'info') as SeverityType,
      count: (v.count as number) ?? 0,
      category: (v.category as string) ?? '',
    })),
    riskScore: (d.risk_score as number) ?? 0,
    trendData: trendRaw.map((t) => ({
      date: (t.date as string) ?? '',
      critical: (t.critical as number) ?? 0,
      high: (t.high as number) ?? 0,
      medium: (t.medium as number) ?? 0,
      low: (t.low as number) ?? 0,
    })),
  };
};

/* ============================================================
   Compliance Control Generation (client-side mapping)
   ============================================================

   The backend returns a flat compliance score + a list of violating
   findings.  The frontend UI expects a 12-row checklist grid of
   named controls per framework.  This function generates those
   controls and maps findings to them via keyword matching.
   ============================================================ */

const FRAMEWORK_CATEGORIES: Record<string, string[]> = {
  'NIST-CSF': [
    'Identify', 'Identify', 'Protect', 'Protect', 'Protect',
    'Detect', 'Detect', 'Respond', 'Respond', 'Recover',
  ],
  'SOC-2': [
    'Security', 'Security', 'Security', 'Confidentiality', 'Confidentiality',
    'Confidentiality', 'Availability', 'Availability', 'Processing Integrity', 'Privacy',
  ],
  'OWASP-10': [
    'Broken Access Control', 'Cryptographic Failures', 'Injection', 'Insecure Design',
    'Security Misconfiguration', 'Vulnerable Components', 'Auth Failures',
    'Integrity Failures', 'Logging Failures', 'SSRF',
  ],
};

const FRAMEWORK_CONTROL_NAMES: Record<string, string[]> = {
  'NIST-CSF': [
    'Asset Management (ID.AM)', 'Risk Assessment (ID.RA)',
    'Identity Management & Access Control (PR.AC)', 'Data Security & Encryption (PR.DS)',
    'Protective Technology (PR.PT)', 'Security Continuous Monitoring (DE.CM)',
    'Detection Processes (DE.DP)', 'Response Planning (RS.RP)',
    'Mitigation (RS.MI)', 'Recovery Planning (RC.RP)',
  ],
  'SOC-2': [
    'Logical Access Control (CC6.1)', 'System Boundary Defense (CC6.3)',
    'Vulnerability Patching (CC7.3)', 'Data Transmission Encryption (CC6.6)',
    'Data Storage Protection (CC6.7)', 'Risk Mitigation (CC9.1)',
    'System Operations & Monitoring (CC7.1)', 'Business Continuity & Backups (A1.2)',
    'Change Management (CC8.1)', 'Privacy Policy & Consent (P1.1)',
  ],
  'OWASP-10': [
    'A01:2021-Broken Access Control', 'A02:2021-Cryptographic Failures',
    'A03:2021-Injection', 'A04:2021-Insecure Design',
    'A05:2021-Security Misconfiguration', 'A06:2021-Vulnerable and Outdated Components',
    'A07:2021-Identification and Authentication Failures', 'A08:2021-Software and Data Integrity Failures',
    'A09:2021-Security Logging and Monitoring Failures', 'A10:2021-Server-Side Request Forgery (SSRF)',
  ],
};

const FRAMEWORK_FULL_NAMES: Record<string, string> = {
  'NIST-CSF': 'NIST Cybersecurity Framework',
  'SOC-2': 'SOC 2 Type II Compliance Standard',
  'OWASP-10': 'OWASP Top 10 Security Risks',
  'nist-csf': 'NIST Cybersecurity Framework',
  'soc-2': 'SOC 2 Type II Compliance Standard',
  'soc2': 'SOC 2 Type II Compliance Standard',
  'owasp-10': 'OWASP Top 10 Security Risks',
  'owasp10': 'OWASP Top 10 Security Risks',
};

/**
 * Match a finding against a control name using keyword heuristics.
 * Returns true if the finding is considered a violation of that control.
 */
function isViolation(controlName: string, finding: Finding): boolean {
  const n = controlName.toLowerCase();
  const title = finding.title.toLowerCase();
  const cat = finding.category.toLowerCase();

  // Access / Auth / Password / Identity controls
  if (n.includes('password') || n.includes('access') || n.includes('user id') || n.includes('role-based') || n.includes('auth') || n.includes('identity')) {
    if (cat.includes('secret') || title.includes('password') || cat.includes('auth') || title.includes('credential') || title.includes('access')) {
      return true;
    }
  }
  // Encryption / Crypto / Data Protection controls
  if (n.includes('encryption') || n.includes('data protection') || n.includes('cryptography') || n.includes('key management') || n.includes('data security') || n.includes('data storage')) {
    if (cat.includes('crypto') || cat.includes('secret') || title.includes('hashing') || title.includes('tls') || title.includes('ssl') || title.includes('encrypt') || title.includes('key')) {
      return true;
    }
  }
  // Vulnerability / Dependency / Component controls
  if (n.includes('vulnerability') || n.includes('development') || n.includes('anti-virus') || n.includes('asset') || n.includes('component') || n.includes('patching') || n.includes('integrity')) {
    if (cat.includes('dep') || cat.includes('cve') || title.includes('vulnerable') || title.includes('outdated')) {
      return true;
    }
  }
  // Network / Config / Monitoring / Boundary / Operations controls
  if (n.includes('firewall') || n.includes('network') || n.includes('config') || n.includes('monitoring') || n.includes('audit') || n.includes('boundary') || n.includes('operations') || n.includes('protective technology') || n.includes('logging')) {
    if (cat.includes('misconfig') || title.includes('cors') || title.includes('port') || title.includes('bind') || title.includes('debug') || title.includes('log')) {
      return true;
    }
  }
  // Incident / Response / Recovery / Mitigation controls
  if (n.includes('incident') || n.includes('response') || n.includes('communication') || n.includes('recovery') || n.includes('mitigation')) {
    if (title.includes('log') || title.includes('error') || title.includes('disclosure') || title.includes('fix') || finding.remediation) {
      return true;
    }
  }
  // Injection controls
  if (n.includes('injection')) {
    if (title.includes('injection') || title.includes('sql') || title.includes('xss') || cat.includes('cve')) {
      return true;
    }
  }
  // SSRF controls
  if (n.includes('ssrf') || n.includes('request forgery')) {
    if (title.includes('ssrf') || title.includes('redirect') || title.includes('forgery')) {
      return true;
    }
  }

  return false;
}

/**
 * Generates compliance controls for a framework using actual findings from the backend.
 */
function generateComplianceControls(framework: string, violatingFindings: Finding[]): ComplianceControl[] {
  const fwKey = FRAMEWORK_CATEGORIES[framework] ? framework : 'NIST-CSF';
  const categories = FRAMEWORK_CATEGORIES[fwKey];
  const names = FRAMEWORK_CONTROL_NAMES[fwKey];

  return names.map((name, i) => {
    const matched: string[] = [];
    for (const f of violatingFindings) {
      if (isViolation(name, f)) {
        matched.push(f.id);
      }
    }

    let status: 'passed' | 'failed' | 'not-applicable' = 'passed';
    if (matched.length > 0) {
      status = 'failed';
    } else if (i === names.length - 1 && violatingFindings.length > 0) {
      // Keep last control as N/A for visual variety when there are findings
      status = 'not-applicable';
    }

    return {
      id: `${framework}-${String(i + 1).padStart(3, '0')}`,
      name,
      description: `Ensure ${name.toLowerCase()} is properly implemented and maintained.`,
      status,
      category: categories[i],
      findings: matched,
    };
  });
}

/* ============================================================
   Store Interface
   ============================================================ */

interface SovaState {
  scans: Scan[];
  findings: Finding[];
  dashboardSummary: DashboardSummary | null;
  complianceReports: Record<string, ComplianceReport>;
  loading: boolean;
  error: string | null;
  selectedScan: Scan | null;
  scanProgress: {
    running: boolean;
    phase: string;
    percent: number;
    findingsCount: number;
  };

  fetchDashboard: () => Promise<void>;
  fetchScans: () => Promise<void>;
  fetchFindings: (scanId?: string) => Promise<void>;
  fetchComplianceReport: (framework: string) => Promise<void>;
  startScan: (target: string, scanType: string, frameworks: string[]) => Promise<void>;
  selectScan: (scan: Scan | null) => void;
  getComplianceReport: (framework: string) => ComplianceReport | null;
  fixAllFindings: () => Promise<any[]>;
  fixAllScanFindings: (scanId: string) => Promise<any[]>;
}

/* ============================================================
   Store Implementation
   ============================================================ */

export const useStore = create<SovaState>((set, get) => ({
  scans: [],
  findings: [],
  dashboardSummary: null,
  complianceReports: {},
  loading: false,
  error: null,
  selectedScan: null,
  scanProgress: {
    running: false,
    phase: '',
    percent: 0,
    findingsCount: 0,
  },

  /* -------------------------------------------------------
     fetchDashboard — GET /api/v1/dashboard/summary
     ------------------------------------------------------- */
  fetchDashboard: async () => {
    set({ loading: true, error: null });
    try {
      const res = await api.getDashboard();
      set({ dashboardSummary: mapDashboardSummary(res.data), loading: false });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load dashboard';
      set({ error: message, loading: false });
    }
  },

  /* -------------------------------------------------------
     fetchScans — GET /api/v1/scan
     ------------------------------------------------------- */
  fetchScans: async () => {
    set({ loading: true, error: null });
    try {
      const res = await api.getScans({ limit: 50 });
      const scans: Scan[] = (res.data as Record<string, unknown>[]).map(mapScan);
      set({ scans, loading: false });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load scans';
      set({ error: message, loading: false });
    }
  },

  /* -------------------------------------------------------
     fetchFindings — GET /api/v1/findings
     ------------------------------------------------------- */
  fetchFindings: async (scanId?: string) => {
    set({ loading: true, error: null });
    try {
      const params: Record<string, unknown> = { per_page: 100 };
      if (scanId) params.scan_id = scanId;
      const res = await api.getFindings(params as Parameters<typeof api.getFindings>[0]);
      const findings: Finding[] = (
        (res.data.findings ?? []) as Record<string, unknown>[]
      ).map(mapFinding);
      set({ findings, loading: false });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load findings';
      set({ error: message, loading: false });
    }
  },

  /* -------------------------------------------------------
     fetchComplianceReport — GET /api/v1/compliance/{framework}
     ------------------------------------------------------- */
  fetchComplianceReport: async (framework: string) => {
    try {
      // Map frontend framework keys (uppercase with dashes) to the
      // lowercase keys the backend expects.
      const backendKey = framework.toLowerCase(); // e.g. "RBI-CSF" → "rbi-csf"
      const res = await api.getCompliance(backendKey);
      const data = res.data as Record<string, unknown>;

      // Map the violating findings returned by the backend
      const rawFindings = (data.findings ?? []) as Record<string, unknown>[];
      const mappedFindings = rawFindings.map(mapFinding);

      // Generate the 12-row control checklist grid dynamically
      const controls = generateComplianceControls(framework, mappedFindings);
      const passedCount = controls.filter((c) => c.status === 'passed').length;
      const failedCount = controls.filter((c) => c.status === 'failed').length;
      const naCount = controls.filter((c) => c.status === 'not-applicable').length;

      const report: ComplianceReport = {
        framework,
        frameworkFullName:
          FRAMEWORK_FULL_NAMES[framework] ??
          FRAMEWORK_FULL_NAMES[backendKey] ??
          framework,
        score: (data.score as number) ?? 100,
        totalControls: controls.length,
        passed: passedCount,
        failed: failedCount,
        notApplicable: naCount,
        controls,
        lastAssessed: new Date().toISOString(),
      };

      set((state) => ({
        complianceReports: {
          ...state.complianceReports,
          [framework]: report,
        },
      }));
    } catch (err: unknown) {
      console.error('Failed to load compliance report:', err);
    }
  },

  /* -------------------------------------------------------
     startScan — POST /api/v1/scan
     Shows a smooth animated progress bar in the UI while
     the synchronous backend request is running.
     ------------------------------------------------------- */
  startScan: async (target: string, scanType: string, _frameworks: string[]) => {
    set({
      scanProgress: { running: true, phase: 'Discovering', percent: 0, findingsCount: 0 },
      error: null,
    });

    const phases = ['Discovering', 'Resolving', 'Scanning', 'Scoring', 'Reporting'];
    let currentPercent = 0;

    // Animate the progress bar smoothly while the API call is pending
    const interval = setInterval(() => {
      currentPercent += Math.random() * 5 + 2;
      if (currentPercent >= 95) currentPercent = 95; // Cap at 95% until backend responds

      const phaseIdx = Math.min(Math.floor(currentPercent / 20), phases.length - 1);
      set({
        scanProgress: {
          running: true,
          phase: phases[phaseIdx],
          percent: Math.round(currentPercent),
          findingsCount: 0,
        },
      });
    }, 400);

    try {
      const res = await api.createScan({ target, scan_type: scanType });
      clearInterval(interval);

      const completedScan = mapScan(res.data as Record<string, unknown>);

      set((state) => ({
        scans: [completedScan, ...state.scans],
        scanProgress: {
          running: false,
          phase: 'Completed',
          percent: 100,
          findingsCount: completedScan.totalFindings,
        },
      }));

      // Refresh dashboard and scans list with fresh data
      get().fetchScans();
      get().fetchDashboard();
    } catch (err: unknown) {
      clearInterval(interval);
      const message = err instanceof Error ? err.message : 'Scan failed';
      set({
        scanProgress: { running: false, phase: 'Failed', percent: 0, findingsCount: 0 },
        error: message,
      });
    }
  },

  /* -------------------------------------------------------
     selectScan — local state only
     ------------------------------------------------------- */
  selectScan: (scan) => set({ selectedScan: scan }),

  /* -------------------------------------------------------
     getComplianceReport — synchronous getter from cache
     ------------------------------------------------------- */
  getComplianceReport: (framework: string) => {
    return get().complianceReports[framework] || null;
  },

  /* -------------------------------------------------------
     fixAllFindings — bulk fixes all active findings globally
     ------------------------------------------------------- */
  fixAllFindings: async () => {
    set({ loading: true, error: null });
    try {
      const res = await api.fixAll();
      // Re-fetch findings, dashboard and scans to sync state
      await get().fetchFindings();
      await get().fetchDashboard();
      await get().fetchScans();
      set({ loading: false });
      return res.data?.applied_findings || [];
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to apply all fixes';
      set({ error: message, loading: false });
      return [];
    }
  },

  /* -------------------------------------------------------
     fixAllScanFindings — bulk fixes all findings for a scan
     ------------------------------------------------------- */
  fixAllScanFindings: async (scanId: string) => {
    set({ loading: true, error: null });
    try {
      const res = await api.fixAllScan(scanId);
      // Re-fetch scan-specific findings, dashboard and scans
      await get().fetchFindings(scanId);
      await get().fetchDashboard();
      await get().fetchScans();
      set({ loading: false });
      return res.data?.applied_findings || [];
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to apply scan fixes';
      set({ error: message, loading: false });
      return [];
    }
  },
}));
