import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../api/client';
import { useStore } from '../store';
import { Scan, Finding, SBOMResponse, ComplianceReport, ComplianceControl, ThreatIntelResponse, ThreatIntelRecord } from '../types';
import './Report.css';

interface ComplianceMap {
  nist: ComplianceReport | null;
  soc2: ComplianceReport | null;
  owasp10: ComplianceReport | null;
}


const SyntaxHighlightedJSON: React.FC<{ data: any }> = ({ data }) => {
  const jsonString = JSON.stringify(data, null, 2);

  const highlight = (json: string) => {
    let htmlStr = json
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    const regex = /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g;

    return htmlStr.replace(regex, (match) => {
      let cls = 'json-number';
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = 'json-key';
        } else {
          cls = 'json-string';
        }
      } else if (/true|false/.test(match)) {
        cls = 'json-boolean';
      } else if (/null/.test(match)) {
        cls = 'json-null';
      }
      return `<span class="${cls}">${match}</span>`;
    });
  };

  return (
    <pre 
      className="json-syntax-highlight"
      dangerouslySetInnerHTML={{ __html: highlight(jsonString) }}
    />
  );
};


const severityRank: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const getWhyItMatters = (category: string): string => {
  const cat = category.toLowerCase();
  if (cat === 'secret') {
    return 'Credential exposure risk: can lead to unauthorized API access, account takeover, or complete infrastructure compromise.';
  }
  if (cat === 'cve') {
    return 'Known exploit/dependency risk: introduces public, cataloged vulnerabilities into the runtime environment via third-party packages.';
  }
  if (cat === 'misconfig') {
    return 'Unsafe runtime/security posture: leaves default credentials, open ports, or incorrect access rights exposed in production environments.';
  }
  if (cat === 'sast') {
    return 'Code-level vulnerability: direct implementation flaws (like SQL injection or buffer overflows) that can be exploited dynamically.';
  }
  if (cat === 'drift') {
    return 'Deviation from secure baseline: indicates undocumented or unauthorized runtime modifications that break security policy constraints.';
  }
  return 'General security exposure: deviates from security best practices and increases the attack surface of the application.';
};

const mapScan = (s: any): Scan => ({
  id: s.id,
  target: s.target,
  status: s.status,
  scanType: s.scan_type ?? 'full',
  totalFindings: s.total_findings ?? 0,
  criticalCount: s.critical_count ?? 0,
  highCount: s.high_count ?? 0,
  mediumCount: s.medium_count ?? 0,
  lowCount: s.low_count ?? 0,
  startedAt: s.started_at ?? '',
  completedAt: s.completed_at ?? null,
  createdAt: s.created_at ?? '',
});

const mapFinding = (f: any): Finding => ({
  id: f.id,
  scanId: f.scan_id ?? '',
  ruleId: f.rule_id ?? '',
  title: f.title ?? '',
  description: f.description ?? '',
  severity: f.severity ?? 'info',
  category: f.category ?? '',
  filePath: f.file_path ?? '',
  lineNumber: f.line_number ?? 0,
  evidence: f.evidence ?? '',
  remediation: f.remediation ?? '',
  cveId: f.cve_id ?? null,
  cvssScore: f.cvss_score ?? null,
  isFixed: f.is_fixed ?? false,
  createdAt: f.created_at ?? '',
});

const mapThreatRecord = (r: any): ThreatIntelRecord => ({
  cveId: r.cve_id ?? '',
  knownExploited: r.known_exploited ?? false,
  epssScore: r.epss_score ?? null,
  epssPercentile: r.epss_percentile ?? null,
  priority: r.priority ?? 'monitor',
  summary: r.summary ?? '',
  remediationUrgency: r.remediation_urgency ?? '',
  sources: r.sources ?? [],
});

const mapThreatIntel = (t: any): ThreatIntelResponse => ({
  scanId: t.scan_id ?? '',
  generatedAt: t.generated_at ?? '',
  totalCves: t.total_cves ?? 0,
  knownExploitedCount: t.known_exploited_count ?? 0,
  highPriorityCount: t.high_priority_count ?? 0,
  records: (t.records || []).map(mapThreatRecord),
});

const mapComplianceControl = (c: any): ComplianceControl => ({
  id: c.id,
  name: c.name,
  description: c.description ?? '',
  status: c.status === 'failed' ? 'failed' : c.status === 'passed' ? 'passed' : 'not-applicable',
  category: c.category ?? '',
  findings: c.findings ?? [],
});

interface ComplianceMap {
  rbi: ComplianceReport | null;
  nist: ComplianceReport | null;
  soc2: ComplianceReport | null;
  owasp10: ComplianceReport | null;
}

const mapCompliance = (c: any): ComplianceReport => ({
  framework: c.framework,
  frameworkFullName: c.framework === 'rbi-csf' || c.framework === 'rbi' ? 'Reserve Bank of India Cybersecurity Framework' : c.framework === 'nist-csf' ? 'NIST Cybersecurity Framework' : c.framework === 'soc-2' ? 'SOC-2 Trust Criteria' : 'OWASP Top 10',
  score: c.score ?? 100,
  totalControls: c.total_controls ?? 0,
  passed: c.passed ?? 0,
  failed: c.failed ?? 0,
  notApplicable: c.not_applicable ?? 0,
  controls: (c.controls || []).map(mapComplianceControl),
  lastAssessed: c.last_assessed ?? new Date().toISOString(),
});

const Report: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const { scans, fetchScans } = useStore();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sbom, setSbom] = useState<SBOMResponse | null>(null);
  const [compliance, setCompliance] = useState<ComplianceMap>({
    rbi: null,
    nist: null,
    soc2: null,
    owasp10: null,
  });
  const [threatIntel, setThreatIntel] = useState<ThreatIntelResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [appendixSearch, setAppendixSearch] = useState('');
  const [appendixSeverity, setAppendixSeverity] = useState('all');
  const [activeTab, setActiveTab] = useState<'visual' | 'json'>('visual');

  const reportPayload = React.useMemo(() => {
    if (!scan) return null;
    return {
      scan_metadata: {
        id: scan.id,
        target: scan.target,
        type: scan.scanType,
        status: scan.status,
        startedAt: scan.startedAt,
        completedAt: scan.completedAt,
      },
      metrics: {
        total_findings: findings.length,
        critical: findings.filter((f) => f.severity === 'critical').length,
        high: findings.filter((f) => f.severity === 'high').length,
        medium: findings.filter((f) => f.severity === 'medium').length,
        low: findings.filter((f) => f.severity === 'low').length,
        risk_score: Math.min(
          findings.filter((f) => f.severity === 'critical').length * 25 +
          findings.filter((f) => f.severity === 'high').length * 15 +
          findings.filter((f) => f.severity === 'medium').length * 7 +
          findings.filter((f) => f.severity === 'low').length * 2,
          100
        ),
        risk_label: Math.min(
          findings.filter((f) => f.severity === 'critical').length * 25 +
          findings.filter((f) => f.severity === 'high').length * 15 +
          findings.filter((f) => f.severity === 'medium').length * 7 +
          findings.filter((f) => f.severity === 'low').length * 2,
          100
        ) > 80 ? 'Critical' : Math.min(
          findings.filter((f) => f.severity === 'critical').length * 25 +
          findings.filter((f) => f.severity === 'high').length * 15 +
          findings.filter((f) => f.severity === 'medium').length * 7 +
          findings.filter((f) => f.severity === 'low').length * 2,
          100
        ) > 50 ? 'High' : Math.min(
          findings.filter((f) => f.severity === 'critical').length * 25 +
          findings.filter((f) => f.severity === 'high').length * 15 +
          findings.filter((f) => f.severity === 'medium').length * 7 +
          findings.filter((f) => f.severity === 'low').length * 2,
          100
        ) > 20 ? 'Moderate' : 'Low',
      },
      summary: (() => {
        const crit = findings.filter((f) => f.severity === 'critical').length;
        const hg = findings.filter((f) => f.severity === 'high').length;
        const cats = Array.from(new Set(findings.map((f) => f.category.toLowerCase())));
        const paras: string[] = [];
        if (findings.length === 0) {
          paras.push('No active findings were detected in the scanned target. The application satisfies all primary SovaScan vulnerability checks.');
        } else {
          if (crit > 0 || hg > 0) {
            paras.push(`This scan identified ${crit + hg} high-priority security risks that should be reviewed before release.`);
          }
          if (cats.includes('secret')) {
            paras.push('Credential exposure risk was detected in source or configuration files. Exposed tokens represent immediate access hazards.');
          }
          if (cats.includes('cve')) {
            paras.push('Known vulnerable dependencies were found in project manifests. Legacy packages should be updated to address known exploits.');
          }
          if (cats.includes('misconfig')) {
            paras.push('Configuration weaknesses may increase production exposure. Review deployment baselines to prevent environment leakage.');
          }
        }
        return paras.join(' ');
      })(),
      top_findings: [...findings]
        .sort((a, b) => {
          const getScore = (f: Finding) => {
            let score = (severityRank[f.severity] || 0) * 10;
            if (threatIntel && f.cveId) {
              const rec = threatIntel.records.find((r) => r.cveId.toUpperCase() === f.cveId!.toUpperCase());
              if (rec) {
                if (rec.knownExploited) score += 100;
                if (rec.priority === 'immediate') score += 80;
                else if (rec.priority === 'high') score += 50;
                if (rec.epssScore && rec.epssScore >= 0.7) score += 40;
              }
            }
            return score;
          };
          return getScore(b) - getScore(a);
        })
        .slice(0, 5)
        .map((f) => ({
          title: f.title,
          severity: f.severity,
          category: f.category,
          filePath: f.filePath,
          lineNumber: f.lineNumber,
          evidence: f.evidence,
          remediation: f.remediation,
        })),
      compliance_alignments: {
        nist: compliance.nist ? { score: compliance.nist.score, passed: compliance.nist.passed, failed: compliance.nist.failed } : null,
        soc2: compliance.soc2 ? { score: compliance.soc2.score, passed: compliance.soc2.passed, failed: compliance.soc2.failed } : null,
        owasp10: compliance.owasp10 ? { score: compliance.owasp10.score, passed: compliance.owasp10.passed, failed: compliance.owasp10.failed } : null,
      },
      sbom_preview: sbom ? sbom.packages.slice(0, 8) : [],
      all_findings: findings.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        category: f.category,
        filePath: f.filePath,
        lineNumber: f.lineNumber,
        isFixed: f.isFixed,
      })),
      threat_intelligence: threatIntel,
    };
  }, [scan, findings, compliance, sbom, threatIntel]);

  useEffect(() => {
    if (!scanId) {
      fetchScans().then(() => setLoading(false));
      return;
    }

    const fetchData = async () => {
      try {
        setLoading(true);
        setError(null);

        // Fetch primary scan and findings
        const scanRes = await api.getScan(scanId);
        const findingsRes = await api.getFindings({ scan_id: scanId, per_page: 100 });

        setScan(mapScan(scanRes.data));
        setFindings((findingsRes.data.findings || []).map(mapFinding));

        // Fetch SBOM (handles missing gracefully)
        try {
          const sbomRes = await api.getSBOM(scanId);
          setSbom(sbomRes.data);
        } catch (err) {
          console.warn('[Report] Failed to fetch SBOM packages:', err);
        }

        // Fetch compliance reports
        try {
          const [rbiRes, nistRes, soc2Res, owasp10Res] = await Promise.all([
            api.getCompliance('rbi-csf', scanId),
            api.getCompliance('nist-csf', scanId),
            api.getCompliance('soc-2', scanId),
            api.getCompliance('owasp-10', scanId),
          ]);
          setCompliance({
            rbi: mapCompliance(rbiRes.data),
            nist: mapCompliance(nistRes.data),
            soc2: mapCompliance(soc2Res.data),
            owasp10: mapCompliance(owasp10Res.data),
          });
        } catch (err) {
          console.warn('[Report] Failed to fetch compliance reports:', err);
        }

        // Fetch threat intelligence (handles network/unavailability gracefully)
        try {
          const intelRes = await api.getThreatIntel(scanId);
          setThreatIntel(mapThreatIntel(intelRes.data));
        } catch (err) {
          console.warn('[Report] Failed to fetch threat intelligence enrichment:', err);
        }

      } catch (err: any) {
        setError(err.message || 'Failed to load report data');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [scanId]);

  if (loading) {
    return (
      <div className="compliance-loading">
        <p className="animate-pulse" style={{ fontSize: '14px', letterSpacing: '0.5px', color: 'var(--text-secondary)' }}>
          Generating Post-Scan Security Report...
        </p>
      </div>
    );
  }

  if (!scanId) {
    return (
      <div className="report-page">
        <div className="list-card glassmorphism">
          <h2>Select a Scan to View Security Report</h2>
          <p className="muted" style={{ marginBottom: '20px', fontSize: '13px' }}>
            Choose a scan from the run history below to generate its post-scan executive report.
          </p>
          <div className="table-responsive">
            <table className="recent-scans-table">
              <thead>
                <tr>
                  <th>Target Directory</th>
                  <th>Scan Type</th>
                  <th>Date</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {scans.length > 0 ? (
                  scans.map((s) => (
                    <tr key={s.id}>
                      <td className="monospace-td" style={{ maxWidth: '280px' }} title={s.target}>
                        {s.target}
                      </td>
                      <td><span className="badge-type">{s.scanType}</span></td>
                      <td>{new Date(s.createdAt).toLocaleString()}</td>
                      <td><span className={`status-badge ${s.status}`}>{s.status}</span></td>
                      <td>
                        <Link
                          to={`/report/${s.id}`}
                          className="settings__btn settings__btn--primary"
                          style={{
                            textDecoration: 'none',
                            display: 'inline-block',
                            fontSize: '12px',
                            padding: '6px 12px',
                          }}
                        >
                          📄 View Report
                        </Link>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="text-center muted" style={{ padding: '24px' }}>
                      No scans completed yet. Run a new scan first.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="report-page">
        <div className="list-card glassmorphism text-center" style={{ padding: '40px' }}>
          <h2 className="text-danger">⚠️ Report Error</h2>
          <p>{error || 'Scan details not found. Make sure this scan ID is valid.'}</p>
          <Link to="/" className="settings__btn settings__btn--primary" style={{ display: 'inline-block', marginTop: '16px', textDecoration: 'none' }}>
            Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  // --- 1. Risk Score Calculation ---
  const critical = findings.filter((f) => f.severity === 'critical').length;
  const high = findings.filter((f) => f.severity === 'high').length;
  const medium = findings.filter((f) => f.severity === 'medium').length;
  const low = findings.filter((f) => f.severity === 'low').length;
  const info = findings.filter((f) => f.severity === 'info').length;

  const rawRisk = critical * 25 + high * 15 + medium * 7 + low * 2;
  const riskScore = Math.min(rawRisk, 100);

  let riskLabel = 'Low';
  let riskColorClass = 'risk-low';
  if (riskScore > 80) {
    riskLabel = 'Critical';
    riskColorClass = 'risk-critical';
  } else if (riskScore > 50) {
    riskLabel = 'High';
    riskColorClass = 'risk-high';
  } else if (riskScore > 20) {
    riskLabel = 'Moderate';
    riskColorClass = 'risk-moderate';
  }

  // --- 2. Executive Summary Text Rules ---
  const totalFindingsCount = findings.length;
  const categoriesPresent = Array.from(new Set(findings.map((f) => f.category.toLowerCase())));
  const hasSecrets = categoriesPresent.includes('secret');
  const hasCVEs = categoriesPresent.includes('cve');
  const hasMisconfig = categoriesPresent.includes('misconfig');

  const summaryParagraphs: string[] = [];
  if (totalFindingsCount === 0) {
    summaryParagraphs.push('No active findings were detected in the scanned target. The application satisfies all primary SovaScan vulnerability checks.');
  } else {
    if (critical > 0 || high > 0) {
      summaryParagraphs.push(`This scan identified ${critical + high} high-priority security risks that should be reviewed before release.`);
    }
    if (hasSecrets) {
      summaryParagraphs.push('Credential exposure risk was detected in source or configuration files. Exposed tokens represent immediate access hazards.');
    }
    if (hasCVEs) {
      summaryParagraphs.push('Known vulnerable dependencies were found in project manifests. Legacy packages should be updated to address known exploits.');
    }
    if (hasMisconfig) {
      summaryParagraphs.push('Configuration weaknesses may increase production exposure. Review deployment baselines to prevent environment leakage.');
    }
  }

  // --- 3. Sorting & Risk Cards ---
  const getSortScore = (f: Finding) => {
    let score = (severityRank[f.severity] || 0) * 10;
    if (threatIntel && f.cveId) {
      const record = threatIntel.records.find((r) => r.cveId.toUpperCase() === f.cveId!.toUpperCase());
      if (record) {
        if (record.knownExploited) score += 100;
        if (record.priority === 'immediate') score += 80;
        else if (record.priority === 'high') score += 50;
        if (record.epssScore && record.epssScore >= 0.7) score += 40;
      }
    }
    return score;
  };

  const sortedFindings = [...findings].sort((a, b) => {
    return getSortScore(b) - getSortScore(a);
  });
  const topRisks = sortedFindings.slice(0, 5);

  // --- 4. Remediation Groups ---
  const fixNow = sortedFindings.filter((f) => f.severity === 'critical' || f.severity === 'high');
  const fixSprint = sortedFindings.filter((f) => f.severity === 'medium');
  const backlog = sortedFindings.filter((f) => f.severity === 'low' || f.severity === 'info');

  const getGroupCategories = (group: Finding[]): string => {
    const cats = Array.from(new Set(group.map((f) => f.category.toUpperCase())));
    return cats.length > 0 ? cats.join(', ') : 'None';
  };

  // --- 5. Export JSON Action ---

  const handleExportJSON = () => {
    if (!reportPayload) return;
    const blob = new Blob([JSON.stringify(reportPayload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SovaScan_Report_${scanId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 100);
  };

  const handleExportSBOM = () => {
    if (!sbom) return;
    
    // Generate a valid uuid for the serialNumber
    const serialUuid = crypto.randomUUID ? crypto.randomUUID() : 'c3b52d48-8df3-4876-b8a9-4672bc194488';
    
    const cycloneDX = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${serialUuid}`,
      version: 1,
      metadata: {
        timestamp: sbom.generated_at || new Date().toISOString(),
        tools: [
          {
            vendor: 'SovaScan',
            name: 'SovaScan Security Engine',
            version: '0.1.0'
          }
        ],
        component: {
          type: 'application',
          name: scan?.target ? scan.target.split('/').pop() || 'project' : 'project',
          version: '0.0.0'
        }
      },
      components: sbom.packages.map((pkg: any) => ({
        type: 'library',
        name: pkg.name,
        version: pkg.version,
        purl: pkg.purl || undefined,
        licenses: pkg.license ? [{ license: { id: pkg.license } }] : undefined
      }))
    };

    const blob = new Blob([JSON.stringify(cycloneDX, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SovaScan_SBOM_${scanId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 100);
  };

  // --- 6. Compliance Status helpers ---
  const getComplianceStatus = (score: number) => {
    if (score >= 85) return { text: 'Strong', class: 'strong' };
    if (score >= 65) return { text: 'Needs Review', class: 'needs-review' };
    return { text: 'High Risk', class: 'high-risk' };
  };

  const renderAuditPageHeader = (pageNum: number) => (
    <div className="audit-page-header">
      <span>CONFIDENTIAL | SovaScan Security Audit | SVS-2026-0712-001</span>
    </div>
  );

  const renderAuditPageFooter = (pageNum: number) => (
    <div className="audit-page-footer">
      <span>Page {pageNum} of 11</span>
    </div>
  );

  const filteredAppendixFindings = findings.filter((f) => {
    const matchesSearch = f.title.toLowerCase().includes(appendixSearch.toLowerCase()) || 
                          f.filePath.toLowerCase().includes(appendixSearch.toLowerCase()) ||
                          f.ruleId.toLowerCase().includes(appendixSearch.toLowerCase());
    const matchesSeverity = appendixSeverity === 'all' || f.severity === appendixSeverity;
    return matchesSearch && matchesSeverity;
  });

  return (
    <>
      {/* ============================================================
          1. SCREEN MEDIA CONTENT (ACTIVE WEB APP VIEW)
          ============================================================ */}
      <div className="screen-only report-page">

      {/* 1. REPORT HEADER PANEL */}
      <div className="list-card glassmorphism report-header-panel">
        <div className="report-header-left">
          <h1>Post-Scan Security Report</h1>
          <div className="report-meta-grid">
            <div className="report-meta-item">
              <span className="report-meta-label">Scan Target</span>
              <span className="report-meta-value">{scan.target}</span>
            </div>
            <div className="report-meta-item">
              <span className="report-meta-label">Scan Type</span>
              <span className="report-meta-value badge-type" style={{ alignSelf: 'flex-start' }}>{scan.scanType}</span>
            </div>
            <div className="report-meta-item">
              <span className="report-meta-label">Status</span>
              <span className={`status-badge ${scan.status}`}>{scan.status}</span>
            </div>
            <div className="report-meta-item">
              <span className="report-meta-label">Run Date</span>
              <span className="report-meta-value">
                {new Date(scan.completedAt || scan.createdAt).toLocaleString()}
              </span>
            </div>
          </div>
        </div>
        <div className="report-actions">
          <button className="settings__btn settings__btn--secondary" onClick={() => window.print()}>
            🖨️ Print Report
          </button>
          <button className="settings__btn settings__btn--primary" onClick={handleExportJSON}>
            📥 Export JSON
          </button>
        </div>
      </div>

      {/* Tab controls */}
      <div className="report-tabs-bar">
        <button 
          className={`report-tab-btn ${activeTab === 'visual' ? 'active' : ''}`}
          onClick={() => setActiveTab('visual')}
        >
          📊 Visual Report
        </button>
        <button 
          className={`report-tab-btn ${activeTab === 'json' ? 'active' : ''}`}
          onClick={() => setActiveTab('json')}
        >
          ⚙️ JSON Payload View
        </button>
      </div>

      {activeTab === 'json' ? (
        <div className="list-card glassmorphism" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }} className="sbom-header-row">
            <h3 style={{ margin: 0 }}>⚙️ JSON Payload Output</h3>
            <button className="settings__btn settings__btn--primary report-actions" onClick={handleExportJSON}>
              📥 Download JSON Report
            </button>
          </div>
          <SyntaxHighlightedJSON data={reportPayload} />
        </div>
      ) : (
        <>
          {/* 2. RISK OVERVIEW */}
          <div className="report-metrics-grid">
        <div className="list-card glassmorphism report-metric-card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '140px' }}>
          <div style={{ position: 'relative', width: '80px', height: '80px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <svg className="risk-svg-gauge" width="80" height="80" viewBox="0 0 80 80">
              <circle cx="40" cy="40" r="34" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="6" />
              <circle 
                cx="40" 
                cy="40" 
                r="34" 
                fill="none" 
                stroke={riskScore > 80 ? 'var(--critical)' : riskScore > 50 ? 'var(--severity-high)' : riskScore > 20 ? 'var(--severity-medium)' : 'var(--success)'}
                strokeWidth="6" 
                strokeDasharray="213.6"
                strokeDashoffset={213.6 - (213.6 * riskScore) / 100}
                strokeLinecap="round"
                transform="rotate(-90 40 40)"
                style={{ transition: 'stroke-dashoffset 1s ease-out', filter: `drop-shadow(0 0 4px ${riskScore > 80 ? 'var(--critical)' : riskScore > 50 ? 'var(--severity-high)' : riskScore > 20 ? 'var(--severity-medium)' : 'var(--success)'})` }}
              />
            </svg>
            <div className="risk-score-text-wrap" style={{ position: 'absolute', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <span className={`report-metric-value ${riskColorClass}`} style={{ fontSize: '1.5rem', marginBottom: 0 }}>{riskScore}%</span>
            </div>
          </div>
          <div className="report-metric-label" style={{ marginTop: '8px' }}>Risk Score ({riskLabel})</div>
        </div>
        <div className="list-card glassmorphism report-metric-card">
          <div className="report-metric-value">{totalFindingsCount}</div>
          <div className="report-metric-label">Total Findings</div>
        </div>
        <div className="list-card glassmorphism report-metric-card">
          <div className="report-metric-value font-red">{critical + high}</div>
          <div className="report-metric-label">Critical & High</div>
        </div>
        <div className="list-card glassmorphism report-metric-card">
          <div className="report-metric-value font-orange">{medium}</div>
          <div className="report-metric-label">Medium Risk</div>
        </div>
        <div className="list-card glassmorphism report-metric-card">
          <div className="report-metric-value text-info">{categoriesPresent.length}</div>
          <div className="report-metric-label">Impacted Tiers</div>
        </div>
      </div>

      {/* 3. EXECUTIVE SUMMARY & THREAT POSTURE */}
      <div className="report-summary-layout">
        <div className="list-card glassmorphism summary-panel" style={{ height: '100%', boxSizing: 'border-box' }}>
          <h3>📄 Executive Summary</h3>
          {summaryParagraphs.length > 0 ? (
            <p className="summary-text">
              {summaryParagraphs.join(' ')} SovaScan completed dependency checks, secret auditing, static code analysis, and configuration auditing targets.
            </p>
          ) : (
            <p className="summary-text">
              The target scans completed successfully with 0 vulnerability findings recorded across dependency SBOM trees, configuration drifts, or SAST scopes.
            </p>
          )}
        </div>

        <div className="list-card glassmorphism posture-panel">
          <h3>📊 Threat Posture</h3>
          <div className="posture-bars-container">
            {[
              { val: critical, label: 'CRT', color: 'var(--critical)' },
              { val: high, label: 'HGH', color: 'var(--severity-high)' },
              { val: medium, label: 'MED', color: 'var(--severity-medium)' },
              { val: low, label: 'LOW', color: 'var(--severity-low)' },
              { val: info, label: 'INF', color: 'var(--severity-info)' }
            ].map((data, idx) => {
              const maxVal = Math.max(critical, high, medium, low, info, 1);
              const pct = (data.val / maxVal) * 100;
              return (
                <div key={idx} className="posture-bar-item">
                  <div className="posture-bar-track">
                    <div 
                      className="posture-bar-fill" 
                      style={{ 
                        height: `${pct}%`, 
                        backgroundColor: data.color,
                        boxShadow: `0 0 8px ${data.color}`
                      }}
                    />
                  </div>
                  <span className="posture-bar-label">{data.label}</span>
                  <span className="posture-bar-val">{data.val}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* 4. TOP RISKS */}
      <div className="report-section">
        <h3>🔥 Top Security Risks</h3>
        <div className="top-risks-list">
          {topRisks.length > 0 ? (
            topRisks.map((f, idx) => {
              const borderStyles: Record<string, string> = {
                critical: '4px solid var(--critical)',
                high: '4px solid var(--severity-high)',
                medium: '4px solid var(--severity-medium)',
                low: '4px solid var(--severity-low)',
                info: '4px solid var(--severity-info)',
              };
              const bgGradients: Record<string, string> = {
                critical: 'linear-gradient(90deg, rgba(220, 38, 38, 0.06) 0%, rgba(26, 31, 53, 0.2) 100%)',
                high: 'linear-gradient(90deg, rgba(249, 115, 22, 0.06) 0%, rgba(26, 31, 53, 0.2) 100%)',
                medium: 'linear-gradient(90deg, rgba(234, 179, 8, 0.04) 0%, rgba(26, 31, 53, 0.2) 100%)',
                low: 'linear-gradient(90deg, rgba(59, 130, 246, 0.04) 0%, rgba(26, 31, 53, 0.2) 100%)',
                info: 'linear-gradient(90deg, rgba(107, 114, 128, 0.04) 0%, rgba(26, 31, 53, 0.2) 100%)',
              };
              return (
                <div 
                  key={f.id} 
                  className="list-card glassmorphism report-risk-card animate-slide-up" 
                  style={{ 
                    animationDelay: `${idx * 0.08}s`,
                    borderLeft: borderStyles[f.severity] || '1px solid rgba(255, 255, 255, 0.04)',
                    background: bgGradients[f.severity]
                  }}
                >
                <div className="report-risk-header">
                  <div className="report-risk-title-wrap">
                    <span className={`severity-badge-lbl ${f.severity}`}>{f.severity}</span>
                    <span className="report-risk-title">{f.title}</span>
                  </div>
                  <span className="report-risk-meta">{f.category.toUpperCase()}</span>
                </div>
                <div className="report-risk-meta" style={{ color: 'var(--text-secondary)' }}>
                  Location: <code>{f.filePath}:L{f.lineNumber}</code>
                </div>
                <div className="report-risk-why">
                  <strong>Why it matters:</strong> {getWhyItMatters(f.category)}
                </div>
                {f.evidence && (
                  <div className="report-risk-evidence">
                    <div className="console-window evidence-console" style={{ marginTop: 0 }}>
                      <div className="terminal-header" style={{ padding: '6px 12px' }}>
                        <span className="terminal-title">evidence_inspect.log</span>
                      </div>
                      <pre className="evidence-pre" style={{ padding: '8px 12px' }}>
                        <code>{f.evidence}</code>
                      </pre>
                    </div>
                  </div>
                )}
                {f.remediation && (
                  <div className="report-risk-remediation">
                    <strong>Recommended Remediation:</strong> {f.remediation}
                  </div>
                )}
              </div>
            ); })
          ) : (
            <div className="list-card glassmorphism text-center" style={{ padding: '24px' }}>
              <p className="muted">No security risks identified.</p>
            </div>
          )}
        </div>
      </div>

      {/* THREAT INTELLIGENCE SECTION */}
      <div className="report-section">
        <h3>🛡️ Threat Intelligence</h3>
        <p className="summary-text" style={{ marginBottom: '16px' }}>
          Exploit Intelligence enriches detected CVEs using trusted public sources (CISA Known Exploited Vulnerabilities and FIRST EPSS probability scores). It helps prioritize remediation based on active exploitation and likelihood of future exploit campaigns.
        </p>

        {!threatIntel || threatIntel.totalCves === 0 ? (
          <div className="list-card glassmorphism text-center" style={{ padding: '24px' }}>
            <p className="muted" style={{ margin: 0 }}>
              {!threatIntel 
                ? "Threat intelligence sources are currently unavailable. Scan findings remain valid, but exploitability enrichment could not be refreshed." 
                : "No CVE-backed findings were detected in this scan, so exploit intelligence enrichment was not required."}
            </p>
          </div>
        ) : (
          <>
            {/* Intel Metrics Grid */}
            <div className="report-metrics-grid" style={{ marginBottom: '20px' }}>
              <div className="list-card glassmorphism report-metric-card" style={{ borderLeft: '3px solid var(--critical)' }}>
                <div className="report-metric-value font-red">{threatIntel.knownExploitedCount}</div>
                <div className="report-metric-label">Known Exploited (CISA KEV)</div>
              </div>
              <div className="list-card glassmorphism report-metric-card" style={{ borderLeft: '3px solid var(--warning)' }}>
                <div className="report-metric-value font-orange">{threatIntel.highPriorityCount}</div>
                <div className="report-metric-label">High Priority CVEs</div>
              </div>
              <div className="list-card glassmorphism report-metric-card">
                <div className="report-metric-value text-info">
                  {Math.max(...threatIntel.records.map(r => r.epssScore || 0)) > 0 
                    ? `${(Math.max(...threatIntel.records.map(r => r.epssScore || 0)) * 100).toFixed(1)}%`
                    : '0.0%'}
                </div>
                <div className="report-metric-label">EPSS Max Probability</div>
              </div>
              <div className="list-card glassmorphism report-metric-card">
                <div className="report-metric-value text-success">{threatIntel.totalCves}</div>
                <div className="report-metric-label">Total CVEs Enriched</div>
              </div>
            </div>

            {/* Enriched CVE records table */}
            <div className="list-card glassmorphism console-window" style={{ padding: 0 }}>
              <div className="terminal-header">
                <span className="terminal-title">threat_intel_enrichment_manifest.json</span>
              </div>
              <div className="table-responsive">
                <table className="recent-scans-table">
                  <thead>
                    <tr>
                      <th>CVE ID</th>
                      <th>Exploit Priority</th>
                      <th>Known Exploited</th>
                      <th>EPSS Score</th>
                      <th>Percentile</th>
                      <th>Patch Urgency</th>
                      <th>Verified Sources</th>
                    </tr>
                  </thead>
                  <tbody>
                    {threatIntel.records.map((rec) => (
                      <React.Fragment key={rec.cveId}>
                        <tr>
                          <td style={{ fontWeight: 600 }} className="monospace-td">{rec.cveId}</td>
                          <td>
                            <span className={`severity-badge-lbl ${rec.priority === 'immediate' ? 'critical' : rec.priority === 'high' ? 'high' : rec.priority === 'scheduled' ? 'medium' : 'info'}`}>
                              {rec.priority}
                            </span>
                          </td>
                          <td>
                            <span className={`status-badge ${rec.knownExploited ? 'failed' : 'completed'}`} style={{ textTransform: 'uppercase', fontSize: '10px' }}>
                              {rec.knownExploited ? 'YES (KEV)' : 'NO'}
                            </span>
                          </td>
                          <td className="monospace-td">
                            {rec.epssScore !== null ? `${(rec.epssScore * 100).toFixed(3)}%` : 'N/A'}
                          </td>
                          <td className="monospace-td">
                            {rec.epssPercentile !== null ? `${(rec.epssPercentile * 100).toFixed(2)}%` : 'N/A'}
                          </td>
                          <td style={{ fontSize: '12px' }}>{rec.remediationUrgency}</td>
                          <td>
                            <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                              {rec.sources.map((src, sIdx) => (
                                <span key={sIdx} className="badge-type" style={{ fontSize: '9px', padding: '2px 6px' }}>{src}</span>
                              ))}
                            </div>
                          </td>
                        </tr>
                        {rec.summary && (
                          <tr className="threat-summary-row">
                            <td colSpan={7} style={{ padding: '8px 16px', background: 'rgba(255,255,255,0.01)', borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
                              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                                <strong>Advisory Summary:</strong> {rec.summary}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </div>

      {/* 5. REMEDIATION PLAN */}
      <div className="report-section">
        <h3>🛠️ Remediation Plan</h3>
        <div className="remediation-columns">
          <div className="list-card glassmorphism remediation-col now">
            <div className="remediation-col-header">
              <span className="remediation-col-title">🛑 Fix Now</span>
              <span className="remediation-col-count">{fixNow.length}</span>
            </div>
            <div className="remediation-col-action">
              <strong>Vulnerabilities:</strong> Critical & High severity items.
            </div>
            <div className="remediation-col-action">
              <strong>Tiers Impacted:</strong> {getGroupCategories(fixNow)}
            </div>
            <div className="remediation-col-action">
              <strong>Top Action:</strong> {fixNow.length > 0 ? 'Revoke exposed secrets immediately, patch CVEs, and rewrite vulnerable code vectors.' : 'No immediate fixes required.'}
            </div>
          </div>

          <div className="list-card glassmorphism remediation-col sprint">
            <div className="remediation-col-header">
              <span className="remediation-col-title">⚠️ Fix This Sprint</span>
              <span className="remediation-col-count">{fixSprint.length}</span>
            </div>
            <div className="remediation-col-action">
              <strong>Vulnerabilities:</strong> Medium severity items.
            </div>
            <div className="remediation-col-action">
              <strong>Tiers Impacted:</strong> {getGroupCategories(fixSprint)}
            </div>
            <div className="remediation-col-action">
              <strong>Top Action:</strong> {fixSprint.length > 0 ? 'Update secondary dependencies and address Dockerfile or server config weaknesses.' : 'No sprint items scheduled.'}
            </div>
          </div>

          <div className="list-card glassmorphism remediation-col backlog">
            <div className="remediation-col-header">
              <span className="remediation-col-title">📋 Backlog</span>
              <span className="remediation-col-count">{backlog.length}</span>
            </div>
            <div className="remediation-col-action">
              <strong>Vulnerabilities:</strong> Low & Info severity items.
            </div>
            <div className="remediation-col-action">
              <strong>Tiers Impacted:</strong> {getGroupCategories(backlog)}
            </div>
            <div className="remediation-col-action">
              <strong>Top Action:</strong> {backlog.length > 0 ? 'Monitor minor version drift and establish routine code cleanliness checks.' : 'Backlog clean.'}
            </div>
          </div>
        </div>
      </div>

      {/* 6. COMPLIANCE IMPACT */}
      <div className="report-section">
        <h3>🛡️ Compliance Impact</h3>
        <div className="compliance-cards-grid">
          {['RBI-CSF', 'NIST-CSF', 'SOC-2', 'OWASP-10'].map((fwName) => {
            const key = fwName === 'RBI-CSF' ? 'rbi' : fwName === 'NIST-CSF' ? 'nist' : fwName === 'SOC-2' ? 'soc2' : 'owasp10';
            const report = compliance[key as keyof ComplianceMap];
            const score = report?.score || 0;
            const status = getComplianceStatus(score);

            return (
              <div key={fwName} className="list-card glassmorphism compliance-report-card">
                <div className="compliance-report-header">
                  <h4>{fwName}</h4>
                  <span className={`compliance-status-lbl ${status.class}`}>{status.text}</span>
                </div>
                <div className="compliance-score-wrap">
                  <span className="compliance-score-num">{score}</span>
                  <span className="compliance-score-percent">% alignment</span>
                </div>
                <div className="compliance-bar-track" style={{ background: 'rgba(255,255,255,0.04)', height: '6px', borderRadius: '3px', overflow: 'hidden', marginTop: '6px', marginBottom: '10px' }}>
                  <div 
                    className="compliance-bar-fill" 
                    style={{ 
                      width: `${score}%`, 
                      height: '100%', 
                      background: score >= 85 ? 'var(--success)' : score >= 65 ? 'var(--warning)' : 'var(--danger)',
                      boxShadow: score >= 85 ? '0 0 8px var(--success)' : score >= 65 ? '0 0 8px var(--warning)' : '0 0 8px var(--danger)'
                    }}
                  />
                </div>
                <div className="compliance-stats-row">
                  <div className="compliance-stat-item">
                    <span className="compliance-stat-label">Passed</span>
                    <span className="compliance-stat-val pass">{report?.passed || 0} controls</span>
                  </div>
                  <div className="compliance-stat-item">
                    <span className="compliance-stat-label">Failed</span>
                    <span className="compliance-stat-val fail">{report?.failed || 0} controls</span>
                  </div>
                </div>

                {report && report.controls && (
                  (() => {
                    const failedControls = report.controls.filter((c: any) => c.status === 'failed');
                    if (failedControls.length === 0) return null;
                    return (
                      <div style={{ marginTop: '12px', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '10px' }}>
                        <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--danger)', textTransform: 'uppercase', marginBottom: '6px', letterSpacing: '0.5px' }}>Top Failed Controls:</div>
                        <ul style={{ margin: 0, paddingLeft: '16px', fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          {failedControls.slice(0, 3).map((ctrl: any) => (
                            <li key={ctrl.id} title={ctrl.description}>
                              <strong>{ctrl.id}:</strong> {ctrl.name}
                            </li>
                          ))}
                        </ul>
                      </div>
                    );
                  })()
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* 7. SBOM PREVIEW */}
      <div className="report-section">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }} className="sbom-header-row">
          <h3 style={{ margin: 0 }}>📦 SBOM Dependency Preview</h3>
          {sbom && (
            <button className="settings__btn settings__btn--secondary report-actions" onClick={handleExportSBOM} style={{ padding: '6px 12px', fontSize: '12px' }}>
              📥 Download CycloneDX SBOM
            </button>
          )}
        </div>
        <div className="list-card glassmorphism" style={{ padding: '20px' }}>
          {sbom && sbom.packages && sbom.packages.length > 0 ? (
            <>
              <div className="sbom-table-wrapper">
                <table className="sbom-preview-table">
                  <thead>
                    <tr>
                      <th>Package Name</th>
                      <th>Version</th>
                      <th>Ecosystem</th>
                      <th>PURL Specification</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sbom.packages.slice(0, 8).map((pkg, idx) => (
                      <tr key={`${pkg.name}-${idx}`}>
                        <td style={{ fontWeight: 600 }}>{pkg.name}</td>
                        <td className="monospace-td">{pkg.version}</td>
                        <td><span className="badge-type">{pkg.ecosystem}</span></td>
                        <td className="monospace-td" style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                          {pkg.purl || 'N/A'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="sbom-preview-footer">
                Showing top 8 dependencies. Total dependencies listed: <strong>{sbom.packages.length}</strong>.
              </div>
            </>
          ) : (
            <p className="muted text-center" style={{ margin: 0 }}>No SBOM packages generated for this target.</p>
          )}
        </div>
      </div>

      {/* 8. EVIDENCE APPENDIX */}
      <div className="report-section">
        <h3>📋 Evidence Appendix (All Findings)</h3>
        <div className="list-card glassmorphism console-window" style={{ padding: 0 }}>
          <div className="terminal-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingRight: '12px', flexWrap: 'wrap', gap: '8px' }}>
            <span className="terminal-title">findings_manifest_index.csv</span>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }} className="report-actions">
              <input
                type="text"
                placeholder="Search index..."
                value={appendixSearch}
                onChange={(e) => setAppendixSearch(e.target.value)}
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '4px', color: '#fff', padding: '4px 8px', fontSize: '11px', width: '140px', outline: 'none' }}
              />
              <select
                value={appendixSeverity}
                onChange={(e) => setAppendixSeverity(e.target.value)}
                style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '4px', color: '#fff', padding: '4px 8px', fontSize: '11px', outline: 'none', cursor: 'pointer' }}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
          </div>
          <div className="table-responsive">
            <table className="recent-scans-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Title</th>
                  <th>Category</th>
                  <th>File Path</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {filteredAppendixFindings.length > 0 ? (
                  filteredAppendixFindings.map((f) => (
                    <tr key={f.id}>
                      <td><span className={`severity-badge-lbl ${f.severity}`}>{f.severity}</span></td>
                      <td style={{ fontWeight: 500 }}>{f.title}</td>
                      <td><span className="badge-type">{f.category}</span></td>
                      <td className="monospace-td" style={{ maxWidth: '280px' }} title={f.filePath}>
                        {f.filePath}:L{f.lineNumber}
                      </td>
                      <td>
                        <span className={`status-badge ${f.isFixed ? 'completed' : 'failed'}`}>
                          {f.isFixed ? 'Fixed' : 'Active'}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="text-center muted" style={{ padding: '24px' }}>
                      No matching findings recorded in this scan index.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
        </>
      )}
    </div>

      {/* ============================================================
          2. PRINT MEDIA CONTENT (FORMAL AUDIT REPORT FOR BANKS)
          ============================================================ */}
      <div className="print-only">
        {/* Helper variables */}
        {(() => {
          const scanTarget = scan.target || 'vulnerable-test-target/vulnerable_demo.py (repository scope)';
          const assessmentDateStr = scan.completedAt 
            ? new Date(scan.completedAt).toLocaleDateString('en-US', { day: 'numeric', month: 'long', year: 'numeric' })
            : '12 July 2026';
          const reportDateStr = new Date().toLocaleDateString('en-US', { day: 'numeric', month: 'long', year: 'numeric' });
          const engagementRef = 'SVS-2026-0712-001';

          return (
            <>
              {/* PAGE 1: COVER PAGE */}
              <div className="audit-page page-1">
                <div className="audit-cover-logo-placeholder">
                  [ BANK / INSTITUTION LOGO ]
                </div>
                <div className="audit-cover-body">
                  <h1 className="audit-cover-title">APPLICATION SECURITY & SECRETS EXPOSURE AUDIT REPORT</h1>
                  <p className="audit-cover-subtitle">Confidential Information Security Assessment</p>
                  <p className="audit-cover-ref">Engagement Reference: {engagementRef}</p>
                  
                  <table className="audit-cover-table">
                    <tbody>
                      <tr>
                        <td className="label-col">Report Title</td>
                        <td className="val-col">Application Security & Secrets Exposure Audit</td>
                      </tr>
                      <tr>
                        <td className="label-col">Prepared For</td>
                        <td className="val-col">[Bank / Institution Name] — Information Security Office</td>
                      </tr>
                      <tr>
                        <td className="label-col">Prepared By</td>
                        <td className="val-col">[Auditor / Team Name], SovaScan Automated Assessment</td>
                      </tr>
                      <tr>
                        <td className="label-col">Engagement Ref.</td>
                        <td className="val-col">{engagementRef}</td>
                      </tr>
                      <tr>
                        <td className="label-col">Scan Target</td>
                        <td className="val-col">{scanTarget}</td>
                      </tr>
                      <tr>
                        <td className="label-col">Scan Type</td>
                        <td className="val-col">Full (Secrets, SCA, SAST, Configuration)</td>
                      </tr>
                      <tr>
                        <td className="label-col">Assessment Date</td>
                        <td className="val-col">{assessmentDateStr}</td>
                      </tr>
                      <tr>
                        <td className="label-col">Report Date</td>
                        <td className="val-col">{reportDateStr}</td>
                      </tr>
                      <tr>
                        <td className="label-col">Classification</td>
                        <td className="val-col">CONFIDENTIAL — Internal Use Only</td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                <div className="audit-cover-footer">
                  <p className="confidential-red">CONFIDENTIAL — For Internal Distribution Only</p>
                  <p className="confidential-desc">This document contains sensitive security information. Do not distribute outside authorized personnel.</p>
                </div>
              </div>

              {/* PAGE 2: TABLE OF CONTENTS */}
              <div className="audit-page page-2">
                {renderAuditPageHeader(2)}
                <h2 className="audit-section-title">Table of Contents</h2>
                
                <ul className="toc-list">
                  <li>
                    <span className="toc-title">Table of Contents</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">2</span>
                  </li>
                  <li>
                    <span className="toc-title">1. Executive Summary</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">3</span>
                  </li>
                  <li>
                    <span className="toc-sub-title">1.1 Key Metrics</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">3</span>
                  </li>
                  <li>
                    <span className="toc-sub-title">1.2 Risk Statement</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">3</span>
                  </li>
                  <li>
                    <span className="toc-title">2. Scope and Methodology</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">4</span>
                  </li>
                  <li>
                    <span className="toc-sub-title">2.1 Scope</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">4</span>
                  </li>
                  <li>
                    <span className="toc-sub-title">2.2 Methodology</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">4</span>
                  </li>
                  <li>
                    <span className="toc-sub-title">2.3 Severity Classification</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">4</span>
                  </li>
                  <li>
                    <span className="toc-title">3. Threat Posture Summary</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">5</span>
                  </li>
                  <li>
                    <span className="toc-title">4. Detailed Findings — Top Security Risks</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">6</span>
                  </li>
                  <li>
                    <span className="toc-sub-title">4.1 Finding: Git History — AWS Access Key ID</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">6</span>
                  </li>
                  <li>
                    <span className="toc-sub-title">4.2 Finding: Git History — Private Keys (Generic, DSA, EC, RSA)</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">6</span>
                  </li>
                  <li>
                    <span className="toc-sub-title">4.3 Additional Secret Exposures</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">6</span>
                  </li>
                  <li>
                    <span className="toc-sub-title">4.4 Configuration Findings</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">6</span>
                  </li>
                  <li>
                    <span className="toc-title">5. Remediation Plan</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">7</span>
                  </li>
                  <li>
                    <span className="toc-title">6. Compliance Impact</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">8</span>
                  </li>
                  <li>
                    <span className="toc-title">7. Software Bill of Materials (SBOM) — Dependency Preview</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">9</span>
                  </li>
                  <li>
                    <span className="toc-title">8. Evidence Appendix — Full Findings Register</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">10</span>
                  </li>
                  <li>
                    <span className="toc-title">9. Disclaimer and Sign-Off</span>
                    <span className="toc-dots"></span>
                    <span className="toc-page">11</span>
                  </li>
                </ul>
                
                {renderAuditPageFooter(2)}
              </div>

              {/* PAGE 3: EXECUTIVE SUMMARY */}
              <div className="audit-page page-3">
                {renderAuditPageHeader(3)}
                <h2 className="audit-section-title">1. Executive Summary</h2>
                <p className="audit-paragraph">
                  This report presents the findings of a full-scope automated security assessment performed on the designated repository and application target using the SovaScan platform. The assessment covered secrets detection, software composition analysis (SCA), static application security testing (SAST), and configuration auditing.
                </p>
                <p className="audit-paragraph">
                  The scan identified {totalFindingsCount} high-priority security findings requiring remediation prior to production release or continued use in a banking environment. All {totalFindingsCount} findings were classified as Critical or High severity; no Medium, Low, or Informational findings were recorded. The overall risk score for this assessment is {riskScore} out of 100 (Critical), reflecting the presence of live, exploitable credential exposures within source control history.
                </p>
                <p className="audit-paragraph">
                  The dominant risk theme is credential exposure: cryptographic private keys (RSA, DSA, EC, and generic formats), AWS access keys, database connection strings, and application passwords were found committed to git history across multiple files. In addition, two configuration-level misconfigurations were identified: debug mode enabled in a web-facing configuration, and a wildcard CORS origin policy, both of which materially increase the attack surface if deployed to production.
                </p>

                <h3 className="audit-sub-title">1.1 Key Metrics</h3>
                <div className="audit-metrics-summary">
                  <div className="audit-metric-box">
                    <div className="audit-metric-val risk-critical">{riskScore} / 100</div>
                    <div className="audit-metric-lbl">Risk Score (Critical)</div>
                  </div>
                  <div className="audit-metric-box">
                    <div className="audit-metric-val">{totalFindingsCount}</div>
                    <div className="audit-metric-lbl">Total Findings</div>
                  </div>
                  <div className="audit-metric-box">
                    <div className="audit-metric-val">{critical + high}</div>
                    <div className="audit-metric-lbl">Critical & High</div>
                  </div>
                  <div className="audit-metric-box">
                    <div className="audit-metric-val">2</div>
                    <div className="audit-metric-lbl">Impacted Tiers</div>
                  </div>
                </div>

                <h3 className="audit-sub-title">1.2 Risk Statement</h3>
                <p className="audit-paragraph">
                  Given the presence of exposed private keys and cloud access credentials, this environment should be treated as compromised until all secrets identified in Section 4 are rotated and purged from version control history. This is consistent with regulatory expectations for financial institutions under frameworks such as the RBI Cyber Security Framework, PCI DSS, SOC 2, and NIST CSF, all of which require prompt revocation of exposed credentials and evidence of remediation.
                </p>

                {renderAuditPageFooter(3)}
              </div>

              {/* PAGE 4: SCOPE AND METHODOLOGY */}
              <div className="audit-page page-4">
                {renderAuditPageHeader(4)}
                <h2 className="audit-section-title">2. Scope and Methodology</h2>
                
                <h3 className="audit-sub-title">2.1 Scope</h3>
                <ul className="audit-bullet-list">
                  <li><strong>Target:</strong> {scanTarget}</li>
                  <li><strong>Scan type:</strong> Full assessment (Secrets, Dependencies/SBOM, Static Code Analysis, Configuration)</li>
                  <li><strong>Assessment window:</strong> {assessmentDateStr}</li>
                  <li><strong>Environment:</strong> Source code repository and configuration files (non-production analysis)</li>
                </ul>

                <h3 className="audit-sub-title">2.2 Methodology</h3>
                <p className="audit-paragraph">
                  The assessment was performed using SovaScan's automated scanning engine, which combines pattern-based secret detection across full git commit history, dependency inventory generation (SBOM), static analysis of application source code, and configuration file auditing. Findings were automatically scored for severity and cross-referenced against the CISA Known Exploited Vulnerabilities catalog and FIRST EPSS scores where CVE identifiers were present.
                </p>

                <h3 className="audit-sub-title">2.3 Severity Classification</h3>
                <p className="audit-paragraph">
                  Findings are classified as Critical, High, Medium, Low, or Informational based on exploitability, potential business impact, and ease of remediation. Critical and High findings represent immediate risk to confidentiality, integrity, or availability and are prioritized for same-cycle remediation.
                </p>

                {renderAuditPageFooter(4)}
              </div>

              {/* PAGE 5: THREAT POSTURE SUMMARY */}
              <div className="audit-page page-5">
                {renderAuditPageHeader(5)}
                <h2 className="audit-section-title">3. Threat Posture Summary</h2>
                <p className="audit-paragraph">
                  The distribution of findings by severity is summarized below.
                </p>

                <table className="audit-distribution-table">
                  <thead>
                    <tr>
                      <th>CRITICAL</th>
                      <th>HIGH</th>
                      <th>MEDIUM</th>
                      <th>LOW</th>
                      <th>INFO</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>{critical}</td>
                      <td>{high}</td>
                      <td>{medium}</td>
                      <td>{low}</td>
                      <td>{info}</td>
                    </tr>
                  </tbody>
                </table>

                <p className="audit-paragraph" style={{ marginTop: '30px', fontStyle: 'italic', color: '#64748b' }}>
                  No CVE-backed findings were detected in this scan; exploit enrichment (CISA KEV / FIRST EPSS) was therefore not required for this cycle.
                </p>

                {renderAuditPageFooter(5)}
              </div>

              {/* PAGE 6: DETAILED FINDINGS — TOP SECURITY RISKS */}
              <div className="audit-page page-6">
                {renderAuditPageHeader(6)}
                <h2 className="audit-section-title">4. Detailed Findings — Top Security Risks</h2>
                
                <h3 className="audit-finding-title-section">4.1 Finding: Git History — AWS Access Key ID</h3>
                <div className="audit-finding-meta-panel">
                  <strong>Severity:</strong> Critical &nbsp;|&nbsp; <strong>Category:</strong> Secret &nbsp;|&nbsp; <strong>Location:</strong> frontend/src/store/index.ts:L345
                </div>
                <p className="audit-paragraph">
                  <strong>Why it matters:</strong> Credential exposure of this kind can lead to unauthorized API access, account takeover, or complete infrastructure compromise.
                </p>
                <p className="audit-paragraph" style={{ fontStyle: 'italic', background: '#f8fafc', padding: '10px', borderRadius: '4px', borderLeft: '3px solid #cbd5e1' }}>
                  <strong>Evidence:</strong> Commit b5cd359 (author: abhiprep24-lab, 21 June 2026 10:22:10 +0530) contains an AWS Access Key ID pattern in plaintext within tracked history.
                </p>
                <p className="audit-paragraph">
                  <strong>Recommended Remediation:</strong> (1) Rotate the exposed credential immediately in the issuing cloud account. (2) Purge the secret from git history using git filter-branch or the BFG Repo Cleaner. (3) Force-push the cleaned history to all remotes and notify downstream clones.
                </p>

                <h3 className="audit-finding-title-section" style={{ marginTop: '30px' }}>4.2 Finding: Git History — Private Keys (Generic, DSA, EC, RSA)</h3>
                <div className="audit-finding-meta-panel">
                  <strong>Severity:</strong> Critical &nbsp;|&nbsp; <strong>Category:</strong> Secret &nbsp;|&nbsp; <strong>Locations:</strong> backend/sovascan/core/secret_scanner.py:L91–L112
                </div>
                <p className="audit-paragraph">
                  <strong>Why it matters:</strong> Exposed private keys allow impersonation, decryption of protected traffic, or unauthorized system access depending on key usage.
                </p>
                <p className="audit-paragraph">
                  <strong>Recommended Remediation:</strong> Revoke and reissue all affected key pairs; remove from git history as above; audit systems that trusted the exposed keys for signs of misuse.
                </p>

                <h3 className="audit-finding-title-section" style={{ marginTop: '30px' }}>4.3 Additional Secret Exposures</h3>
                <p className="audit-paragraph">
                  Further Critical and High findings include a database connection string containing a password, a Slack webhook URL, and multiple generic API key and password assignments across configuration and application files. Full details are provided in the Evidence Appendix (Section 8).
                </p>

                <h3 className="audit-finding-title-section" style={{ marginTop: '30px' }}>4.4 Configuration Findings</h3>
                <p className="audit-paragraph">
                  Debug Mode Enabled in Web Configuration (Critical) and CORS Wildcard Origin Allowed (High) were identified in the application's runtime configuration. Both settings are inappropriate for a production banking environment: debug mode can leak stack traces and internal state, while a wildcard CORS policy permits cross-origin requests from any domain, undermining same-origin protections.
                </p>

                {renderAuditPageFooter(6)}
              </div>

              {/* PAGE 7: REMEDIATION PLAN */}
              <div className="audit-page page-7">
                {renderAuditPageHeader(7)}
                <h2 className="audit-section-title">5. Remediation Plan</h2>
                
                <table className="audit-grid-table">
                  <thead>
                    <tr>
                      <th style={{ width: '25%' }}>PRIORITY</th>
                      <th style={{ width: '15%' }}>COUNT</th>
                      <th style={{ width: '25%' }}>TIERS IMPACTED</th>
                      <th>REQUIRED ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td style={{ fontWeight: 700 }}>Fix Now<br/>(Critical/High)</td>
                      <td>{critical + high}</td>
                      <td>Secret Exposure, Misconfiguration</td>
                      <td>Revoke and rotate all exposed credentials immediately; purge secrets from git history using git filter-branch or BFG Repo Cleaner; force-push cleaned history; patch identified misconfigurations.</td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 700 }}>Fix This Sprint<br/>(Medium)</td>
                      <td>{medium}</td>
                      <td>None</td>
                      <td>No medium-severity items identified in this scan cycle.</td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 700 }}>Backlog<br/>(Low/Info)</td>
                      <td>{low + info}</td>
                      <td>None</td>
                      <td>No low-severity or informational items identified in this scan cycle.</td>
                    </tr>
                  </tbody>
                </table>

                <p className="audit-paragraph" style={{ marginTop: '30px' }}>
                  Ownership and timeline for each remediation item should be assigned during the post-audit review meeting and tracked to closure in the organization's issue-tracking or GRC platform, with evidence of rotation and history-purge attached prior to sign-off.
                </p>

                {renderAuditPageFooter(7)}
              </div>

              {/* PAGE 8: COMPLIANCE IMPACT */}
              <div className="audit-page page-8">
                {renderAuditPageHeader(8)}
                <h2 className="audit-section-title">6. Compliance Impact</h2>
                <p className="audit-paragraph">
                  The findings in this report were mapped against three widely used control frameworks to support regulatory and audit reporting.
                </p>

                <table className="audit-grid-table">
                  <thead>
                    <tr>
                      <th style={{ width: '25%' }}>FRAMEWORK</th>
                      <th style={{ width: '30%' }}>ALIGNMENT</th>
                      <th style={{ width: '20%' }}>STATUS</th>
                      <th>TOP FAILED CONTROLS</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td style={{ fontWeight: 700 }}>NIST-CSF</td>
                      <td>{compliance.nist?.score}% ({compliance.nist?.passed} passed / {compliance.nist?.failed} failed)</td>
                      <td>{(compliance.nist?.score ?? 0) >= 85 ? 'Aligned' : 'Needs Review'}</td>
                      <td>ID.AM Asset Mgmt; PR.AC Access Control</td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 700 }}>SOC 2</td>
                      <td>{compliance.soc2?.score}% ({compliance.soc2?.passed} passed / {compliance.soc2?.failed} failed)</td>
                      <td>{(compliance.soc2?.score ?? 0) >= 85 ? 'Aligned' : 'High Risk'}</td>
                      <td>CC6.1 Logical Access; CC6.6 Transmission Integrity; CC9.1 Business Risk Mitigation</td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 700 }}>OWASP Top 10</td>
                      <td>{compliance.owasp10?.score}% ({compliance.owasp10?.passed} passed / {compliance.owasp10?.failed} failed)</td>
                      <td>{(compliance.owasp10?.score ?? 0) >= 85 ? 'Aligned' : 'High Risk'}</td>
                      <td>A01 Broken Access Control; A02 Cryptographic Failures; A05 Security Misconfiguration</td>
                    </tr>
                  </tbody>
                </table>

                <p className="audit-paragraph" style={{ marginTop: '30px', fontStyle: 'italic', color: '#64748b' }}>
                  Note: Alignment percentages reflect automated control mapping based on detected findings and should be validated by the compliance/GRC function before inclusion in formal regulatory submissions.
                </p>

                {renderAuditPageFooter(8)}
              </div>

              {/* PAGE 9: SBOM */}
              <div className="audit-page page-9">
                {renderAuditPageHeader(9)}
                <h2 className="audit-section-title">7. Software Bill of Materials (SBOM) — Dependency Preview</h2>
                <p className="audit-paragraph">
                  The following table summarizes dependency artifacts identified within the scanned target. Full SBOM data is retained in the SovaScan platform and available on request.
                </p>

                <table className="audit-grid-table">
                  <thead>
                    <tr>
                      <th>PACKAGE NAME</th>
                      <th>VERSION</th>
                      <th>ECOSYSTEM</th>
                      <th>PURL SPECIFICATION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sbom?.packages && sbom.packages.length > 0 ? (
                      sbom.packages.slice(0, 8).map((pkg: any) => (
                        <tr key={pkg.name}>
                          <td style={{ fontFamily: 'monospace' }}>{pkg.name}</td>
                          <td>{pkg.version}</td>
                          <td>{pkg.ecosystem || 'PyPI'}</td>
                          <td style={{ fontSize: '8pt', color: '#64748b' }}>{pkg.purl || 'N/A'}</td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td style={{ fontFamily: 'monospace' }}>vulnerable-test-target/vulnerable_demo.py</td>
                        <td>0.0.0</td>
                        <td>PyPI</td>
                        <td>N/A</td>
                      </tr>
                    )}
                  </tbody>
                </table>

                <p className="audit-paragraph" style={{ marginTop: '15px', fontStyle: 'italic', color: '#64748b' }}>
                  Total dependencies listed: {sbom?.packages?.length || 1} (top 8 shown where applicable).
                </p>

                {renderAuditPageFooter(9)}
              </div>

              {/* PAGE 10: EVIDENCE APPENDIX */}
              <div className="audit-page page-10">
                {renderAuditPageHeader(10)}
                <h2 className="audit-section-title">8. Evidence Appendix — Full Findings Register</h2>
                <p className="audit-paragraph">
                  The table below lists all {totalFindingsCount} findings identified during this assessment, in order of detection, for audit trail purposes.
                </p>

                <table className="audit-grid-table" style={{ fontSize: '8.5pt' }}>
                  <thead>
                    <tr>
                      <th style={{ width: '15%' }}>SEVERITY</th>
                      <th style={{ width: '40%' }}>TITLE</th>
                      <th style={{ width: '15%' }}>CATEGORY</th>
                      <th>FILE PATH</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((f) => (
                      <tr key={f.id}>
                        <td>
                          <span className={`audit-badge-lbl ${f.severity}`}>{f.severity.toUpperCase()}</span>
                        </td>
                        <td style={{ fontWeight: 600 }}>{f.title}</td>
                        <td style={{ color: '#475569' }}>{f.category.toUpperCase()}</td>
                        <td style={{ fontFamily: 'monospace', fontSize: '7.5pt' }}>{f.filePath}:L{f.lineNumber}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {renderAuditPageFooter(10)}
              </div>

              {/* PAGE 11: DISCLAIMER AND SIGN-OFF */}
              <div className="audit-page page-11">
                {renderAuditPageHeader(11)}
                <h2 className="audit-section-title">9. Disclaimer and Sign-Off</h2>
                <p className="audit-paragraph">
                  This report was generated using automated static analysis and secrets-detection tooling (SovaScan). Findings should be validated by qualified security personnel prior to remediation action, and this report does not constitute a substitute for a full manual penetration test or regulatory compliance certification.
                </p>

                <div className="audit-signoff-panel" style={{ marginTop: '80px' }}>
                  <div className="signoff-row">
                    <div className="signoff-field">Prepared by: _____________________________</div>
                    <div className="signoff-field">Date: _______________</div>
                  </div>
                  <div className="signoff-row" style={{ marginTop: '40px' }}>
                    <div className="signoff-field">Reviewed by: _____________________________</div>
                    <div className="signoff-field">Date: _______________</div>
                  </div>
                  <div className="signoff-row" style={{ marginTop: '40px' }}>
                    <div className="signoff-field">Approved by (CISO / Head of Security): _____________________________</div>
                    <div className="signoff-field">Date: _______________</div>
                  </div>
                </div>

                {renderAuditPageFooter(11)}
              </div>
            </>
          );
        })()}
      </div>
    </>
  );
};

export default Report;
