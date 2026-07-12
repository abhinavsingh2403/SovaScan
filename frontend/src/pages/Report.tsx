import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../api/client';
import { useStore } from '../store';
import { Scan, Finding, SBOMResponse, ComplianceReport } from '../types';
import './Report.css';

interface ComplianceMap {
  nist: ComplianceReport | null;
  soc2: ComplianceReport | null;
  owasp10: ComplianceReport | null;
}

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

const Report: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const { scans, fetchScans } = useStore();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sbom, setSbom] = useState<SBOMResponse | null>(null);
  const [compliance, setCompliance] = useState<ComplianceMap>({
    nist: null,
    soc2: null,
    owasp10: null,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [appendixSearch, setAppendixSearch] = useState('');
  const [appendixSeverity, setAppendixSeverity] = useState('all');

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

        setScan(scanRes.data);
        setFindings(findingsRes.data.findings || []);

        // Fetch SBOM (handles missing gracefully)
        try {
          const sbomRes = await api.getSBOM(scanId);
          setSbom(sbomRes.data);
        } catch (err) {
          console.warn('[Report] Failed to fetch SBOM packages:', err);
        }

        // Fetch compliance reports
        try {
          const [nistRes, soc2Res, owasp10Res] = await Promise.all([
            api.getCompliance('NIST-CSF'),
            api.getCompliance('SOC-2'),
            api.getCompliance('OWASP-10'),
          ]);
          setCompliance({
            nist: nistRes.data,
            soc2: soc2Res.data,
            owasp10: owasp10Res.data,
          });
        } catch (err) {
          console.warn('[Report] Failed to fetch compliance reports:', err);
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
        <div className="spinner"></div>
        <p>Generating Post-Scan Security Report...</p>
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
  const sortedFindings = [...findings].sort((a, b) => {
    const rankA = severityRank[a.severity] || 0;
    const rankB = severityRank[b.severity] || 0;
    return rankB - rankA;
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
    const payload = {
      scan_metadata: {
        id: scan.id,
        target: scan.target,
        type: scan.scanType,
        status: scan.status,
        startedAt: scan.startedAt,
        completedAt: scan.completedAt,
      },
      metrics: {
        total_findings: totalFindingsCount,
        critical,
        high,
        medium,
        low,
        risk_score: riskScore,
        risk_label: riskLabel,
      },
      summary: summaryParagraphs.join(' '),
      top_findings: topRisks.map((f) => ({
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
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SovaScan_Report_${scanId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleExportSBOM = () => {
    if (!sbom) return;
    const blob = new Blob([JSON.stringify(sbom, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SovaScan_SBOM_${scanId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // --- 6. Compliance Status helpers ---
  const getComplianceStatus = (score: number) => {
    if (score >= 85) return { text: 'Strong', class: 'strong' };
    if (score >= 65) return { text: 'Needs Review', class: 'needs-review' };
    return { text: 'High Risk', class: 'high-risk' };
  };

  const filteredAppendixFindings = findings.filter((f) => {
    const matchesSearch = f.title.toLowerCase().includes(appendixSearch.toLowerCase()) || 
                          f.filePath.toLowerCase().includes(appendixSearch.toLowerCase()) ||
                          f.ruleId.toLowerCase().includes(appendixSearch.toLowerCase());
    const matchesSeverity = appendixSeverity === 'all' || f.severity === appendixSeverity;
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="report-page">
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

      {/* 2. RISK OVERVIEW */}
      <div className="report-metrics-grid">
        <div className="list-card glassmorphism report-metric-card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '140px' }}>
          <div style={{ position: 'relative', width: '80px', height: '80px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <svg width="80" height="80" viewBox="0 0 80 80">
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
            <div style={{ position: 'absolute', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <span className={`report-metric-value ${riskColorClass}`} style={{ fontSize: '1.5rem', marginBottom: 0 }}>{riskScore}</span>
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
          {['NIST-CSF', 'SOC-2', 'OWASP-10'].map((fwName) => {
            const key = fwName === 'NIST-CSF' ? 'nist' : fwName === 'SOC-2' ? 'soc2' : 'owasp10';
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
    </div>
  );
};

export default Report;
