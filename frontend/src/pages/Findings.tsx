import React, { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useStore } from '../store';
import { api } from '../api/client';
import { Finding } from '../types';
import './Findings.css';

const Findings: React.FC = () => {
  const {
    findings,
    loading,
    fetchFindings,
    fixAllFindings,
    fixAllScanFindings,
    scans,
    fetchScans,
  } = useStore();
  const location = useLocation();
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [scanFilter, setScanFilter] = useState('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [applyingFixId, setApplyingFixId] = useState<string | null>(null);
  const [fixSuccessMsg, setFixSuccessMsg] = useState<Record<string, string>>({});
  const [applyingBulkFix, setApplyingBulkFix] = useState(false);
  const [pendingFix, setPendingFix] = useState<Record<string, { patch: string; description: string }>>({});
  const [loadingFixId, setLoadingFixId] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const searchParam = params.get('search');
    const severityParam = params.get('severity');
    const categoryParam = params.get('category');
    const scanParam = params.get('scan');

    if (searchParam) setSearchTerm(searchParam);
    if (severityParam) setSeverityFilter(severityParam);
    if (categoryParam) setCategoryFilter(categoryParam);
    if (scanParam) setScanFilter(scanParam);
  }, [location.search]);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  useEffect(() => {
    fetchFindings(scanFilter === 'all' ? undefined : scanFilter);
  }, [scanFilter, fetchFindings]);

  const handleFixAll = async () => {
    const fixableCount = findings.filter((f) => !f.isFixed).length;
    if (fixableCount === 0) {
      alert('No active findings to fix!');
      return;
    }
    const confirmMsg =
      scanFilter === 'all'
        ? `Are you sure you want to apply auto-fixes to all ${fixableCount} active findings on disk in one go?`
        : `Are you sure you want to apply auto-fixes to all ${fixableCount} active findings of the selected scan on disk in one go?`;

    if (window.confirm(confirmMsg)) {
      setApplyingBulkFix(true);
      try {
        let fixed: any[] = [];
        if (scanFilter === 'all') {
          fixed = await fixAllFindings();
        } else {
          fixed = await fixAllScanFindings(scanFilter);
        }
        if (fixed && fixed.length > 0) {
          const detailMsg = fixed
            .map((f: any) => `• ${f.title} (${f.file_path || f.filePath}:${f.line_number || f.lineNumber})`)
            .join('\n');
          alert(`Successfully applied bulk fixes to ${fixed.length} vulnerability findings:\n\n${detailMsg}`);
        } else {
          alert('Bulk fixes successfully applied to all files on disk!');
        }
      } catch (err) {
        console.error('Bulk fix failed:', err);
        alert('Failed to apply bulk fixes.');
      } finally {
        setApplyingBulkFix(false);
      }
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const requestFixSuggestion = async (finding: Finding, e: React.MouseEvent) => {
    e.stopPropagation();
    setLoadingFixId(finding.id);
    try {
      const res = await api.applyFix(finding.id, false);
      const patch = res.data?.patch || '';
      const description = res.data?.description || 'No suggestion description available.';
      setPendingFix((prev) => ({
        ...prev,
        [finding.id]: { patch, description },
      }));
    } catch (err: any) {
      alert(`Failed to load fix suggestion: ${err.message || err}`);
    } finally {
      setLoadingFixId(null);
    }
  };

  const confirmApplyFix = async (finding: Finding) => {
    setApplyingFixId(finding.id);
    try {
      const res = await api.applyFix(finding.id, true);
      const desc = res.data?.description || 'Fix applied successfully!';
      setFixSuccessMsg((prev) => ({
        ...prev,
        [finding.id]: desc,
      }));
      finding.isFixed = true;
      setPendingFix((prev) => {
        const next = { ...prev };
        delete next[finding.id];
        return next;
      });
    } catch {
      setFixSuccessMsg((prev) => ({
        ...prev,
        [finding.id]: 'Fix request failed. Please try again.',
      }));
    } finally {
      setApplyingFixId(null);
    }
  };

  const cancelFixSuggestion = (findingId: string) => {
    setPendingFix((prev) => {
      const next = { ...prev };
      delete next[findingId];
      return next;
    });
  };

  const renderDiff = (patch: string) => {
    if (!patch) return <div className="no-diff">No diff content generated.</div>;
    const lines = patch.split('\n');
    return (
      <div className="diff-viewer">
        {lines.map((line, idx) => {
          let lineClass = 'diff-line';
          if (line.startsWith('+') && !line.startsWith('+++')) {
            lineClass += ' insertion';
          } else if (line.startsWith('-') && !line.startsWith('---')) {
            lineClass += ' deletion';
          } else if (line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++')) {
            lineClass += ' meta';
          }
          return (
            <div key={idx} className={lineClass}>
              {line}
            </div>
          );
        })}
      </div>
    );
  };

  const getVulnerabilityImpact = (finding: Finding) => {
    const category = (finding.category || '').toLowerCase();
    const ruleId = (finding.ruleId || '').toUpperCase();
    const title = (finding.title || '').toLowerCase();

    if (category === 'secret') {
      return (
        "An attacker can steal this hardcoded credential and gain direct access to your databases, " +
        "cloud services, external APIs, or communication channels. This can lead to massive data theft, " +
        "service abuse, or severe financial losses."
      );
    }
    
    if (category === 'cve') {
      const cveName = finding.cveId || 'a third-party library';
      return (
        `Using ${cveName} with known public vulnerabilities means attackers can exploit well-documented bugs. ` +
        "Depending on the specific bug, they could crash your server, steal data, or run malicious code on your systems."
      );
    }

    if (ruleId === 'SOVA-INFRA-001' || title.includes('root user')) {
      return (
        "Running your application containers as 'root' (admin) means if an attacker compromises the app, " +
        "they instantly gain admin control over the container. This makes it significantly easier to break out " +
        "and compromise the host server."
      );
    }

    if (ruleId === 'SOVA-MISCONFIG-001' || title.includes('debug mode') || title.includes('debug')) {
      return (
        "Enabling debug mode in production exposes internal code stack traces, server path details, and environment variables " +
        "to the public whenever an error occurs. Attackers use this blueprint to locate further entry points."
      );
    }

    if (ruleId === 'SOVA-INFRA-002' || title.includes('base image')) {
      return (
        "Using unpinned, outdated, or generic base images introduces pre-existing vulnerabilities into your container environment " +
        "and makes your builds unpredictable, increasing the risk of code breaking unexpectedly."
      );
    }

    if (ruleId.startsWith('SOVA-WEB-') || title.includes('headers') || title.includes('ssl') || title.includes('tls')) {
      return (
        "Missing HTTP security headers or weak SSL/TLS settings leave your users vulnerable to browser-based attacks " +
        "such as clickjacking, cross-site scripting (XSS), or having their traffic intercepted (man-in-the-middle)."
      );
    }

    if (ruleId.startsWith('SOVA-DB-') || title.includes('database') || title.includes('sql')) {
      return (
        "Weak database configurations (such as empty passwords or allowing connections from any IP) let attackers " +
        "brute-force or connect directly to your database, exposing all stored sensitive data to theft or deletion."
      );
    }

    if (category === 'config_drift') {
      return (
        "Unauthorized settings changes or drift from your approved security baseline mean that security controls " +
        "might have been disabled or altered, leaving unknown configuration gaps or causing system instability."
      );
    }

    // Default fallback
    return (
      "This misconfiguration weakens the defensive layers of your application. It could allow unauthorized users " +
      "to bypass security controls, view internal system data, or trigger service disruptions."
    );
  };

  // Extract unique categories for filter
  const categories = ['all', ...Array.from(new Set(findings.map((f) => f.category)))];

  // Filtering logic
  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.filePath.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.ruleId.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity = severityFilter === 'all' || f.severity === severityFilter;
    const matchesCategory = categoryFilter === 'all' || f.category === categoryFilter;

    return matchesSearch && matchesSeverity && matchesCategory;
  });

  return (
    <div className="findings-container">
      {/* Filters Bar */}
      <div className="filters-bar glassmorphism animate-fade-in">
        <div className="search-box">
          <span className="search-icon">🔍</span>
          <input
            type="text"
            placeholder="Search by title, file path, rule ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        <div className="dropdowns-wrap">
          <div className="filter-select">
            <label>Scan:</label>
            <select
              value={scanFilter}
              onChange={(e) => setScanFilter(e.target.value)}
            >
              <option value="all">All Scans</option>
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.target} ({new Date(scan.createdAt).toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>

          <div className="filter-select">
            <label>Severity:</label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>

          <div className="filter-select">
            <label>Category:</label>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
            >
              {categories.map((cat) => (
                <option key={cat} value={cat}>
                  {cat === 'all' ? 'All Categories' : cat}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Findings Count Summary */}
      <div className="results-summary animate-fade-in">
        <p>
          Showing <span>{filteredFindings.length}</span> of <span>{findings.length}</span> active
          findings
        </p>
        {findings.some((f) => !f.isFixed) && (
          <button
            className="fix-all-btn"
            onClick={handleFixAll}
            disabled={applyingBulkFix}
          >
            {applyingBulkFix ? 'Applying Bulk Fixes...' : '⚡ Fix All (1-Go)'}
          </button>
        )}
      </div>

      {/* Findings Table/Accordion List */}
      <div className="findings-list animate-slide-up">
        {loading ? (
          <div className="findings-loading">
            <div className="spinner"></div>
            <p>Analyzing vulnerabilities...</p>
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="no-findings glassmorphism">
            <h3>No matching findings found</h3>
            <p>Try resetting your filters or start a new scan.</p>
          </div>
        ) : (
          filteredFindings.map((finding) => {
            const isExpanded = expandedId === finding.id;
            return (
              <div
                key={finding.id}
                className={`finding-row-card glassmorphism ${isExpanded ? 'expanded' : ''} ${
                  finding.isFixed ? 'fixed' : ''
                }`}
                onClick={() => toggleExpand(finding.id)}
              >
                {/* Header Summary Row */}
                <div className="finding-header">
                  <div className="left-meta">
                    <span className={`severity-badge-lbl ${finding.severity}`}>
                      {finding.severity}
                    </span>
                    <span className="rule-id-lbl">{finding.ruleId}</span>
                  </div>
                  <div className="finding-title-sec">
                    <h4>{finding.title}</h4>
                    <p className="path-text">{finding.filePath}:{finding.lineNumber}</p>
                  </div>
                  <div className="right-controls">
                    <span className="category-tag">{finding.category}</span>
                    {finding.cvssScore && (
                      <span className="cvss-badge">CVSS {finding.cvssScore}</span>
                    )}
                    {finding.isFixed ? (
                      <span className="fixed-pill">✓ Fixed</span>
                    ) : (
                      <button
                        className="auto-fix-btn"
                        onClick={(e) => requestFixSuggestion(finding, e)}
                        disabled={loadingFixId === finding.id || applyingFixId === finding.id}
                      >
                        {loadingFixId === finding.id ? 'Loading...' : '⚡ Auto Fix'}
                      </button>
                    )}
                    <span className={`chevron ${isExpanded ? 'up' : 'down'}`}>▼</span>
                  </div>
                </div>

                {/* Expanded Details Body */}
                <div className={`finding-body ${isExpanded ? 'show' : ''}`} onClick={(e) => e.stopPropagation()}>
                  <div className="details-section">
                    <h5>Description</h5>
                    <p className="desc-text">{finding.description}</p>
                  </div>

                  <div className="details-section">
                    <h5>Potential Impact (Plain English)</h5>
                    <p className="impact-text">{getVulnerabilityImpact(finding)}</p>
                  </div>

                  <div className="details-section">
                    <h5>Code Evidence</h5>
                    <pre className="evidence-pre">
                      <code>{finding.evidence}</code>
                    </pre>
                  </div>

                  <div className="details-section">
                    <h5>Remediation Steps</h5>
                    <p className="remediation-text">{finding.remediation}</p>
                  </div>

                  {finding.cveId && (
                    <div className="details-section">
                      <h5>Vulnerability Identifier</h5>
                      <p className="cve-link-text">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${finding.cveId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          {finding.cveId} (NVD details)
                        </a>
                      </p>
                    </div>
                  )}

                  {pendingFix[finding.id] && (
                    <div className="fix-preview-box glassmorphism" onClick={(e) => e.stopPropagation()}>
                      <h5>Suggested Fix Preview</h5>
                      <p className="fix-desc">{pendingFix[finding.id].description}</p>
                      
                      {renderDiff(pendingFix[finding.id].patch)}

                      <div className="fix-actions">
                        <a
                          className="editor-link-btn"
                          href={`vscode://file/${finding.filePath}:${finding.lineNumber}`}
                          onClick={(e) => e.stopPropagation()}
                        >
                          🖥️ Open in Editor (VS Code / Antigravity)
                        </a>
                        
                        <button
                          className="confirm-fix-btn"
                          onClick={() => confirmApplyFix(finding)}
                          disabled={applyingFixId === finding.id}
                        >
                          {applyingFixId === finding.id ? 'Applying...' : '✓ Confirm & Apply Fix'}
                        </button>
                        
                        <button
                          className="cancel-fix-btn"
                          onClick={() => cancelFixSuggestion(finding.id)}
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}

                  {fixSuccessMsg[finding.id] && (
                    <div className="fix-success-banner">
                      {fixSuccessMsg[finding.id]}
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export default Findings;
