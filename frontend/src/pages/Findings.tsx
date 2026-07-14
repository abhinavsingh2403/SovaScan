import React, { useEffect, useState } from 'react';
import { useLocation, Link } from 'react-router-dom';
import { useStore } from '../store';
import { api } from '../api/client';
import { Finding } from '../types';
import './Findings.css';

const getReplacementFromPatch = (patch: string): string => {
  if (!patch) return '';
  const lines = patch.split('\n');
  const addedLines = lines
    .filter((line) => line.startsWith('+') && !line.startsWith('+++'))
    .map((line) => line.slice(1));
  return addedLines.join('\n');
};

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
  const [customReplacements, setCustomReplacements] = useState<Record<string, string>>({});
  const [contextCache, setContextCache] = useState<Record<string, { lines: Array<{num: number; content: string}>; targetLine: number; filePath: string; startLine: number; endLine: number }>>({});
  const [loadingContextId, setLoadingContextId] = useState<string | null>(null);
  const [collapsedContext, setCollapsedContext] = useState<Record<string, boolean>>({});
  const [currentContextText, setCurrentContextText] = useState<Record<string, string>>({});
  const [backupContextText, setBackupContextText] = useState<Record<string, string>>({});

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

  const loadFindingContext = async (finding: Finding) => {
    const id = finding.id;
    if (contextCache[id]) return;
    setLoadingContextId(id);
    try {
      const ctxRes = await api.getFindingContext(id);
      const ctxData = ctxRes.data;
      setContextCache((prev) => ({
        ...prev,
        [id]: {
          lines: ctxData.lines,
          targetLine: ctxData.target_line,
          filePath: ctxData.file_path,
          startLine: ctxData.start_line,
          endLine: ctxData.end_line,
        },
      }));

      const initialText = ctxData.lines.map((l: any) => l.content).join('\n');
      setCurrentContextText((prev) => ({
        ...prev,
        [id]: initialText,
      }));
      setBackupContextText((prev) => ({
        ...prev,
        [id]: initialText,
      }));
      setCustomReplacements((prev) => ({
        ...prev,
        [id]: prev[id] !== undefined ? prev[id] : (finding.evidence || ''),
      }));
      setCollapsedContext((prev) => ({
        ...prev,
        [id]: false,
      }));
    } catch (err) {
      console.error("Failed to load context for finding", id, err);
    } finally {
      setLoadingContextId(null);
    }
  };

  const toggleExpand = async (id: string, finding: Finding) => {
    const isExpanding = expandedId !== id;
    setExpandedId(isExpanding ? id : null);
    if (isExpanding) {
      await loadFindingContext(finding);
    }
  };

  const requestFixSuggestion = async (finding: Finding, e: React.MouseEvent) => {
    e.stopPropagation();
    setExpandedId(finding.id); // auto-expand to show details/sandbox
    setLoadingFixId(finding.id);

    const fixPromise = api.applyFix(finding.id, false);
    const contextPromise = loadFindingContext(finding);

    try {
      const [res] = await Promise.all([fixPromise, contextPromise]);
      const patch = res.data?.patch || '';
      const description = res.data?.description || 'No suggestion description available.';
      
      setPendingFix((prev) => ({
        ...prev,
        [finding.id]: { patch, description },
      }));

      const replacementText = getReplacementFromPatch(patch);
      setCustomReplacements((prev) => ({
        ...prev,
        [finding.id]: replacementText,
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
      const customReplacement = customReplacements[finding.id] || '';
      
      const res = await api.applyFix(
        finding.id,
        true,
        customReplacement,
        undefined, // contextReplacement
        undefined, // contextStartLine
        undefined  // contextEndLine
      );
        const desc = res.data?.description || 'Fix applied successfully!';
        setFixSuccessMsg((prev) => ({
          ...prev,
          [finding.id]: desc,
        }));
        finding.isFixed = true;

        // Refetch context to show the updated file directly on the page
        try {
          const ctxRes = await api.getFindingContext(finding.id);
          const ctxData = ctxRes.data;
          setContextCache((prev) => ({
            ...prev,
            [finding.id]: {
              lines: ctxData.lines,
              targetLine: ctxData.target_line,
              filePath: ctxData.file_path,
              startLine: ctxData.start_line,
              endLine: ctxData.end_line,
            },
          }));
          const updatedText = ctxData.lines.map((l: any) => l.content).join('\n');
          setCurrentContextText((prev) => ({
            ...prev,
            [finding.id]: updatedText,
          }));
        } catch (e) {
          console.error("Failed to refetch context", e);
        }
    } catch (err: any) {
      setFixSuccessMsg((prev) => ({
        ...prev,
        [finding.id]: `Fix request failed: ${err.message || err}`,
      }));
    } finally {
      setApplyingFixId(null);
    }
  };

  const revertAppliedFix = async (finding: Finding) => {
    const ctx = contextCache[finding.id];
    const backupText = backupContextText[finding.id];
    if (!ctx || !backupText) {
      alert("No backup context available to revert the fix!");
      return;
    }
    setApplyingFixId(finding.id);
    try {
      await api.revertFix(finding.id, backupText, ctx.startLine, ctx.endLine);
      setFixSuccessMsg((prev) => ({
        ...prev,
        [finding.id]: "Fix reverted successfully! File restored to original content.",
      }));
      finding.isFixed = false;
      
      // Refetch context to show the original content
      try {
        const ctxRes = await api.getFindingContext(finding.id);
        const ctxData = ctxRes.data;
        setContextCache((prev) => ({
          ...prev,
          [finding.id]: {
            lines: ctxData.lines,
            targetLine: ctxData.target_line,
            filePath: ctxData.file_path,
            startLine: ctxData.start_line,
            endLine: ctxData.end_line,
          },
        }));
        const restoredText = ctxData.lines.map((l: any) => l.content).join('\n');
        setCurrentContextText((prev) => ({
          ...prev,
          [finding.id]: restoredText,
        }));
        setPendingFix((prev) => {
          const next = { ...prev };
          delete next[finding.id];
          return next;
        });
      } catch (e) {
        console.error("Failed to refetch context after revert", e);
      }
    } catch (err: any) {
      alert(`Failed to revert fix: ${err.message || err}`);
    } finally {
      setApplyingFixId(null);
    }
  };

  const cancelFixSuggestion = (finding: Finding) => {
    const findingId = finding.id;
    const ctx = contextCache[findingId];
    if (ctx) {
      const originalText = ctx.lines.map((l: any) => l.content).join('\n');
      setCurrentContextText((prev) => ({
        ...prev,
        [findingId]: originalText,
      }));
    }
    setCustomReplacements((prev) => ({
      ...prev,
      [findingId]: finding.evidence || '',
    }));
    setPendingFix((prev) => {
      const next = { ...prev };
      delete next[findingId];
      return next;
    });
    setFixSuccessMsg((prev) => {
      const next = { ...prev };
      delete next[findingId];
      return next;
    });
  };

  const renderCodeContext = (finding: Finding) => {
    const ctx = contextCache[finding.id];
    if (loadingContextId === finding.id) {
      return (
        <div className="code-context-loading">
          <div className="spinner" style={{ width: 16, height: 16 }}></div>
          <span>Loading source context...</span>
        </div>
      );
    }
    if (!ctx || !ctx.lines || ctx.lines.length === 0) return null;

    const isCollapsed = collapsedContext[finding.id] || false;

    return (
      <div className={`code-context-viewer ${finding.isFixed ? 'fixed-state' : ''}`}>
        <div 
          className="context-header" 
          onClick={() => setCollapsedContext(prev => ({ ...prev, [finding.id]: !isCollapsed }))}
          style={{ cursor: 'pointer', userSelect: 'none' }}
        >
          <span className="context-file-label">
            📄 {ctx.filePath} {finding.isFixed && <span className="fixed-indicator-badge">✓ Applied</span>}
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="context-line-range">Lines {ctx.lines[0]?.num}–{ctx.lines[ctx.lines.length - 1]?.num}</span>
            <span className="collapse-chevron" style={{ 
              transform: isCollapsed ? 'rotate(0deg)' : 'rotate(180deg)', 
              transition: 'transform 0.2s',
              display: 'inline-block'
            }}>▼</span>
          </div>
        </div>

        {!isCollapsed && (
          <div className="context-lines-wrap" style={{ background: '#0d1117' }}>
            {ctx.lines.map((line: { num: number; content: string }) => {
              const isTarget = line.num === ctx.targetLine;
              return (
                <div
                  key={line.num}
                  className={`context-line ${isTarget ? (finding.isFixed ? 'fixed-highlight' : 'target-highlight') : ''}`}
                >
                  <span className="line-num-gutter">{line.num}</span>
                  <code className="line-content">{line.content}</code>
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  const renderSideBySideSandbox = (finding: Finding) => {
    const originalCode = finding.evidence || '';
    const currentValue = customReplacements[finding.id] !== undefined ? customReplacements[finding.id] : '';

    return (
      <div className="split-diff-container" style={{ marginTop: '16px', marginBottom: '12px' }}>
        {/* Left Pane: Original Code */}
        <div className="split-pane original-pane" style={{ background: 'rgba(0, 0, 0, 0.25)' }}>
          <div className="pane-header header-original" style={{ background: 'rgba(239, 68, 68, 0.08)', color: '#f87171' }}>
            <span className="pane-indicator">🔴 Original Code</span>
            <span className="file-tag">Original</span>
          </div>
          <div className="pane-editor-wrap" style={{ padding: '12px', background: 'rgba(0, 0, 0, 0.15)' }}>
            <pre className="code-display" style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: '#f87171' }}>
              <code>{originalCode}</code>
            </pre>
          </div>
        </div>

        {/* Right Pane: Proposed Sandbox Editor */}
        <div className="split-pane sandbox-pane" style={{ background: 'rgba(0, 0, 0, 0.25)' }}>
          <div className="pane-header header-sandbox" style={{ background: 'rgba(16, 185, 129, 0.08)', color: '#34d399' }}>
            <span className="pane-indicator">🟢 Sandbox / Proposed Fix</span>
            <span className="edit-badge">Editable ✏️</span>
          </div>
          <div className="pane-editor-wrap" style={{ padding: '12px', background: 'rgba(0, 0, 0, 0.15)' }}>
            <textarea
              className="sandbox-textarea"
              value={currentValue}
              disabled={finding.isFixed}
              onChange={(e) => {
                setCustomReplacements((prev) => ({
                  ...prev,
                  [finding.id]: e.target.value,
                }));
              }}
              placeholder="// Write/tweak your replacement code here..."
              rows={Math.max(3, currentValue.split('\n').length)}
              style={{
                width: '100%',
                background: 'transparent',
                color: '#34d399',
                border: 'none',
                fontFamily: "'Fira Code', 'Courier New', Courier, monospace",
                fontSize: '12px',
                lineHeight: '1.5',
                resize: 'vertical',
                outline: 'none',
                padding: 0,
                margin: 0,
                whiteSpace: 'pre',
                tabSize: 4,
              }}
            />
          </div>
        </div>
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
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', width: '100%' }}>
              <select
                value={scanFilter}
                onChange={(e) => setScanFilter(e.target.value)}
                style={{ flex: 1 }}
              >
                <option value="all">All Scans</option>
                {scans.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    {scan.target} ({new Date(scan.createdAt).toLocaleDateString()})
                  </option>
                ))}
              </select>
              {scanFilter !== 'all' && (
                <Link
                  to={`/report/${scanFilter}`}
                  className="settings__btn settings__btn--secondary"
                  style={{
                    textDecoration: 'none',
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '11px',
                    padding: '8px 12px',
                    height: '35px',
                    boxSizing: 'border-box',
                    whiteSpace: 'nowrap',
                  }}
                  title="View Scan Report"
                >
                  📄 Report
                </Link>
              )}
            </div>
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
      <div className="findings-list animate-slide-up stagger-children">
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
                onClick={() => toggleExpand(finding.id, finding)}
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
                <div className={`finding-body smooth-expand ${isExpanded ? 'show' : ''}`} onClick={(e) => e.stopPropagation()}>
                  <div className="details-section">
                    <h5>Description</h5>
                    <p className="desc-text">{finding.description}</p>
                  </div>

                  <div className="details-section">
                    <h5>Potential Impact (Plain English)</h5>
                    <p className="impact-text">{getVulnerabilityImpact(finding)}</p>
                  </div>

                  <div className="details-section">
                    <h5>Code Context Sandbox</h5>
                    <p className="sandbox-help-text" style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                      Edit the code directly inside the sandbox box below, or click <strong>⚡ Auto Fix</strong> to view the AI suggestion.
                    </p>
                    
                    {renderCodeContext(finding)}
                    {!finding.isFixed && renderSideBySideSandbox(finding)}

                    {!finding.isFixed && pendingFix[finding.id] && (
                      <div className="fix-desc-box" style={{ 
                        marginTop: '8px', 
                        marginBottom: '8px', 
                        padding: '10px 12px', 
                        background: 'rgba(245, 158, 11, 0.08)', 
                        borderLeft: '3px solid #f59e0b',
                        borderRadius: '4px', 
                        fontSize: '12px',
                        color: '#f3f4f6'
                      }}>
                        <strong>AI Fix Suggestion:</strong> {pendingFix[finding.id].description}
                      </div>
                    )}
                    
                    <div className="fix-actions" style={{ marginTop: '12px', marginBottom: '16px' }}>
                      <a
                        className="editor-link-btn"
                        href={`vscode://file/${finding.filePath}:${finding.lineNumber}`}
                        onClick={(e) => e.stopPropagation()}
                      >
                        🖥️ Open in Editor (VS Code / Antigravity)
                      </a>

                      {finding.isFixed ? (
                        <>
                          <button
                            className="confirm-fix-btn success-applied"
                            disabled={true}
                            style={{ marginRight: '8px' }}
                          >
                            ✓ Applied to Disk
                          </button>
                          <button
                            className="revert-fix-btn"
                            onClick={() => revertAppliedFix(finding)}
                            disabled={applyingFixId === finding.id}
                            style={{
                              background: 'rgba(255, 255, 255, 0.08)',
                              border: '1px solid rgba(255, 255, 255, 0.15)',
                              color: '#c9d1d9',
                              padding: '8px 16px',
                              borderRadius: '6px',
                              fontWeight: '600',
                              cursor: 'pointer'
                            }}
                          >
                            {applyingFixId === finding.id ? 'Reverting...' : '↩ Revert Fix'}
                          </button>
                        </>
                      ) : (
                        <>
                          <button
                            className="confirm-fix-btn"
                            onClick={() => confirmApplyFix(finding)}
                            disabled={applyingFixId === finding.id || loadingContextId === finding.id}
                          >
                            {applyingFixId === finding.id ? 'Applying to disk...' : '✓ Confirm & Apply Fix'}
                          </button>
                          
                          <button
                            className="cancel-fix-btn"
                            onClick={() => cancelFixSuggestion(finding)}
                          >
                            Reset
                          </button>
                        </>
                      )}
                    </div>

                    {finding.isFixed && (
                      <div className="fix-applied-desc-banner" style={{
                        marginTop: '12px',
                        padding: '12px 16px',
                        background: 'rgba(16, 185, 129, 0.08)',
                        border: '1px solid rgba(16, 185, 129, 0.25)',
                        borderRadius: '6px',
                        color: '#34d399',
                        fontSize: '12px',
                        lineHeight: '1.5'
                      }}>
                        {pendingFix[finding.id]?.description || finding.description}
                      </div>
                    )}
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
