import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useStore } from '../store';
import './Compliance.css';

/* Framework icon mapping for visual distinction */
const frameworkIcons: Record<string, string> = {
  'NIST-CSF': '🏛️',
  'SOC-2': '🔐',
  'OWASP-10': '🕸️',
};

const Compliance: React.FC = () => {
  const { getComplianceReport, fetchComplianceReport, findings } = useStore();
  const [selectedFramework, setSelectedFramework] = useState(() => {
    try {
      const stored = localStorage.getItem('sovascan-settings');
      if (stored) {
        const parsed = JSON.parse(stored);
        return parsed.defaultFramework || 'NIST-CSF';
      }
    } catch {
      // ignore
    }
    return 'NIST-CSF';
  });
  const [expandedControlId, setExpandedControlId] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    fetchComplianceReport(selectedFramework);
  }, [selectedFramework, fetchComplianceReport]);

  const report = getComplianceReport(selectedFramework);

  if (!report) {
    return (
      <div className="compliance-loading">
        <div className="compliance-loading-card glassmorphism">
          <div className="loading-pulse-ring"></div>
          <p>Loading compliance alignment mapping...</p>
          <span className="loading-sub">Analyzing {selectedFramework} controls</span>
        </div>
      </div>
    );
  }

  // Find findings matching a control ID (mapped mock list)
  const getControlFindings = (findingIds: string[]) => {
    return findings.filter((f) => findingIds.includes(f.id));
  };

  // Category-specific color mapping for visual organization
  const getCategoryClass = (cat: string) => {
    const c = cat.toLowerCase();
    if (c === 'identify' || c === 'security') return 'cat-identify';
    if (c === 'protect' || c === 'confidentiality') return 'cat-protect';
    if (c === 'detect' || c === 'availability') return 'cat-detect';
    if (c === 'respond' || c === 'processing integrity') return 'cat-respond';
    if (c === 'recover' || c === 'privacy') return 'cat-recover';
    return 'cat-default';
  };

  const toggleControl = (id: string) => {
    setExpandedControlId(expandedControlId === id ? null : id);
  };

  const scoreColor = report.score > 80 ? '#10b981' : report.score > 60 ? '#f59e0b' : '#ef4444';

  return (
    <div className="compliance-container">
      {/* Framework Selector Tabs */}
      <div className="framework-selector animate-fade-in">
        {['NIST-CSF', 'SOC-2', 'OWASP-10'].map((fw) => {
          const isActive = selectedFramework === fw;
          const fwReport = getComplianceReport(fw);
          const score = fwReport?.score || 0;
          
          return (
            <button
              key={fw}
              className={`fw-tab glassmorphism ${isActive ? 'active' : ''}`}
              onClick={() => setSelectedFramework(fw)}
            >
              <div className="fw-icon-badge">{frameworkIcons[fw] || '🛡️'}</div>
              <div className="fw-tab-info">
                <h3>{fw}</h3>
                <div className="fw-score-progress-wrap">
                  <div className="fw-score-mini">Alignment: {score}%</div>
                  <div className="fw-mini-bar-track">
                    <div 
                      className="fw-mini-bar-fill" 
                      style={{ 
                        width: `${score}%`, 
                        backgroundColor: score > 80 ? '#10b981' : score > 60 ? '#f59e0b' : '#ef4444' 
                      }}
                    ></div>
                  </div>
                </div>
              </div>
              {isActive && <span className="fw-active-indicator">●</span>}
            </button>
          );
        })}
      </div>

      <div className="compliance-layout animate-slide-up">
        {/* Compliance Meter Panel */}
        <div className="compliance-score-card glassmorphism">
          <div className="score-card-header">
            <h2>{report.frameworkFullName}</h2>
            <span className={`risk-level-badge ${report.score > 80 ? 'low' : report.score > 60 ? 'medium' : 'critical'}`}>
              {report.score > 80 ? '● LOW RISK' : report.score > 60 ? '● MEDIUM RISK' : '● CRITICAL RISK'}
            </span>
          </div>
          <span className="last-assessed-date">
            Last assessed: {new Date(report.lastAssessed).toLocaleString()}
          </span>

          <div className="gauge-outer-wrap animate-scan-glow">
            <div className="compliance-gauge">
              <svg viewBox="0 0 36 36" className="circular-gauge speedometer-dial">
                <defs>
                  <linearGradient id="comp-grad-green" x1="0" y1="1" x2="1" y2="0">
                    <stop offset="0%" stopColor="#10b981" />
                    <stop offset="100%" stopColor="#059669" />
                  </linearGradient>
                  <linearGradient id="comp-grad-orange" x1="0" y1="1" x2="1" y2="0">
                    <stop offset="0%" stopColor="#f59e0b" />
                    <stop offset="100%" stopColor="#d97706" />
                  </linearGradient>
                  <linearGradient id="comp-grad-red" x1="0" y1="1" x2="1" y2="0">
                    <stop offset="0%" stopColor="#ef4444" />
                    <stop offset="100%" stopColor="#dc2626" />
                  </linearGradient>
                  <filter id="glow-comp">
                    <feGaussianBlur stdDeviation="0.8" result="blur"/>
                    <feMerge>
                      <feMergeNode in="blur"/>
                      <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                  </filter>
                </defs>
                {/* Tick marks around gauge */}
                {[...Array(9)].map((_, i) => {
                  const angle = -135 + i * (270 / 8);
                  const rad = (angle * Math.PI) / 180;
                  const r1 = 15.8;
                  const r2 = 17;
                  const cx = 18, cy = 18;
                  return (
                    <line
                      key={i}
                      x1={cx + r1 * Math.cos(rad)}
                      y1={cy + r1 * Math.sin(rad)}
                      x2={cx + r2 * Math.cos(rad)}
                      y2={cy + r2 * Math.sin(rad)}
                      stroke="rgba(255,255,255,0.08)"
                      strokeWidth="0.3"
                    />
                  );
                })}
                <path
                  className="gauge-bg"
                  strokeDasharray="75, 100"
                  strokeLinecap="round"
                  d="M18 3 a 15 15 0 1 1 0 30 a 15 15 0 1 1 0 -30"
                  fill="none"
                  stroke="rgba(255, 255, 255, 0.03)"
                  strokeWidth="2.5"
                  transform="rotate(-135 18 18)"
                />
                <path
                  className="gauge-fill"
                  strokeDasharray={`${report.score * 0.75}, 100`}
                  stroke={report.score > 80 ? 'url(#comp-grad-green)' : report.score > 60 ? 'url(#comp-grad-orange)' : 'url(#comp-grad-red)'}
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  filter="url(#glow-comp)"
                  d="M18 3 a 15 15 0 1 1 0 30 a 15 15 0 1 1 0 -30"
                  fill="none"
                  transform="rotate(-135 18 18)"
                />
              </svg>
              <div className="gauge-inner-value">
                <span className="gauge-score" style={{ color: scoreColor }}>{report.score}%</span>
                <span className="gauge-label">Alignment</span>
              </div>
            </div>
          </div>

          <div className="controls-summary-breakdown">
            <div className="breakdown-stat passed">
              <span className="stat-bullet">✔</span>
              <div className="stat-desc">
                <strong>{report.passed} passed</strong>
                <span>Audit aligned controls</span>
              </div>
              <span className="stat-pct">{report.totalControls > 0 ? Math.round((report.passed / report.totalControls) * 100) : 0}%</span>
            </div>
            <div className="breakdown-stat failed">
              <span className="stat-bullet">✖</span>
              <div className="stat-desc">
                <strong>{report.failed} failed</strong>
                <span>Requires remediation</span>
              </div>
              <span className="stat-pct">{report.totalControls > 0 ? Math.round((report.failed / report.totalControls) * 100) : 0}%</span>
            </div>
            <div className="breakdown-stat na">
              <span className="stat-bullet">●</span>
              <div className="stat-desc">
                <strong>{report.notApplicable} N/A</strong>
                <span>Excluded from scope</span>
              </div>
              <span className="stat-pct">—</span>
            </div>
          </div>

          {/* Category Coverage Bars */}
          <div className="category-coverage-section">
            <h4 className="coverage-title">Category Coverage</h4>
            {(() => {
              const categories = [...new Set(report.controls.map((c: any) => c.category))];
              return categories.map((cat: string) => {
                const catControls = report.controls.filter((c: any) => c.category === cat);
                const catPassed = catControls.filter((c: any) => c.status === 'passed').length;
                const catPct = catControls.length > 0 ? Math.round((catPassed / catControls.length) * 100) : 0;
                return (
                  <div key={cat} className="coverage-bar-row">
                    <div className="coverage-bar-label">
                      <span className={`cov-cat-dot ${getCategoryClass(cat)}`}></span>
                      <span>{cat}</span>
                    </div>
                    <div className="coverage-bar-track">
                      <div
                        className="coverage-bar-fill"
                        style={{
                          width: `${catPct}%`,
                          background: catPct === 100 ? '#10b981' : catPct >= 50 ? '#f59e0b' : '#ef4444'
                        }}
                      />
                    </div>
                    <span className="coverage-bar-value">{catPassed}/{catControls.length}</span>
                  </div>
                );
              });
            })()}
          </div>
        </div>

        {/* Detailed Controls Table List */}
        <div className="controls-list-card glassmorphism">
          <div className="checklist-header">
            <h2>Audit Controls Checklist</h2>
            <div className="checklist-header-meta">
              <span className="checklist-mini-pill passed">{report.passed} ✔</span>
              <span className="checklist-mini-pill failed">{report.failed} ✖</span>
              <span className="checklist-count-tag">{report.totalControls} Controls</span>
            </div>
          </div>
          
          <div className="controls-list stagger-children">
            {report.controls.map((control: any, index: number) => {
              const controlFindings = getControlFindings(control.findings);
              const isExpanded = expandedControlId === control.id;
              
              return (
                <div 
                  key={control.id} 
                  className={`control-item-row ${isExpanded ? 'expanded' : ''} ${control.status}`}
                  onClick={() => toggleControl(control.id)}
                  style={{ animationDelay: `${index * 40}ms` }}
                >
                  <div className="control-header-line">
                    <span className={`control-status-dot ${control.status}`}>
                      {control.status === 'passed' ? '✔' : control.status === 'failed' ? '✖' : '—'}
                    </span>
                    
                    <div className="control-meta-info">
                      <div className="control-title-row">
                        <h3>{control.name}</h3>
                        <span className={`control-cat-tag ${getCategoryClass(control.category)}`}>
                          {control.category}
                        </span>
                      </div>
                      <p className="control-desc">{control.description}</p>
                    </div>

                    <div className="control-right-meta">
                      <span className="control-id">{control.id}</span>
                      <span className={`accordion-chevron ${isExpanded ? 'rotated' : ''}`}>▼</span>
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="control-expanded-details" onClick={(e) => e.stopPropagation()}>
                      <div className="control-remediation-info">
                        <h4>Audit Requirement Details</h4>
                        <p>{control.description}</p>
                        <div className="control-audit-meta">
                          <span className="audit-meta-tag">Framework: <strong>{selectedFramework}</strong></span>
                          <span className="audit-meta-tag">Control ID: <strong>{control.id}</strong></span>
                          <span className="audit-meta-tag">Category: <strong>{control.category}</strong></span>
                          <span className={`audit-meta-tag status-tag ${control.status}`}>Status: <strong>{control.status.toUpperCase()}</strong></span>
                        </div>
                      </div>

                      {controlFindings.length > 0 ? (
                        <div className="control-violations-box">
                          <p className="violations-title">Violating Vulnerability Findings ({controlFindings.length})</p>
                          <div className="violating-vulns-list">
                            {controlFindings.map((f) => (
                              <div 
                                key={f.id} 
                                className="violating-vuln-item interactive-vuln-item"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  navigate(`/findings?search=${encodeURIComponent(f.title)}`);
                                }}
                                title="Click to inspect this finding on the Findings page"
                              >
                                <span className={`severity-bullet ${f.severity}`}></span>
                                <span className="vuln-title-ref">{f.title}</span>
                                <span className="vuln-path-ref">{f.filePath.split(/[/\\]/).pop()}:{f.lineNumber}</span>
                                <span className="vuln-arrow">→</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      ) : control.status === 'failed' ? (
                        <div className="control-violations-box">
                          <p className="violations-title">Control Baseline Violation Detected</p>
                          <p className="violations-desc">Active vulnerabilities in the codebase violate this control's security requirements. Remediation is required to achieve compliance.</p>
                          <div 
                            className="violating-vuln-item interactive-vuln-item violation-navigate"
                            onClick={(e) => {
                              e.stopPropagation();
                              navigate(`/findings`);
                            }}
                            title="View all findings on the Findings page"
                          >
                            <span className="severity-bullet critical"></span>
                            <span className="vuln-title-ref">{control.name}</span>
                            <span className="vuln-path-ref">Inspect findings →</span>
                          </div>
                        </div>
                      ) : (
                        <div className="control-status-success-box">
                          <span className="success-icon">🛡️</span>
                          <p>No active security findings violate this control baseline. Alignment verified.</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Compliance;
