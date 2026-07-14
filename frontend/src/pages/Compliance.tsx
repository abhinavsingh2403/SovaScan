import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useStore } from '../store';
import './Compliance.css';

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
        <div className="spinner"></div>
        <p>Loading compliance alignment mapping...</p>
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
              <div className="fw-icon-badge">🛡️</div>
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
            </button>
          );
        })}
      </div>

      <div className="compliance-layout animate-slide-up">
        {/* Compliance Meter Panel */}
        <div className="compliance-score-card glassmorphism">
          <h2>{report.frameworkFullName}</h2>
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
                <span className="gauge-score">{report.score}%</span>
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
            </div>
            <div className="breakdown-stat failed">
              <span className="stat-bullet">✖</span>
              <div className="stat-desc">
                <strong>{report.failed} failed</strong>
                <span>Requires remediation</span>
              </div>
            </div>
            <div className="breakdown-stat na">
              <span className="stat-bullet">●</span>
              <div className="stat-desc">
                <strong>{report.notApplicable} N/A</strong>
                <span>Excluded from scope</span>
              </div>
            </div>
          </div>
        </div>

        {/* Detailed Controls Table List */}
        <div className="controls-list-card glassmorphism">
          <div className="checklist-header">
            <h2>Audit Controls Checklist</h2>
            <span className="checklist-count-tag">{report.totalControls} Controls Total</span>
          </div>
          
          <div className="controls-list stagger-children">
            {report.controls.map((control) => {
              const controlFindings = getControlFindings(control.findings);
              const isExpanded = expandedControlId === control.id;
              
              return (
                <div 
                  key={control.id} 
                  className={`control-item-row ${isExpanded ? 'expanded' : ''} ${control.status}`}
                  onClick={() => toggleControl(control.id)}
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
                        <p>This control validates alignment with standard framework controls mapping. Run regular codebase scans to verify continuous compliance posture.</p>
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
