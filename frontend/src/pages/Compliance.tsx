import React, { useState, useEffect } from 'react';
import { useStore } from '../store';
import './Compliance.css';

const Compliance: React.FC = () => {
  const { getComplianceReport, fetchComplianceReport, findings } = useStore();
  const [selectedFramework, setSelectedFramework] = useState('NIST-CSF');

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

  return (
    <div className="compliance-container">
      {/* Framework Selector Tabs */}
      <div className="framework-selector animate-fade-in">
        {['NIST-CSF', 'SOC-2', 'OWASP-10'].map((fw) => {
          const isActive = selectedFramework === fw;
          const fwReport = getComplianceReport(fw);
          return (
            <button
              key={fw}
              className={`fw-tab glassmorphism ${isActive ? 'active' : ''}`}
              onClick={() => setSelectedFramework(fw)}
            >
              <span className="fw-icon">🛡️</span>
              <div className="fw-tab-info">
                <h3>{fw}</h3>
                <p className="fw-score-mini">Score: {fwReport?.score}%</p>
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

          <div className="gauge-outer-wrap">
            <div className="compliance-gauge">
              <svg viewBox="0 0 36 36" className="circular-gauge">
                <path
                  className="gauge-bg"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className="gauge-fill"
                  strokeDasharray={`${report.score}, 100`}
                  stroke={report.score > 80 ? '#10b981' : report.score > 60 ? '#f59e0b' : '#ef4444'}
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="gauge-inner-value">
                <span className="gauge-score">{report.score}%</span>
                <span className="gauge-label">Compliance</span>
              </div>
            </div>
          </div>

          <div className="controls-summary-breakdown">
            <div className="breakdown-stat passed">
              <span className="stat-bullet">●</span>
              <div className="stat-desc">
                <strong>{report.passed}</strong>
                <span>Passed Controls</span>
              </div>
            </div>
            <div className="breakdown-stat failed">
              <span className="stat-bullet">●</span>
              <div className="stat-desc">
                <strong>{report.failed}</strong>
                <span>Failed Controls</span>
              </div>
            </div>
            <div className="breakdown-stat na">
              <span className="stat-bullet">●</span>
              <div className="stat-desc">
                <strong>{report.notApplicable}</strong>
                <span>N/A Controls</span>
              </div>
            </div>
          </div>
        </div>

        {/* Detailed Controls Table List */}
        <div className="controls-list-card glassmorphism">
          <h2>Audit Controls Checklist ({report.totalControls} Controls)</h2>
          <div className="controls-list">
            {report.controls.map((control) => {
              const controlFindings = getControlFindings(control.findings);
              return (
                <div key={control.id} className="control-item-row">
                  <div className="control-header-line">
                    <span className={`control-status-dot ${control.status}`}>
                      {control.status === 'passed' ? '✔' : control.status === 'failed' ? '✖' : '-'}
                    </span>
                    <div className="control-meta-info">
                      <div className="control-title-row">
                        <h3>{control.name}</h3>
                        <span className="control-cat-tag">{control.category}</span>
                      </div>
                      <p className="control-desc">{control.description}</p>
                    </div>
                    <span className="control-id">{control.id}</span>
                  </div>

                  {controlFindings.length > 0 && (
                    <div className="control-violations-box">
                      <p className="violations-title">Violating Vulnerabilities:</p>
                      {controlFindings.map((f) => (
                        <div key={f.id} className="violating-vuln-item">
                          <span className={`severity-bullet ${f.severity}`}></span>
                          <span className="vuln-title-ref">{f.title}</span>
                          <span className="vuln-path-ref">{f.filePath}:{f.lineNumber}</span>
                        </div>
                      ))}
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
