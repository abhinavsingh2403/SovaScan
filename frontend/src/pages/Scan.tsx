import React, { useState, useEffect } from 'react';
import { useStore } from '../store';
import './Scan.css';

const Scan: React.FC = () => {
  const { startScan, cancelScan, scanProgress, scans, fetchScans } = useStore();
  const [targetPath, setTargetPath] = useState('');
  const [scanType, setScanType] = useState(() => {
    try {
      const stored = localStorage.getItem('sovascan-settings');
      if (stored) {
        const parsed = JSON.parse(stored);
        return parsed.defaultScanType || 'full';
      }
    } catch {
      // ignore
    }
    return 'full';
  });
  const [frameworks, setFrameworks] = useState<string[]>(['RBI-CSF', 'NIST-CSF', 'SOC-2']);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [excludeDirs, setExcludeDirs] = useState('node_modules, .git, venv');

  const [scanLogs, setScanLogs] = useState<string[]>([]);
  const terminalEndRef = React.useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  useEffect(() => {
    if (scanProgress.running) {
      if (scanLogs.length === 0) {
        setScanLogs([
          `[SYSTEM] Initializing SovaScan engine for target: ${targetPath}...`,
          "[SYSTEM] Establishing WebSocket handshake...",
          "[SYSTEM] Queuing codebase scan target..."
        ]);
      }
      if (scanProgress.phase) {
        const logMsg = `[ENGINE] Entering phase: ${scanProgress.phase}`;
        setScanLogs((prev) => {
          if (prev.length > 0 && prev[prev.length - 1] === logMsg) return prev;
          return [...prev, logMsg];
        });
      }
    } else {
      setScanLogs([]);
    }
  }, [scanProgress.running, scanProgress.phase, targetPath]);

  useEffect(() => {
    if (scanProgress.running && scanProgress.findingsCount > 0) {
      setScanLogs((prev) => [
        ...prev,
        `[ALERT] Discovered security vulnerability #${scanProgress.findingsCount}: MATCHED!`
      ]);
    }
  }, [scanProgress.running, scanProgress.findingsCount]);

  useEffect(() => {
    if (terminalEndRef.current && terminalEndRef.current.parentElement) {
      const container = terminalEndRef.current.parentElement;
      container.scrollTop = container.scrollHeight;
    }
  }, [scanLogs]);

  const handleFrameworkToggle = (fw: string) => {
    if (frameworks.includes(fw)) {
      setFrameworks(frameworks.filter((f) => f !== fw));
    } else {
      setFrameworks([...frameworks, fw]);
    }
  };

  const handleStartScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetPath.trim()) return;
    startScan(targetPath, scanType, frameworks);
  };

  return (
    <div className="scan-container">
      <div className="scan-grid">
        {/* Configuration Panel */}
        <div className="config-panel glassmorphism animate-fade-in">
          <h2>Start New Security Scan</h2>
          <form onSubmit={handleStartScan} className="scan-form">
            <div className="form-group">
              <label htmlFor="targetPath">Target Path or Repository URL:</label>
              <div className="input-with-icon">
                <span className="input-icon">
                  {targetPath.startsWith('http://') || targetPath.startsWith('https://') ? (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
                      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
                    </svg>
                  ) : (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
                    </svg>
                  )}
                </span>
                <input
                  type="text"
                  id="targetPath"
                  placeholder="e.g., C:/projects/my-app OR https://github.com/user/repo"
                  value={targetPath}
                  onChange={(e) => setTargetPath(e.target.value)}
                  disabled={scanProgress.running}
                  required
                />
              </div>
              <p className="field-help">Specify a local directory path OR paste a remote git repository URL.</p>
            </div>

            <div className="form-group">
              <label>Scan Type:</label>
              <div className="scan-type-options">
                <label className={`scan-type-card ${scanType === 'full' ? 'active' : ''}`}>
                  <input
                    type="radio"
                    name="scanType"
                    value="full"
                    checked={scanType === 'full'}
                    onChange={() => setScanType('full')}
                    disabled={scanProgress.running}
                  />
                  <div className="radio-content">
                    <span className="radio-icon">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                      </svg>
                    </span>
                    <div className="radio-text">
                      <strong>Full Scan</strong>
                      <span>Check CVEs, Secrets, & Misconfigs</span>
                    </div>
                  </div>
                </label>

                <label className={`scan-type-card ${scanType === 'dependencies' ? 'active' : ''}`}>
                  <input
                    type="radio"
                    name="scanType"
                    value="dependencies"
                    checked={scanType === 'dependencies'}
                    onChange={() => setScanType('dependencies')}
                    disabled={scanProgress.running}
                  />
                  <div className="radio-content">
                    <span className="radio-icon">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
                        <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
                        <line x1="12" y1="22.08" x2="12" y2="12" />
                      </svg>
                    </span>
                    <div className="radio-text">
                      <strong>Dependencies</strong>
                      <span>SBOM & Software Vulnerabilities</span>
                    </div>
                  </div>
                </label>

                <label className={`scan-type-card ${scanType === 'secrets' ? 'active' : ''}`}>
                  <input
                    type="radio"
                    name="scanType"
                    value="secrets"
                    checked={scanType === 'secrets'}
                    onChange={() => setScanType('secrets')}
                    disabled={scanProgress.running}
                  />
                  <div className="radio-content">
                    <span className="radio-icon">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="7.5" cy="15.5" r="4.5" />
                        <path d="M21 2l-9.6 9.6" />
                        <path d="M15.5 7.5l3 3L22 7l-3-3" />
                      </svg>
                    </span>
                    <div className="radio-text">
                      <strong>Secrets</strong>
                      <span>API Keys, Credentials, Tokens</span>
                    </div>
                  </div>
                </label>

                <label className={`scan-type-card ${scanType === 'sast' ? 'active' : ''}`}>
                  <input
                    type="radio"
                    name="scanType"
                    value="sast"
                    checked={scanType === 'sast'}
                    onChange={() => setScanType('sast')}
                    disabled={scanProgress.running}
                  />
                  <div className="radio-content">
                    <span className="radio-icon">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                        <polyline points="14 2 14 8 20 8" />
                        <line x1="16" y1="13" x2="8" y2="13" />
                        <line x1="16" y1="17" x2="8" y2="17" />
                        <polyline points="10 9 9 9 8 9" />
                      </svg>
                    </span>
                    <div className="radio-text">
                      <strong>SAST Only</strong>
                      <span>Static Application Security Testing</span>
                    </div>
                  </div>
                </label>

                <label className={`scan-type-card ${scanType === 'git-history' ? 'active' : ''}`}>
                  <input
                    type="radio"
                    name="scanType"
                    value="git-history"
                    checked={scanType === 'git-history'}
                    onChange={() => setScanType('git-history')}
                    disabled={scanProgress.running}
                  />
                  <div className="radio-content">
                    <span className="radio-icon">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="18" r="3" />
                        <circle cx="6" cy="6" r="3" />
                        <circle cx="18" cy="6" r="3" />
                        <path d="M18 9v1a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V9" />
                        <path d="M12 12v3" />
                      </svg>
                    </span>
                    <div className="radio-text">
                      <strong>Git History</strong>
                      <span>Scan Commit History for Secrets</span>
                    </div>
                  </div>
                </label>
              </div>
            </div>

            <div className="form-group">
              <label>Compliance Framework Mapping:</label>
              <div className="checkboxes-row">
                {['RBI-CSF', 'NIST-CSF', 'SOC-2', 'OWASP-10'].map((fw) => (
                  <label key={fw} className={`checkbox-card ${frameworks.includes(fw) ? 'active' : ''}`}>
                    <input
                      type="checkbox"
                      checked={frameworks.includes(fw)}
                      onChange={() => handleFrameworkToggle(fw)}
                      disabled={scanProgress.running}
                    />
                    <span>{fw}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Advanced Toggle */}
            <div className="advanced-toggle">
              <button
                type="button"
                className="ghost-btn"
                onClick={() => setShowAdvanced(!showAdvanced)}
              >
                {showAdvanced ? 'Hide Advanced Options' : 'Show Advanced Options'}
              </button>
            </div>

            {showAdvanced && (
              <div className="advanced-options animate-fade-in">
                <div className="form-group">
                  <label htmlFor="excludeDirs">Exclude Directories (comma separated):</label>
                  <input
                    type="text"
                    id="excludeDirs"
                    value={excludeDirs}
                    onChange={(e) => setExcludeDirs(e.target.value)}
                    disabled={scanProgress.running}
                  />
                </div>
              </div>
            )}

            <button
              type="submit"
              className={`submit-scan-btn ${!scanProgress.running && targetPath.trim() ? 'glow-cta' : ''}`}
              disabled={scanProgress.running || !targetPath.trim()}
            >
              {scanProgress.running ? 'Scanning Execution in Progress...' : '🦉 Launch SovaScan'}
            </button>
          </form>
        </div>

        {/* Progress & Live Results Panel */}
        <div className="progress-panel glassmorphism animate-fade-in">
          {scanProgress.running ? (
            <div className="progress-active-state">
              <div className="radar-hud-container animate-scan-glow">
                <div className="radar-ping-ring animate-radar-pulse"></div>
                <div className="radar-ping-ring-2"></div>
                <div className="radar-sweep-line animate-radar-spin"></div>
                <div className="radar-core-glow"></div>
                <span className="radar-icon-center">🦉</span>
              </div>
              
              <h3>Analyzing Target</h3>
              <p className="target-lbl truncate">{targetPath}</p>

              <div className="progress-bar-container">
                <div
                  className="progress-bar-fill"
                  style={{ width: `${scanProgress.percent}%` }}
                ></div>
              </div>
              <div className="progress-meta">
                <span className="percent-num">{scanProgress.percent}%</span>
                <span className="phase-num">{scanProgress.phase} phase</span>
              </div>

              <div className="cancel-scan-action" style={{ textAlign: 'center', margin: '8px 0 12px 0' }}>
                <button
                  type="button"
                  className="btn btn-danger btn-sm"
                  onClick={() => cancelScan(scanProgress.activeScanId)}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 16px', fontSize: '0.8125rem', fontWeight: 600 }}
                >
                  🛑 Cancel Scan
                </button>
              </div>

              <div className="findings-ticker">
                <span className="ticker-number font-red">{scanProgress.findingsCount}</span>
                <p>Security findings discovered so far</p>
              </div>

              {/* Scrolling Terminal Console Logs */}
              <div className="terminal-log-container">
                <div className="terminal-header">
                  <span className="dot dot-red"></span>
                  <span className="dot dot-yellow"></span>
                  <span className="dot dot-green"></span>
                  <span className="terminal-title">sovascan@engine-log:~</span>
                </div>
                <div className="terminal-body">
                  {scanLogs.map((log, index) => (
                    <div key={index} className={`terminal-line ${log.startsWith('[ALERT]') ? 'warn' : ''}`}>
                      <span className="term-prompt">$</span> {log}
                    </div>
                  ))}
                  <div ref={terminalEndRef} />
                </div>
              </div>
            </div>
          ) : (
            <div className="progress-idle-state">
              <div className="idle-reticle-container">
                <div className="idle-reticle-ring-1 animate-radar-spin"></div>
                <div className="idle-reticle-ring-2"></div>
                <div className="owl-mascot">🦉</div>
              </div>
              <h3>Scan Engine Idle</h3>
              <p>Configure parameters on the left and start the analyzer to view live results.</p>
            </div>
          )}
        </div>
      </div>

      {/* History section */}
      <div className="scan-history-section glassmorphism animate-slide-up console-window">
        <div className="terminal-header">
          <span className="dot dot-red"></span>
          <span className="dot dot-yellow"></span>
          <span className="dot dot-green"></span>
          <span className="terminal-title">sovascan@history:~</span>
        </div>
        <div className="console-body">
          <h2>Scan Run History</h2>
          <div className="table-responsive">
            <table className="scan-history-table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Type</th>
                  <th>Run Date</th>
                  <th>Findings Count</th>
                  <th>Duration</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 10).map((scan) => (
                  <tr key={scan.id}>
                    <td className="monospace-td" title={scan.target}>{scan.target}</td>
                    <td><span className="badge-type">{scan.scanType}</span></td>
                    <td>{new Date(scan.createdAt).toLocaleString()}</td>
                    <td>
                      <span className="scan-count-tag red-tag">{scan.criticalCount}</span>
                      <span className="scan-count-tag orange-tag">{scan.highCount}</span>
                      <span className="scan-count-tag yellow-tag">{scan.mediumCount}</span>
                    </td>
                    <td>
                      {scan.completedAt
                        ? `${Math.round(
                            (new Date(scan.completedAt).getTime() -
                              new Date(scan.startedAt).getTime()) /
                              1000
                          )}s`
                        : '-'}
                    </td>
                    <td>
                      <span className={`status-badge ${scan.status}`}>{scan.status}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Scan;
