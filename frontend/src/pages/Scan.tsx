import React, { useState, useEffect } from 'react';
import { useStore } from '../store';
import './Scan.css';

const Scan: React.FC = () => {
  const { startScan, scanProgress, scans, fetchScans } = useStore();
  const [targetPath, setTargetPath] = useState('');
  const [scanType, setScanType] = useState('full');
  const [frameworks, setFrameworks] = useState<string[]>(['NIST-CSF', 'SOC-2']);
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
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
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
                  {targetPath.startsWith('http://') || targetPath.startsWith('https://') ? '🔗' : '📁'}
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
                    <span className="radio-icon">⚡</span>
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
                    <span className="radio-icon">📦</span>
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
                    <span className="radio-icon">🔑</span>
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
                    <span className="radio-icon">🔬</span>
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
                    <span className="radio-icon">📜</span>
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
                {['NIST-CSF', 'SOC-2', 'OWASP-10'].map((fw) => (
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
              className="submit-scan-btn"
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
                    <td className="monospace-td">{scan.target}</td>
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
