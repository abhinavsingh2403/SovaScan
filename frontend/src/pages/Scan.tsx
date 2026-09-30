import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Crosshair,
  Package,
  KeyRound,
  FileCode2,
  GitBranch,
  FolderSearch,
  Globe,
  Play,
  XCircle,
  Terminal,
  Landmark,
  ShieldCheck,
  Lock,
  ShieldAlert,
  AlertTriangle,
  Cloud,
  HardDrive,
  ExternalLink
} from 'lucide-react';
import { api } from '../api/client';
import { useStore } from '../store';
import { CyberRadarHUD } from '../components/CyberRadarHUD';
import './Scan.css';

const fwIcons: Record<string, React.ReactNode> = {
  'RBI-CSF': <Landmark size={14} strokeWidth={2} />,
  'NIST-CSF': <ShieldCheck size={14} strokeWidth={2} />,
  'SOC-2': <Lock size={14} strokeWidth={2} />,
  'OWASP-10': <ShieldAlert size={14} strokeWidth={2} />,
};

const Scan: React.FC = () => {
  const { startScan, cancelScan, scanProgress, scans, fetchScans } = useStore();
  const [targetPath, setTargetPath] = useState('https://github.com/abhinavsingh2403/SovaScan');
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

  const [deploymentMode, setDeploymentMode] = useState<'cloud' | 'local' | null>(null);

  useEffect(() => {
    api.getDeploymentInfo()
      .then((res: any) => setDeploymentMode(res.data?.mode || 'local'))
      .catch(() => setDeploymentMode('local'));
  }, []);

  const isLocalPath = (path: string) => {
    const trimmed = path.trim();
    return (
      /^[a-zA-Z]:[\\/]/.test(trimmed) ||
      trimmed.startsWith('/') ||
      trimmed.startsWith('~') ||
      trimmed.startsWith('\\\\') ||
      trimmed.startsWith('./')
    );
  };

  const showCloudWarning = deploymentMode === 'cloud' && isLocalPath(targetPath);

  const [scanLogs, setScanLogs] = useState<string[]>([]);
  const terminalEndRef = React.useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  useEffect(() => {
    if (!scanProgress.running) {
      fetchScans();
    }
  }, [scanProgress.running, fetchScans]);

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
          
          {/* Target Mode Quick Selector */}
          <div className="target-mode-pill-row" style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
            <button
              type="button"
              onClick={() => setTargetPath('https://github.com/abhinavsingh2403/SovaScan')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '12px',
                padding: '7px 14px',
                borderRadius: '8px',
                border: targetPath.includes('github.com') ? '1px solid var(--accent-primary)' : '1px solid var(--border-color)',
                background: targetPath.includes('github.com') ? 'var(--accent-glow)' : 'rgba(255,255,255,0.02)',
                color: targetPath.includes('github.com') ? 'var(--accent-primary)' : 'var(--text-secondary)',
                cursor: 'pointer',
                fontWeight: 600,
                transition: 'all 0.2s ease',
              }}
            >
              <Globe size={14} />
              <span>GitHub Repository (Remote)</span>
            </button>
            <button
              type="button"
              onClick={() => setTargetPath('.')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '12px',
                padding: '7px 14px',
                borderRadius: '8px',
                border: targetPath === '.' ? '1px solid var(--accent-primary)' : '1px solid var(--border-color)',
                background: targetPath === '.' ? 'var(--accent-glow)' : 'rgba(255,255,255,0.02)',
                color: targetPath === '.' ? 'var(--accent-primary)' : 'var(--text-secondary)',
                cursor: 'pointer',
                fontWeight: 600,
                transition: 'all 0.2s ease',
              }}
            >
              <FolderSearch size={14} />
              <span>Project Scope (.)</span>
            </button>
            <button
              type="button"
              onClick={() => {
                if (targetPath.includes('github.com') || targetPath === '.') {
                  setTargetPath(deploymentMode === 'cloud' ? 'https://github.com/abhinavsingh2403/SovaScan' : 'C:\\Users\\ss\\Documents\\SovaScan');
                }
              }}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '12px',
                padding: '7px 14px',
                borderRadius: '8px',
                border: (!targetPath.includes('github.com') && targetPath !== '.') ? '1px solid var(--accent-primary)' : '1px solid var(--border-color)',
                background: (!targetPath.includes('github.com') && targetPath !== '.') ? 'var(--accent-glow)' : 'rgba(255,255,255,0.02)',
                color: (!targetPath.includes('github.com') && targetPath !== '.') ? 'var(--accent-primary)' : 'var(--text-secondary)',
                cursor: 'pointer',
                fontWeight: 600,
                transition: 'all 0.2s ease',
              }}
            >
              <HardDrive size={14} />
              <span>Custom Local Path</span>
            </button>
          </div>

          <form onSubmit={handleStartScan} className="scan-form">
            <div className="form-group">
              <label htmlFor="targetPath">Target Directory or Git Repository URL:</label>
              <div className="input-with-icon">
                <span className="input-icon">
                  {targetPath.startsWith('http://') || targetPath.startsWith('https://') ? (
                    <Globe size={16} strokeWidth={2} style={{ color: 'var(--accent-telemetry)' }} />
                  ) : (
                    <FolderSearch size={16} strokeWidth={2} style={{ color: 'var(--accent-primary)' }} />
                  )}
                </span>
                <input
                  type="text"
                  id="targetPath"
                  placeholder="e.g. https://github.com/user/repo or . for application root"
                  value={targetPath}
                  onChange={(e) => setTargetPath(e.target.value)}
                  disabled={scanProgress.running}
                  required
                />
              </div>

              {showCloudWarning ? (
                <div className="cloud-path-notice" style={{
                  marginTop: '10px',
                  padding: '12px 16px',
                  background: 'rgba(245, 158, 11, 0.08)',
                  border: '1px solid rgba(245, 158, 11, 0.35)',
                  borderRadius: '8px',
                  display: 'flex',
                  gap: '10px',
                  alignItems: 'flex-start',
                  color: '#fef3c7',
                  fontSize: '12px',
                }}>
                  <AlertTriangle size={18} style={{ color: '#f59e0b', flexShrink: 0, marginTop: '2px' }} />
                  <div>
                    <strong style={{ color: '#f59e0b', display: 'block', marginBottom: '3px' }}>
                      Cloud Environment Notice: Local paths cannot be read by cloud servers
                    </strong>
                    SovaScan is currently hosted on cloud infrastructure. Cloud servers cannot read paths on your private local machine ({targetPath}).
                    To scan your repository, provide its GitHub repository URL or use '.' for the server workspace.
                    <div style={{ marginTop: '8px' }}>
                      <button
                        type="button"
                        onClick={() => setTargetPath('https://github.com/abhinavsingh2403/SovaScan')}
                        style={{
                          background: '#f59e0b',
                          color: '#000',
                          fontWeight: 600,
                          border: 'none',
                          padding: '5px 12px',
                          borderRadius: '5px',
                          cursor: 'pointer',
                          fontSize: '11px',
                        }}
                      >
                        Switch to GitHub Repository URL
                      </button>
                    </div>
                  </div>
                </div>
              ) : (
                <p className="field-help">
                  {targetPath.startsWith('http://') || targetPath.startsWith('https://')
                    ? 'Remote GitHub repository scan: SovaScan performs git clone, SAST, secrets, and CVE analysis.'
                    : targetPath === '.'
                    ? 'Project scope scan: analyzes application root workspace directly.'
                    : 'Local directory scan: scans filesystem path on host.'}
                </p>
              )}
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
                      <Crosshair size={18} strokeWidth={2} />
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
                      <Package size={18} strokeWidth={2} />
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
                      <KeyRound size={18} strokeWidth={2} />
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
                      <FileCode2 size={18} strokeWidth={2} />
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
                      <GitBranch size={18} strokeWidth={2} />
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
                    <span className="checkbox-icon">{fwIcons[fw]}</span>
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
              className={`submit-scan-btn ${!scanProgress.running && targetPath.trim() && !showCloudWarning ? 'glow-cta' : ''}`}
              disabled={scanProgress.running || !targetPath.trim() || showCloudWarning}
              title={showCloudWarning ? "Cannot scan private local filesystem paths while running in cloud deployment mode" : undefined}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                opacity: showCloudWarning ? 0.6 : 1,
                cursor: showCloudWarning ? 'not-allowed' : undefined,
              }}
            >
              {scanProgress.running ? (
                <>
                  <div className="spinner" style={{ width: 16, height: 16, borderTopColor: '#fff' }} />
                  <span>Scanning Execution in Progress...</span>
                </>
              ) : (
                <>
                  <Play size={16} fill="currentColor" />
                  <span>Launch SovaScan Analysis</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Progress & Live Results Panel */}
        <div className="progress-panel glassmorphism animate-fade-in">
          {scanProgress.running ? (
            <div className="progress-active-state">
              <CyberRadarHUD
                active={true}
                phase={scanProgress.phase}
                percent={scanProgress.percent}
                findingsCount={scanProgress.findingsCount}
                target={targetPath}
              />
              
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
                  <XCircle size={15} strokeWidth={2} /> Cancel Scan
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
              <CyberRadarHUD
                active={false}
                phase="Engine Idle"
                percent={0}
                findingsCount={0}
              />
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
                  <th>Findings</th>
                  <th>Duration</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {scans.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-secondary)' }}>
                      No scan history found. Launch a scan above to start analyzing codebases.
                    </td>
                  </tr>
                ) : (
                  scans.slice(0, 15).map((scan) => (
                    <tr key={scan.id}>
                      <td className="monospace-td" title={scan.target}>
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', maxWidth: '280px' }} className="truncate">
                          {scan.target.startsWith('http') ? (
                            <Globe size={13} style={{ color: '#06b6d4', flexShrink: 0 }} />
                          ) : (
                            <FolderSearch size={13} style={{ color: '#f59e0b', flexShrink: 0 }} />
                          )}
                          <span className="truncate">{scan.target}</span>
                        </div>
                      </td>
                      <td><span className="badge-type">{scan.scanType}</span></td>
                      <td>{new Date(scan.createdAt).toLocaleString()}</td>
                      <td>
                        <div style={{ display: 'inline-flex', gap: '4px', alignItems: 'center' }}>
                          <span className="scan-count-tag red-tag" title="Critical">{scan.criticalCount}</span>
                          <span className="scan-count-tag orange-tag" title="High">{scan.highCount}</span>
                          <span className="scan-count-tag yellow-tag" title="Medium">{scan.mediumCount}</span>
                          <span style={{ fontSize: '11px', color: 'var(--text-secondary)', marginLeft: '4px' }}>
                            ({scan.totalFindings})
                          </span>
                        </div>
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
                      <td>
                        <Link
                          to={`/findings?scan=${scan.id}`}
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '5px',
                            padding: '4px 10px',
                            borderRadius: '6px',
                            background: 'rgba(245, 158, 11, 0.12)',
                            color: 'var(--accent-primary)',
                            fontSize: '11px',
                            fontWeight: 600,
                            textDecoration: 'none',
                            border: '1px solid rgba(245, 158, 11, 0.25)',
                            transition: 'all 0.2s ease',
                          }}
                        >
                          <span>View Findings</span>
                          <ExternalLink size={11} />
                        </Link>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Scan;
