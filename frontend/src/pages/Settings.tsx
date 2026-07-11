import React, { useState, useEffect } from 'react';
import './Settings.css';

/* ============================================================
   Settings Page
   ============================================================
   Provides user-configurable preferences for SovaScan such as
   API connection, scan defaults, notification toggles, and
   data-management actions.
   ============================================================ */

interface SettingsState {
  apiBaseUrl: string;
  scanTimeout: number;
  defaultScanType: string;
  maxFileSize: number;
  enableNotifications: boolean;
  autoRefreshDashboard: boolean;
  darkMode: boolean;
  defaultFramework: string;
}

const DEFAULT_SETTINGS: SettingsState = {
  apiBaseUrl: '/api/v1',
  scanTimeout: 300,
  defaultScanType: 'full',
  maxFileSize: 10,
  enableNotifications: true,
  autoRefreshDashboard: true,
  darkMode: true,
  defaultFramework: 'NIST-CSF',
};

const STORAGE_KEY = 'sovascan-settings';

const Settings: React.FC = () => {
  const [settings, setSettings] = useState<SettingsState>(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      return stored ? { ...DEFAULT_SETTINGS, ...JSON.parse(stored) } : DEFAULT_SETTINGS;
    } catch {
      return DEFAULT_SETTINGS;
    }
  });
  const [saved, setSaved] = useState(false);

  /* Persist on save */
  const handleSave = () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
    setSaved(true);
  };

  const handleReset = () => {
    setSettings(DEFAULT_SETTINGS);
    localStorage.removeItem(STORAGE_KEY);
    setSaved(false);
  };

  const handleClearData = () => {
    if (window.confirm('Are you sure you want to clear all cached scan data? This cannot be undone.')) {
      localStorage.clear();
      setSettings(DEFAULT_SETTINGS);
    }
  };

  /* Auto-dismiss toast */
  useEffect(() => {
    if (!saved) return;
    const timer = setTimeout(() => setSaved(false), 2500);
    return () => clearTimeout(timer);
  }, [saved]);

  const update = <K extends keyof SettingsState>(key: K, value: SettingsState[K]) => {
    setSettings((prev) => ({ ...prev, [key]: value }));
  };

  return (
    <div className="settings animate-fade-in">
      {/* ---- API Configuration ---- */}
      <section className="settings__section glassmorphism">
        <div className="settings__section-header">
          <span className="settings__section-icon">🔗</span>
          <h2 className="settings__section-title">API Configuration</h2>
        </div>
        <p className="settings__section-desc">
          Configure the backend connection and request settings.
        </p>

        <div className="settings__row">
          <div className="settings__row-info">
            <div className="settings__row-label">API Base URL</div>
            <div className="settings__row-hint">
              The root URL used for all backend requests.
            </div>
          </div>
          <input
            className="settings__input"
            type="text"
            value={settings.apiBaseUrl}
            onChange={(e) => update('apiBaseUrl', e.target.value)}
            placeholder="/api/v1"
          />
        </div>

        <div className="settings__row">
          <div className="settings__row-info">
            <div className="settings__row-label">Scan Timeout (seconds)</div>
            <div className="settings__row-hint">
              Maximum time a scan is allowed to run before timing out.
            </div>
          </div>
          <input
            className="settings__input"
            type="number"
            min={30}
            max={3600}
            value={settings.scanTimeout}
            onChange={(e) => update('scanTimeout', Number(e.target.value))}
          />
        </div>

        <div className="settings__row">
          <div className="settings__row-info">
            <div className="settings__row-label">Max File Size (MB)</div>
            <div className="settings__row-hint">
              Files larger than this are skipped during scanning.
            </div>
          </div>
          <input
            className="settings__input"
            type="number"
            min={1}
            max={100}
            value={settings.maxFileSize}
            onChange={(e) => update('maxFileSize', Number(e.target.value))}
          />
        </div>
      </section>

      {/* ---- Scan Defaults ---- */}
      <section className="settings__section glassmorphism">
        <div className="settings__section-header">
          <span className="settings__section-icon">🚀</span>
          <h2 className="settings__section-title">Scan Defaults</h2>
        </div>
        <p className="settings__section-desc">
          Default values used when starting a new scan.
        </p>

        <div className="settings__row">
          <div className="settings__row-info">
            <div className="settings__row-label">Default Scan Type</div>
            <div className="settings__row-hint">
              The scan type pre-selected on the New Scan page.
            </div>
          </div>
          <select
            className="settings__select"
            value={settings.defaultScanType}
            onChange={(e) => update('defaultScanType', e.target.value)}
          >
            <option value="full">Full Scan</option>
            <option value="dependency">Dependency Only</option>
            <option value="secret">Secret Detection</option>
            <option value="config">Configuration Audit</option>
          </select>
        </div>

        <div className="settings__row">
          <div className="settings__row-info">
            <div className="settings__row-label">Default Compliance Framework</div>
            <div className="settings__row-hint">
              The framework pre-selected on the Compliance page.
            </div>
          </div>
          <select
            className="settings__select"
            value={settings.defaultFramework}
            onChange={(e) => update('defaultFramework', e.target.value)}
          >
            <option value="NIST-CSF">NIST Cybersecurity Framework</option>
            <option value="SOC-2">SOC 2 Type II Standard</option>
            <option value="OWASP-10">OWASP Top 10 Security Risks</option>
          </select>
        </div>
      </section>

      {/* ---- Preferences ---- */}
      <section className="settings__section glassmorphism">
        <div className="settings__section-header">
          <span className="settings__section-icon">🎛️</span>
          <h2 className="settings__section-title">Preferences</h2>
        </div>
        <p className="settings__section-desc">
          Toggle application behaviour and appearance settings.
        </p>

        <div className="settings__row">
          <div className="settings__row-info">
            <div className="settings__row-label">Enable Notifications</div>
            <div className="settings__row-hint">
              Show in-app alerts when scans complete or new findings arrive.
            </div>
          </div>
          <label className="settings__toggle">
            <input
              type="checkbox"
              checked={settings.enableNotifications}
              onChange={(e) => update('enableNotifications', e.target.checked)}
            />
            <span className="settings__toggle-slider" />
          </label>
        </div>

        <div className="settings__row">
          <div className="settings__row-info">
            <div className="settings__row-label">Auto-Refresh Dashboard</div>
            <div className="settings__row-hint">
              Automatically reload dashboard data every 60 seconds.
            </div>
          </div>
          <label className="settings__toggle">
            <input
              type="checkbox"
              checked={settings.autoRefreshDashboard}
              onChange={(e) => update('autoRefreshDashboard', e.target.checked)}
            />
            <span className="settings__toggle-slider" />
          </label>
        </div>

        <div className="settings__row">
          <div className="settings__row-info">
            <div className="settings__row-label">Dark Mode</div>
            <div className="settings__row-hint">
              Use the dark colour scheme (recommended).
            </div>
          </div>
          <label className="settings__toggle">
            <input
              type="checkbox"
              checked={settings.darkMode}
              onChange={(e) => update('darkMode', e.target.checked)}
            />
            <span className="settings__toggle-slider" />
          </label>
        </div>
      </section>

      {/* ---- Data Management ---- */}
      <section className="settings__section glassmorphism">
        <div className="settings__section-header">
          <span className="settings__section-icon">🗄️</span>
          <h2 className="settings__section-title">Data Management</h2>
        </div>
        <p className="settings__section-desc">
          Manage locally cached data and reset preferences.
        </p>

        <div className="settings__row">
          <div className="settings__row-info">
            <div className="settings__row-label">Clear Cached Data</div>
            <div className="settings__row-hint">
              Removes all locally stored scan results and preferences.
            </div>
          </div>
          <button className="settings__btn settings__btn--danger" onClick={handleClearData}>
            Clear All Data
          </button>
        </div>
      </section>

      {/* ---- About ---- */}
      <section className="settings__section glassmorphism">
        <div className="settings__section-header">
          <span className="settings__section-icon">🦉</span>
          <h2 className="settings__section-title">About SovaScan</h2>
        </div>
        <div className="settings__about">
          <span className="settings__about-logo animate-radar-pulse">🦉</span>
          <div className="settings__about-info">
            <h3>SovaScan v0.1.0</h3>
            <p>
              Intelligent Dependency, Configuration, and Secrets Security
              Analyzer tailored for Financial & Banking Codebases.
            </p>
          </div>
        </div>
      </section>

      {/* ---- Action Buttons ---- */}
      <div className="settings__actions">
        <button className="settings__btn settings__btn--primary" onClick={handleSave}>
          Save Settings
        </button>
        <button className="settings__btn settings__btn--secondary" onClick={handleReset}>
          Reset to Defaults
        </button>
      </div>

      {/* ---- Toast ---- */}
      {saved && (
        <div className="settings__toast">
          ✅ Settings saved successfully
        </div>
      )}
    </div>
  );
};

export default Settings;
