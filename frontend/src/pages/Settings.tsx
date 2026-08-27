import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { useStore } from '../store';
import './Settings.css';

interface SystemSettings {
  slack_webhook_url: string;
  database_url: string;
  api_host: string;
  api_port: number;
  debug: boolean;
}

const Settings: React.FC = () => {
  const { theme, setTheme } = useStore();
  const [slackWebhookUrl, setSlackWebhookUrl] = useState('');
  const [systemInfo, setSystemInfo] = useState<SystemSettings | null>(null);
  const [loading, setLoading] = useState(false);
  const [testingWebhook, setTestingWebhook] = useState(false);
  const [clearingHistory, setClearingHistory] = useState(false);
  const [saved, setSaved] = useState(false);
  const [toastMsg, setToastMsg] = useState('');

  const fetchSettings = async () => {
    setLoading(true);
    try {
      const res = await api.getSystemSettings();
      setSlackWebhookUrl(res.data.slack_webhook_url || '');
      setSystemInfo(res.data);
    } catch (err: any) {
      console.error("Failed to load settings from backend", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleSave = async () => {
    setLoading(true);
    try {
      await api.saveSystemSettings(slackWebhookUrl);
      setToastMsg('✅ Settings saved successfully');
      setSaved(true);
      fetchSettings();
    } catch (err: any) {
      alert(`Failed to save settings: ${err.message || err}`);
    } finally {
      setLoading(false);
    }
  };

  const handleTestWebhook = async () => {
    if (!slackWebhookUrl.trim()) {
      alert("Please enter a Slack Webhook URL first.");
      return;
    }
    setTestingWebhook(true);
    try {
      await api.testWebhook(slackWebhookUrl);
      setToastMsg('⚡ Test Slack alert sent successfully!');
      setSaved(true);
    } catch (err: any) {
      alert(`Slack Notification failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setTestingWebhook(false);
    }
  };

  const handleClearData = () => {
    if (window.confirm('Are you sure you want to clear all locally cached browser states? This will reset active keys.')) {
      localStorage.clear();
      setToastMsg('🧹 Local cache cleared.');
      setSaved(true);
      setTimeout(() => window.location.reload(), 1500);
    }
  };

  const handleClearScanHistory = async () => {
    if (!window.confirm('⚠️ This will permanently delete ALL completed and failed scan records and their findings from the database. Running scans will be preserved.\n\nThis action cannot be undone. Continue?')) {
      return;
    }
    setClearingHistory(true);
    try {
      const res = await api.clearScanHistory();
      const detail = res.data?.detail || 'Scan history cleared.';
      setToastMsg(`🗑️ ${detail}`);
      setSaved(true);
    } catch (err: any) {
      alert(`Failed to clear scan history: ${err.message || err}`);
    } finally {
      setClearingHistory(false);
    }
  };

  useEffect(() => {
    if (!saved) return;
    const timer = setTimeout(() => setSaved(false), 3000);
    return () => clearTimeout(timer);
  }, [saved]);

  return (
    <div className="settings animate-fade-in">
      {/* Visual Theme & Appearance Section */}
      <section className="settings__section glassmorphism animate-slide-up" style={{ animationDelay: '0.02s' }}>
        <div className="settings__section-header">
          <span className="settings__section-icon">🎨</span>
          <h2 className="settings__section-title">Visual Theme & Appearance</h2>
        </div>
        <p className="settings__section-desc">
          Choose your preferred dashboard interface theme. Light Theme provides a clean, high-contrast slate layout, while Dark Theme provides deep obsidian glassmorphism.
        </p>

        <div className="settings__row">
          <div className="settings__row-info">
            <div className="settings__row-label">Active Interface Theme</div>
            <div className="settings__row-hint">
              Theme selection is saved in browser storage and applied automatically across all pages.
            </div>
          </div>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <button
              className={`settings__btn ${theme === 'light' ? 'settings__btn--primary' : 'settings__btn--secondary'}`}
              onClick={() => {
                setTheme('light');
                setToastMsg('☀️ Light Theme applied');
                setSaved(true);
              }}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            >
              ☀️ Light Theme
            </button>
            <button
              className={`settings__btn ${theme === 'dark' ? 'settings__btn--primary' : 'settings__btn--secondary'}`}
              onClick={() => {
                setTheme('dark');
                setToastMsg('🌙 Dark Theme applied');
                setSaved(true);
              }}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            >
              🌙 Dark Theme
            </button>
          </div>
        </div>
      </section>

      {/* Webhook Settings Section */}
      <section className="settings__section glassmorphism animate-slide-up" style={{ animationDelay: '0.05s' }}>
        <div className="settings__section-header">
          <span className="settings__section-icon">🔔</span>
          <h2 className="settings__section-title">Audit Notifications (Slack / Teams)</h2>
        </div>
        <p className="settings__section-desc">
          Configure real-time notifications to alert security teams when scans finish and identify critical vulnerabilities.
        </p>

        <div className="settings__row">
          <div className="settings__row-info">
            <div className="settings__row-label">Slack Webhook URL</div>
            <div className="settings__row-hint">
              Incoming Webhook URL configured in your Slack app integration dashboard.
            </div>
          </div>
          <input
            className="settings__input"
            type="text"
            value={slackWebhookUrl}
            onChange={(e) => setSlackWebhookUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/..."
            style={{ width: '100%', maxWidth: '500px' }}
          />
        </div>

        <div className="settings__row-actions" style={{ marginTop: '16px', display: 'flex', gap: '12px' }}>
          <button 
            className="settings__btn settings__btn--primary" 
            onClick={handleSave}
            disabled={loading}
          >
            {loading ? 'Saving...' : 'Save Configuration'}
          </button>
          <button 
            className="settings__btn settings__btn--secondary" 
            onClick={handleTestWebhook}
            disabled={testingWebhook}
          >
            {testingWebhook ? 'Testing...' : '⚡ Test Webhook Alert'}
          </button>
        </div>
      </section>

      {/* System Information Section */}
      <section className="settings__section glassmorphism animate-slide-up" style={{ animationDelay: '0.12s' }}>
        <div className="settings__section-header">
          <span className="settings__section-icon">🖥️</span>
          <h2 className="settings__section-title">System Environment & Ledger Status</h2>
        </div>
        <p className="settings__section-desc">
          Current connection metadata and system environment parameters.
        </p>

        {systemInfo && (
          <div className="system-info-grid" style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '16px',
            marginTop: '12px',
            fontSize: '13px'
          }}>
            <div className="info-box" style={{ background: 'rgba(0,0,0,0.15)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.03)' }}>
              <div style={{ color: 'var(--text-secondary)', marginBottom: '4px' }}>Database Engine</div>
              <div style={{ fontFamily: 'monospace', color: '#3b82f6' }}>SQLite 3 (Local Audit Ledger)</div>
            </div>
            <div className="info-box" style={{ background: 'rgba(0,0,0,0.15)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.03)' }}>
              <div style={{ color: 'var(--text-secondary)', marginBottom: '4px' }}>Database Path</div>
              <div style={{ fontFamily: 'monospace', fontSize: '11px', wordBreak: 'break-all' }}>{systemInfo.database_url}</div>
            </div>
            <div className="info-box" style={{ background: 'rgba(0,0,0,0.15)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.03)' }}>
              <div style={{ color: 'var(--text-secondary)', marginBottom: '4px' }}>Server Endpoint</div>
              <div style={{ fontFamily: 'monospace' }}>http://{systemInfo.api_host}:{systemInfo.api_port}</div>
            </div>
            <div className="info-box" style={{ background: 'rgba(0,0,0,0.15)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.03)' }}>
              <div style={{ color: 'var(--text-secondary)', marginBottom: '4px' }}>Active API Host Mode</div>
              <div style={{ color: systemInfo.debug ? '#f59e0b' : '#10b981', fontWeight: 600 }}>
                {systemInfo.debug ? 'DEVELOPMENT / DEBUG' : 'PRODUCTION HARDENED'}
              </div>
            </div>
          </div>
        )}
      </section>

      {/* Danger Zone Section */}
      <section className="settings__section settings__section--danger glassmorphism animate-slide-up" style={{ animationDelay: '0.19s' }}>
        <div className="settings__section-header">
          <span className="settings__section-icon">⚠️</span>
          <h2 className="settings__section-title" style={{ color: 'var(--danger)' }}>System Maintenance</h2>
        </div>
        <p className="settings__section-desc">
          Destructive operations for resetting active configurations and purging historical data.
        </p>

        <div className="settings__row" style={{ borderTop: '1px solid rgba(239, 68, 68, 0.08)', paddingTop: '16px' }}>
          <div className="settings__row-info">
            <div className="settings__row-label">Clear Scan History</div>
            <div className="settings__row-hint">
              Permanently deletes all completed and failed scan records and their associated findings from the database. Running or pending scans are preserved.
            </div>
          </div>
          <button
            className="settings__btn settings__btn--danger"
            onClick={handleClearScanHistory}
            disabled={clearingHistory}
          >
            {clearingHistory ? 'Clearing...' : '🗑️ Clear Scan History'}
          </button>
        </div>

        <div className="settings__row">
          <div className="settings__row-info">
            <div className="settings__row-label">Clear Browser Session</div>
            <div className="settings__row-hint">
              Clears the active browser local storage settings, loaded keys, and UI cache states.
            </div>
          </div>
          <button className="settings__btn settings__btn--danger" onClick={handleClearData}>
            Clear Local Cache
          </button>
        </div>
      </section>

      {/* Toast Notification */}
      {saved && (
        <div className="settings__toast">
          {toastMsg}
        </div>
      )}
    </div>
  );
};

export default Settings;
