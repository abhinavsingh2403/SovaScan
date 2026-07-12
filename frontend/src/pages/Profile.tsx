import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useStore } from '../store';
import './Profile.css';

interface ApiKey {
  id: string;
  name: string;
  key: string;
  createdAt: string;
  lastUsed: string;
}

interface ActivityItem {
  id: string;
  action: string;
  target: string;
  timestamp: string;
  status: 'success' | 'warning' | 'error' | 'info';
}

const Profile: React.FC = () => {
  const location = useLocation();
  const [activeTab, setActiveTab] = useState<'profile' | 'api-keys' | 'activity'>('profile');

  // Handle hash route redirection (e.g. /profile#api-keys)
  useEffect(() => {
    const hash = location.hash;
    if (hash === '#api-keys') {
      setActiveTab('api-keys');
    } else if (hash === '#activity') {
      setActiveTab('activity');
    } else {
      setActiveTab('profile');
    }
  }, [location]);

  const KEYS_STORAGE_KEY = 'sovascan-api-keys';
  const DEFAULT_KEYS: ApiKey[] = [
    {
      id: '1',
      name: 'GitHub-CI-Prod',
      key: 'ss_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
      createdAt: '2026-06-15T12:00:00Z',
      lastUsed: '2026-07-11T18:30:00Z',
    },
    {
      id: '2',
      name: 'Local-Developer-Key',
      key: 'ss_live_z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4',
      createdAt: '2026-07-01T09:15:00Z',
      lastUsed: '2026-07-12T01:45:00Z',
    }
  ];

  const [apiKeys, setApiKeys] = useState<ApiKey[]>(() => {
    try {
      const stored = localStorage.getItem(KEYS_STORAGE_KEY);
      return stored ? JSON.parse(stored) : DEFAULT_KEYS;
    } catch {
      return DEFAULT_KEYS;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(KEYS_STORAGE_KEY, JSON.stringify(apiKeys));
    } catch {
      // ignore
    }
  }, [apiKeys]);
  const [newKeyName, setNewKeyName] = useState('');
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);

  const { scans, findings, fetchScans, fetchFindings } = useStore();

  useEffect(() => {
    fetchScans();
    fetchFindings();
  }, [fetchScans, fetchFindings]);

  // Dynamically build user activities from active scans and findings
  const activity: ActivityItem[] = [];

  // Add scan events
  scans.forEach((scan, idx) => {
    activity.push({
      id: `scan-${scan.id}-${idx}`,
      action: `Vulnerability scan completed (${scan.scanType})`,
      target: scan.target,
      timestamp: scan.completedAt || scan.createdAt,
      status: scan.status === 'failed' ? 'error' : 'success',
    });
  });

  // Add auto-fix and discovery events
  findings.forEach((finding, idx) => {
    if (finding.isFixed) {
      activity.push({
        id: `fix-${finding.id}-${idx}`,
        action: `Applied Auto-Fix patch for ${finding.title}`,
        target: `${finding.filePath}:L${finding.lineNumber}`,
        timestamp: finding.createdAt,
        status: 'success',
      });
    } else if (finding.severity === 'critical' || finding.severity === 'high') {
      activity.push({
        id: `vuln-${finding.id}-${idx}`,
        action: `${finding.severity.toUpperCase()} vulnerability detected`,
        target: `${finding.title} in ${finding.filePath}`,
        timestamp: finding.createdAt,
        status: 'warning',
      });
    }
  });

  // Sort by timestamp descending
  activity.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  // Fallback default list if no events are recorded yet
  if (activity.length === 0) {
    activity.push(
      {
        id: 'mock-1',
        action: 'Vulnerability scan initiated',
        target: 'C:/Projects/bank-api',
        timestamp: new Date().toISOString(),
        status: 'info',
      },
      {
        id: 'mock-2',
        action: 'SovaScan Dashboard initialized',
        target: 'SovaScan Client Web App',
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        status: 'success',
      }
    );
  }

  const handleGenerateKey = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyName.trim()) return;

    const randomHex = Array.from({ length: 32 }, () =>
      Math.floor(Math.random() * 16).toString(16)
    ).join('');
    const newKeyString = `ss_live_${randomHex}`;

    const newApiKey: ApiKey = {
      id: Date.now().toString(),
      name: newKeyName,
      key: newKeyString,
      createdAt: new Date().toISOString(),
      lastUsed: 'Never',
    };

    setApiKeys([newApiKey, ...apiKeys]);
    setGeneratedKey(newKeyString);
    setNewKeyName('');
  };

  const handleRevokeKey = (id: string) => {
    if (window.confirm('Are you sure you want to revoke this API key? Systems using this key will immediately lose access.')) {
      setApiKeys(apiKeys.filter((k) => k.id !== id));
      if (generatedKey) setGeneratedKey(null);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    alert('API Key copied to clipboard!');
  };

  return (
    <div className="profile-page">
      {/* Tab Navigation */}
      <div className="profile-page__tabs">
        <button
          className={`profile-page__tab-btn ${activeTab === 'profile' ? 'active' : ''}`}
          onClick={() => setActiveTab('profile')}
        >
          👤 Account Info
        </button>
        <button
          className={`profile-page__tab-btn ${activeTab === 'api-keys' ? 'active' : ''}`}
          onClick={() => setActiveTab('api-keys')}
        >
          🔑 CLI & API Keys
        </button>
        <button
          className={`profile-page__tab-btn ${activeTab === 'activity' ? 'active' : ''}`}
          onClick={() => setActiveTab('activity')}
        >
          🕒 User Activity
        </button>
      </div>

      <div className="profile-page__content">
        {/* TAB 1: Profile Info */}
        {activeTab === 'profile' && (
          <section className="profile-section animate-fade-in glassmorphism">
            <div className="profile-section__header">
              <h2>Account Details</h2>
              <p>Verify and manage your user profile settings and credentials.</p>
            </div>

            <div className="profile-info-grid">
              <div className="profile-info-grid__avatar-section">
                <div className="profile-info-grid__avatar-large">SA</div>
                <h3>Sova Admin</h3>
                <span className="role-tag">Security Administrator</span>
              </div>

              <div className="profile-info-grid__fields">
                <div className="profile-field">
                  <span className="profile-field__label">Full Name</span>
                  <div className="profile-field__value">Sova Admin</div>
                </div>
                <div className="profile-field">
                  <span className="profile-field__label">Email Address</span>
                  <div className="profile-field__value">admin@sovascan.local</div>
                </div>
                <div className="profile-field">
                  <span className="profile-field__label">User Role</span>
                  <div className="profile-field__value">Security Administrator</div>
                </div>
                <div className="profile-field">
                  <span className="profile-field__label">Organization / Department</span>
                  <div className="profile-field__value">InfoSec Compliance Team</div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* TAB 2: API Keys */}
        {activeTab === 'api-keys' && (
          <section className="profile-section animate-fade-in glassmorphism" id="api-keys">
            <div className="profile-section__header">
              <h2>CLI & API Keys</h2>
              <p>Manage API keys for integrating SovaScan CLI scans in your local environments and CI/CD pipelines.</p>
            </div>

            {/* Key generator form */}
            <form onSubmit={handleGenerateKey} className="api-key-form">
              <div className="api-key-form__input-group">
                <input
                  type="text"
                  placeholder="Key Description (e.g. GitLab-Runner-CI)"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  className="api-key-form__input"
                  required
                />
                <button type="submit" className="api-key-form__btn">
                  Generate Key
                </button>
              </div>
            </form>

            {/* Display newly generated key */}
            {generatedKey && (
              <div className="new-key-alert">
                <div className="new-key-alert__warning">
                  ⚠️ Make sure to copy this key now. You won't be able to see it again!
                </div>
                <div className="new-key-alert__display">
                  <code>{generatedKey}</code>
                  <button
                    onClick={() => copyToClipboard(generatedKey)}
                    className="new-key-alert__copy-btn"
                  >
                    📋 Copy Key
                  </button>
                </div>
              </div>
            )}

            {/* Existing Keys Table */}
            <div className="keys-list">
              <h3>Active Credentials</h3>
              {apiKeys.length === 0 ? (
                <div className="keys-list__empty">No active credentials generated yet.</div>
              ) : (
                <div className="keys-table-container">
                  <table className="keys-table">
                    <thead>
                      <tr>
                        <th>Description</th>
                        <th>Prefix</th>
                        <th>Created</th>
                        <th>Last Used</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {apiKeys.map((k) => (
                        <tr key={k.id}>
                          <td className="key-name">{k.name}</td>
                          <td>
                            <code>{k.key.substring(0, 12)}...</code>
                          </td>
                          <td>{new Date(k.createdAt).toLocaleDateString()}</td>
                          <td>
                            {k.lastUsed === 'Never'
                              ? 'Never'
                              : new Date(k.lastUsed).toLocaleString()}
                          </td>
                          <td>
                            <button
                              onClick={() => handleRevokeKey(k.id)}
                              className="btn-revoke"
                              title="Revoke Key"
                            >
                              Revoke
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </section>
        )}

        {/* TAB 3: Activity Log */}
        {activeTab === 'activity' && (
          <section className="profile-section animate-fade-in glassmorphism" id="activity">
            <div className="profile-section__header">
              <h2>User Activity Log</h2>
              <p>Audit trail of operations triggered by your user account.</p>
            </div>

            <div className="activity-timeline">
              {activity.map((item) => (
                <div key={item.id} className="activity-timeline__item">
                  <div className={`activity-timeline__dot status-${item.status}`} />
                  <div className="activity-timeline__content">
                    <div className="activity-timeline__action">{item.action}</div>
                    <div className="activity-timeline__target">Target: <code>{item.target}</code></div>
                    <div className="activity-timeline__time">
                      {new Date(item.timestamp).toLocaleString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}
      </div>
    </div>
  );
};

export default Profile;
