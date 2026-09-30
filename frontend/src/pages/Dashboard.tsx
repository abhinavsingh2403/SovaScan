import React, { useEffect, useState } from 'react';
import { useStore } from '../store';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
  CartesianGrid,
} from 'recharts';
import './Dashboard.css';

import { useNavigate, Link } from 'react-router-dom';
import {
  Activity,
  ShieldAlert,
  Flame,
  ShieldCheck,
  RefreshCw,
  Globe,
  HardDrive,
  FileArchive,
  ArrowRight,
  Sparkles,
  ExternalLink,
  Lock,
  Landmark,
  FileCode2,
} from 'lucide-react';
import { TiltCard } from '../components/TiltCard';

const SEVERITY_COLORS = {
  critical: '#F43F5E',
  high: '#FB923C',
  medium: '#FACC15',
  low: '#38BDF8',
  info: '#94A3B8',
};

// Custom Chart Tooltips for premium aesthetic
const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="custom-chart-tooltip glassmorphism">
        <p className="tooltip-date">{label}</p>
        {payload.map((p: any) => (
          <p key={p.name} className="tooltip-value" style={{ color: p.color || p.payload?.color }}>
            <span className="tooltip-dot" style={{ backgroundColor: p.color || p.payload?.color }}></span>
            {p.name}: <strong>{p.value}</strong>
          </p>
        ))}
      </div>
    );
  }
  return null;
};

/**
 * Smooth Numeric Roll Counter Hook (0 → target)
 * Soft ease-out cubic animation over duration ms on mount/update.
 */
function useCountUp(value: number, duration: number = 650): number {
  const [displayValue, setDisplayValue] = useState(0);

  useEffect(() => {
    let start: number | null = null;
    let frameId: number;

    const step = (ts: number) => {
      if (!start) start = ts;
      const progress = Math.min((ts - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplayValue(Math.round(value * eased));

      if (progress < 1) {
        frameId = requestAnimationFrame(step);
      } else {
        setDisplayValue(value);
      }
    };

    frameId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frameId);
  }, [value, duration]);

  return displayValue;
}

const Dashboard: React.FC = () => {
  const { dashboardSummary, loading, fetchDashboard } = useStore();
  const [activeIndex, setActiveIndex] = useState<number | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await fetchDashboard();
    setTimeout(() => setIsRefreshing(false), 600);
  };

  const animatedRiskScore = useCountUp(dashboardSummary?.riskScore ?? 0);
  const animatedTotalScans = useCountUp(dashboardSummary?.totalScans ?? 0);
  const animatedTotalFindings = useCountUp(dashboardSummary?.totalFindings ?? 0);
  const animatedCriticalHigh = useCountUp(
    (dashboardSummary?.severityDistribution?.critical ?? 0) +
      (dashboardSummary?.severityDistribution?.high ?? 0)
  );

  if (loading && !dashboardSummary) {
    return (
      <div className="dashboard-loading">
        <div className="spinner"></div>
        <p>Loading security posture summary...</p>
      </div>
    );
  }

  const summary = dashboardSummary || {
    totalScans: 0,
    totalFindings: 0,
    riskScore: 0,
    severityDistribution: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    recentScans: [],
    topVulnerabilities: [],
    trendData: [],
  };

  // Format data for vertical threat columns chart
  const barData = ['critical', 'high', 'medium', 'low', 'info'].map((name) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value: summary.severityDistribution[name as keyof typeof SEVERITY_COLORS] || 0,
    color: `url(#grad-${name})`,
    rawColor: SEVERITY_COLORS[name as keyof typeof SEVERITY_COLORS],
    sevKey: name,
  }));

  // Clean helper for scan target display
  const getTargetMeta = (targetStr: string) => {
    const raw = (targetStr || '').trim();
    if (raw.startsWith('http://') || raw.startsWith('https://')) {
      const parts = raw.replace(/\.git$/, '').split('/');
      const repo = parts.slice(-2).join('/');
      return {
        icon: <Globe size={14} className="target-type-icon text-cyan" />,
        label: repo || raw,
        badge: 'GitHub',
        full: raw,
      };
    }
    if (raw.startsWith('upload:')) {
      const name = raw.replace(/^upload:/, '');
      return {
        icon: <FileArchive size={14} className="target-type-icon text-purple" />,
        label: name,
        badge: 'Archive',
        full: raw,
      };
    }
    const folder = raw.split(/[\\/]/).pop() || raw;
    return {
      icon: <HardDrive size={14} className="target-type-icon text-amber" />,
      label: folder,
      badge: 'Local',
      full: raw,
    };
  };

  // Preprocess trend data
  let trendData = [...summary.trendData];
  if (trendData.length === 1) {
    const singlePoint = trendData[0];
    trendData = [
      {
        date: 'Start',
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      },
      singlePoint,
    ];
  }

  // Calculate live compliance health estimations
  const crit = summary.severityDistribution.critical || 0;
  const high = summary.severityDistribution.high || 0;
  const med = summary.severityDistribution.medium || 0;
  const penalty = crit * 15 + high * 8 + med * 2;

  const frameworksHealth = [
    {
      name: 'RBI-CSF',
      fullName: 'Reserve Bank Cyber Security Framework',
      score: Math.max(15, Math.min(100, Math.round(100 - penalty * 1.1))),
      icon: <Landmark size={14} strokeWidth={2} />,
    },
    {
      name: 'NIST-CSF',
      fullName: 'National Institute Standards Framework',
      score: Math.max(20, Math.min(100, Math.round(100 - penalty * 0.9))),
      icon: <ShieldCheck size={14} strokeWidth={2} />,
    },
    {
      name: 'SOC-2',
      fullName: 'Service Organization Control Trust Criteria',
      score: Math.max(18, Math.min(100, Math.round(100 - penalty * 1.05))),
      icon: <Lock size={14} strokeWidth={2} />,
    },
    {
      name: 'OWASP-10',
      fullName: 'Top 10 Web Application Vulnerabilities',
      score: Math.max(10, Math.min(100, Math.round(100 - penalty * 1.25))),
      icon: <ShieldAlert size={14} strokeWidth={2} />,
    },
  ];

  return (
    <div className="dashboard-container">
      {/* Sticky Glassmorphic Telemetry Header Bar */}
      <div className="dashboard-sticky-bar glassmorphism">
        <div className="sticky-bar-left">
          <span className="live-status-pill">
            <span className="live-pulse-dot" />
            <Activity size={14} className="text-accent" />
            <strong className="status-title">Live Posture Telemetry</strong>
          </span>
          <div className="quick-metrics-separator" />
          <span className="quick-metric-item">
            Risk Index:{' '}
            <strong
              style={{
                color:
                  summary.riskScore > 75
                    ? '#f43f5e'
                    : summary.riskScore > 40
                    ? '#f59e0b'
                    : '#10b981',
              }}
            >
              {animatedRiskScore}/100
            </strong>
          </span>
          <span className="quick-metric-item">
            Active Findings:{' '}
            <strong style={{ color: summary.totalFindings > 0 ? '#f43f5e' : '#10b981' }}>
              {animatedTotalFindings}
            </strong>
          </span>
        </div>

        <div className="sticky-bar-actions">
          <button
            type="button"
            className={`dashboard-refresh-btn ${isRefreshing ? 'is-spinning' : ''}`}
            onClick={handleRefresh}
            title="Refresh Security Metrics"
          >
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
          <Link
            to="/findings"
            className="settings__btn settings__btn--secondary"
            style={{
              textDecoration: 'none',
              padding: '6px 12px',
              fontSize: '12px',
              borderRadius: '6px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span>View Findings</span>
            <ArrowRight size={13} />
          </Link>
          <Link
            to="/scan"
            className="settings__btn settings__btn--primary glow-cta"
            style={{
              textDecoration: 'none',
              padding: '6px 14px',
              fontSize: '12px',
              borderRadius: '6px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              fontWeight: 600,
            }}
          >
            <span>+ New Scan</span>
          </Link>
        </div>
      </div>

      {/* Top 4 Stat Cards with TiltCard Micro-Physics */}
      <div className="stats-grid staggerContainer">
        <TiltCard maxTilt={8} elevation={10} className="stat-card glassmorphism risk-card animate-scan-glow hover-lift">
          <div className="risk-score-circle">
            <svg viewBox="0 0 36 36" className="circular-chart hud-dial">
              <defs>
                <linearGradient id="risk-grad" x1="0" y1="1" x2="1" y2="0">
                  <stop offset="0%" stopColor="#10B981" />
                  <stop offset="50%" stopColor="#F59E0B" />
                  <stop offset="100%" stopColor="#F43F5E" />
                </linearGradient>
                <filter id="glow-filter">
                  <feGaussianBlur stdDeviation="1" result="coloredBlur" />
                  <feMerge>
                    <feMergeNode in="coloredBlur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>
              <circle
                className="hud-outer-ring animate-radar-spin"
                cx="18"
                cy="18"
                r="17"
                stroke="currentColor"
                strokeWidth="0.5"
                strokeDasharray="4, 2"
                fill="none"
              />
              <circle
                className="circle-bg"
                cx="18"
                cy="18"
                r="14"
                stroke="rgba(255, 255, 255, 0.03)"
                strokeWidth="2.5"
                fill="none"
              />
              <path
                className="circle progress-path"
                strokeDasharray={`${summary.riskScore}, 100`}
                stroke="url(#risk-grad)"
                strokeWidth="2.5"
                strokeLinecap="round"
                filter="url(#glow-filter)"
                d="M18 4 a 14 14 0 1 1 0 28 a 14 14 0 1 1 0 -28"
                fill="none"
              />
              <text x="18" y="18.5" className="percentage">
                {animatedRiskScore}
              </text>
              <text x="18" y="25" className="hud-label">
                {summary.riskScore > 75
                  ? 'CRITICAL'
                  : summary.riskScore > 40
                  ? 'WARNING'
                  : 'SECURE'}
              </text>
            </svg>
          </div>
          <div className="risk-info">
            <div className="stat-heading-row">
              <h3>Overall Security Risk</h3>
              <span
                className={`posture-badge ${
                  summary.riskScore > 75
                    ? 'badge-crit'
                    : summary.riskScore > 40
                    ? 'badge-warn'
                    : 'badge-sec'
                }`}
              >
                {summary.riskScore > 75
                  ? 'High Exposure'
                  : summary.riskScore > 40
                  ? 'Elevated Risk'
                  : 'Hardened (A+)'}
              </span>
            </div>
            <p className="risk-desc">
              Weighted index calculated from CVEs, SAST rules, and secrets exposure.
            </p>
          </div>
        </TiltCard>

        <TiltCard maxTilt={8} elevation={10} className="stat-card glassmorphism scans-card hover-lift">
          <div className="stat-icon count-icon">
            <Activity size={22} strokeWidth={2} />
          </div>
          <div className="stat-details">
            <h3>Total Codebase Scans</h3>
            <p className="stat-number">{animatedTotalScans}</p>
            <div className="stat-sub-row">
              <span className="stat-sub-highlight">
                {summary.recentScans.length > 0
                  ? `Latest: ${new Date(summary.recentScans[0].createdAt).toLocaleDateString()}`
                  : 'Ready for initial run'}
              </span>
            </div>
          </div>
        </TiltCard>

        <TiltCard
          maxTilt={8}
          elevation={10}
          className="stat-card glassmorphism findings-card hover-lift"
          onClick={() => navigate('/findings')}
          style={{ cursor: 'pointer' }}
          title="Click to view all findings"
        >
          <div className="stat-icon finding-icon">
            <ShieldAlert size={22} strokeWidth={2} />
          </div>
          <div className="stat-details">
            <div className="stat-heading-row">
              <h3>Active Findings</h3>
              <span className="interactive-arrow-hint">View →</span>
            </div>
            <p className="stat-number">{animatedTotalFindings}</p>
            <div className="mini-sev-counters">
              <span className="mini-pill pill-crit">C: {summary.severityDistribution.critical}</span>
              <span className="mini-pill pill-high">H: {summary.severityDistribution.high}</span>
              <span className="mini-pill pill-med">M: {summary.severityDistribution.medium}</span>
              <span className="mini-pill pill-low">L: {summary.severityDistribution.low}</span>
            </div>
          </div>
        </TiltCard>

        <TiltCard
          maxTilt={8}
          elevation={10}
          className="stat-card glassmorphism critical-card hover-lift"
          onClick={() => navigate('/findings?severity=critical')}
          style={{ cursor: 'pointer' }}
          title="Click to review critical findings"
        >
          <div className="stat-icon critical-icon">
            <Flame size={22} strokeWidth={2} />
          </div>
          <div className="stat-details">
            <div className="stat-heading-row">
              <h3>Critical & High</h3>
              <span className="interactive-arrow-hint">Triage →</span>
            </div>
            <p className="stat-number">{animatedCriticalHigh}</p>
            <span className="stat-sub font-red">
              {animatedCriticalHigh > 0
                ? 'Immediate remediation priority'
                : 'Zero critical exposure detected'}
            </span>
          </div>
        </TiltCard>
      </div>

      {/* Middle Visualizations */}
      <div className="charts-grid animate-slide-up">
        {/* Severity Distribution */}
        <div className="chart-card glassmorphism">
          <div className="chart-header-row">
            <h2>Findings by Severity</h2>
            <span className="chart-header-sub">Click a severity bar to filter</span>
          </div>

          <div className="chart-wrapper side-by-side-chart">
            <div className="bar-chart-container-left">
              <ResponsiveContainer width="100%" height={220}>
                <BarChart
                  data={barData}
                  margin={{ top: 15, right: 10, left: 15, bottom: 5 }}
                  onMouseLeave={() => setActiveIndex(null)}
                >
                  <defs>
                    <linearGradient id="grad-critical" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#F43F5E" />
                      <stop offset="100%" stopColor="#9F1239" />
                    </linearGradient>
                    <linearGradient id="grad-high" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#FB923C" />
                      <stop offset="100%" stopColor="#C2410C" />
                    </linearGradient>
                    <linearGradient id="grad-medium" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#FACC15" />
                      <stop offset="100%" stopColor="#A16207" />
                    </linearGradient>
                    <linearGradient id="grad-low" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#38BDF8" />
                      <stop offset="100%" stopColor="#0369A1" />
                    </linearGradient>
                    <linearGradient id="grad-info" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#94A3B8" />
                      <stop offset="100%" stopColor="#475569" />
                    </linearGradient>

                    <filter id="glow-effect" x="-20%" y="-20%" width="140%" height="140%">
                      <feGaussianBlur stdDeviation="3" result="blur" />
                      <feComposite in="SourceGraphic" in2="blur" operator="over" />
                    </filter>
                  </defs>
                  <XAxis
                    dataKey="name"
                    axisLine={false}
                    tickLine={false}
                    tick={{ fill: '#94a3b8', fontSize: 10, fontWeight: 600, fontFamily: 'Outfit' }}
                  />
                  <YAxis axisLine={false} tickLine={false} hide />
                  <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.015)' }} />
                  <Bar
                    dataKey="value"
                    radius={6}
                    barSize={24}
                    background={{ fill: 'rgba(255, 255, 255, 0.02)', radius: 6 }}
                  >
                    {barData.map((entry, index) => {
                      const isHovered = activeIndex === index;
                      const isDimmed = activeIndex !== null && !isHovered;
                      return (
                        <Cell
                          key={`cell-${index}`}
                          fill={entry.color}
                          opacity={isDimmed ? 0.35 : 1}
                          filter={isHovered ? 'url(#glow-effect)' : 'none'}
                          style={{
                            transition: 'all 0.25s cubic-bezier(0.25, 0.8, 0.25, 1)',
                            cursor: 'pointer',
                          }}
                          onMouseEnter={() => setActiveIndex(index)}
                          onMouseLeave={() => setActiveIndex(null)}
                          onClick={() => navigate(`/findings?severity=${entry.sevKey}`)}
                        />
                      );
                    })}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Vertical Progress List with Click-to-Filter */}
            <div className="severity-progress-list">
              {['critical', 'high', 'medium', 'low', 'info'].map((sevKey, index) => {
                const count =
                  summary.severityDistribution[sevKey as keyof typeof SEVERITY_COLORS] || 0;
                const total = summary.totalFindings || 1;
                const percentage = Math.round((count / total) * 100);
                const color = SEVERITY_COLORS[sevKey as keyof typeof SEVERITY_COLORS];
                const label = sevKey.charAt(0).toUpperCase() + sevKey.slice(1);

                let icon = null;
                if (sevKey === 'critical') {
                  icon = (
                    <svg
                      className="sev-icon red-icon"
                      viewBox="0 0 16 16"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <path d="M8 2l6 10H2L8 2z" />
                      <line x1="8" y1="6" x2="8" y2="9" />
                      <line x1="8" y1="12" x2="8.01" y2="12" />
                    </svg>
                  );
                } else if (sevKey === 'high') {
                  icon = (
                    <svg
                      className="sev-icon orange-icon"
                      viewBox="0 0 16 16"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <circle cx="8" cy="8" r="6" />
                      <line x1="8" y1="5" x2="8" y2="8" />
                      <line x1="8" y1="11" x2="8.01" y2="11" />
                    </svg>
                  );
                } else if (sevKey === 'medium') {
                  icon = (
                    <svg className="sev-icon yellow-icon" viewBox="0 0 16 16" fill="none">
                      <circle cx="8" cy="8" r="3" fill="#FFD600" />
                    </svg>
                  );
                } else if (sevKey === 'low') {
                  icon = (
                    <svg className="sev-icon cyan-icon" viewBox="0 0 16 16" fill="none">
                      <circle cx="8" cy="8" r="3" fill="#00E5FF" />
                    </svg>
                  );
                } else {
                  icon = (
                    <svg
                      className="sev-icon grey-icon"
                      viewBox="0 0 16 16"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <circle cx="8" cy="8" r="6" />
                      <line x1="8" y1="11" x2="8" y2="8" />
                      <line x1="8" y1="5" x2="8.01" y2="5" />
                    </svg>
                  );
                }

                const isRowActive = activeIndex === index;
                return (
                  <div
                    key={sevKey}
                    className={`sev-progress-row ${count === 0 ? 'muted' : ''} ${
                      isRowActive ? 'hovered' : ''
                    }`}
                    onMouseEnter={() => count > 0 && setActiveIndex(index)}
                    onMouseLeave={() => setActiveIndex(null)}
                    onClick={() => count > 0 && navigate(`/findings?severity=${sevKey}`)}
                    style={{ cursor: count > 0 ? 'pointer' : 'default' }}
                    title={count > 0 ? `Filter by ${label}` : undefined}
                  >
                    <div className="sev-info-section">
                      <div className="sev-label-row">
                        <span className="sev-icon-wrap">{icon}</span>
                        <span className="sev-label-name">{label}</span>
                      </div>
                      <div className="sev-bar-track">
                        <div
                          className="sev-bar-fill"
                          style={{
                            width: `${count > 0 ? percentage : 0}%`,
                            backgroundColor: color,
                          }}
                        ></div>
                      </div>
                    </div>
                    <div className="sev-values-section">
                      <span className="sev-count-val">{count}</span>
                      <span className="sev-percent-val">{count > 0 ? `${percentage}%` : '0%'}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Scan History Trend */}
        <div className="chart-card glassmorphism">
          <div className="chart-header-row">
            <h2>Security Trend Over Time</h2>
            <span className="chart-header-sub">Trajectory of vulnerability discoveries</span>
          </div>

          <div className="chart-wrapper">
            {trendData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={trendData}>
                  <defs>
                    <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#FF1E56" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#FF1E56" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#FF9F1C" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#FF9F1C" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgba(255, 255, 255, 0.05)" vertical={false} strokeDasharray="3 3" />
                  <XAxis
                    dataKey="date"
                    stroke="#64748b"
                    fontSize={11}
                    tickLine={false}
                    axisLine={false}
                    dy={10}
                    tickFormatter={(value) =>
                      typeof value === 'string' && value.includes(' ') ? value.split(' ')[1] : value
                    }
                  />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} dx={-10} />
                  <Tooltip content={<CustomTooltip />} />
                  <Area
                    type="monotone"
                    dataKey="critical"
                    stroke="#FF1E56"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorCritical)"
                    name="Critical"
                    dot={{ r: 3, strokeWidth: 1.5, fill: '#050811' }}
                    activeDot={{ r: 5, strokeWidth: 1.5, fill: '#FF1E56' }}
                  />
                  <Area
                    type="monotone"
                    dataKey="high"
                    stroke="#FF9F1C"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorHigh)"
                    name="High"
                    dot={{ r: 3, strokeWidth: 1.5, fill: '#050811' }}
                    activeDot={{ r: 5, strokeWidth: 1.5, fill: '#FF9F1C' }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="chart-empty-state">
                <Activity size={32} className="text-secondary opacity-40" />
                <p>No historical scan records available yet.</p>
                <Link to="/scan" className="settings__btn settings__btn--secondary">
                  Launch First Scan
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Compliance Framework Posture Overview (Executive Widget) */}
      <div className="compliance-posture-card glassmorphism animate-slide-up">
        <div className="compliance-card-header">
          <div className="compliance-card-title-group">
            <ShieldCheck size={18} className="text-accent" />
            <h3>Compliance Readiness Matrix</h3>
          </div>
          <Link to="/compliance" className="compliance-view-all-link">
            <span>Open Detailed Framework Audits</span>
            <ExternalLink size={12} />
          </Link>
        </div>

        <div className="frameworks-readiness-grid">
          {frameworksHealth.map((fw) => (
            <div
              key={fw.name}
              className="framework-readiness-item"
              onClick={() => navigate(`/compliance?framework=${fw.name}`)}
              style={{ cursor: 'pointer' }}
              title={`View ${fw.fullName} controls`}
            >
              <div className="fw-item-top">
                <span className="fw-badge">
                  <span className="fw-icon-wrap">{fw.icon}</span>
                  <span className="fw-code-name">{fw.name}</span>
                </span>
                <span
                  className="fw-score-val"
                  style={{
                    color: fw.score >= 80 ? '#10b981' : fw.score >= 50 ? '#f59e0b' : '#f43f5e',
                  }}
                >
                  {fw.score}%
                </span>
              </div>
              <div className="fw-bar-bg">
                <div
                  className="fw-bar-fill"
                  style={{
                    width: `${fw.score}%`,
                    background:
                      fw.score >= 80
                        ? 'linear-gradient(90deg, #10b981, #34d399)'
                        : fw.score >= 50
                        ? 'linear-gradient(90deg, #f59e0b, #fbbf24)'
                        : 'linear-gradient(90deg, #f43f5e, #fb7185)',
                  }}
                />
              </div>
              <span className="fw-desc-lbl truncate">{fw.fullName}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Bottom Grid: Recent Scans Console & Top Security Findings */}
      <div className="bottom-grid animate-slide-up stagger-children">
        {/* Recent Scans Table Console Window */}
        <div className="list-card glassmorphism table-section console-window">
          <div className="terminal-header">
            <span className="dot dot-red"></span>
            <span className="dot dot-yellow"></span>
            <span className="dot dot-green"></span>
            <span className="terminal-title">sovascan@telemetry:~</span>
          </div>

          <div className="console-body">
            <div className="table-heading-row">
              <h2>Recent Scans</h2>
              <Link to="/scan" className="console-new-scan-link">
                + Launch Scan
              </Link>
            </div>

            {summary.recentScans.length > 0 ? (
              <div className="table-responsive">
                <table className="recent-scans-table">
                  <thead>
                    <tr>
                      <th>Target</th>
                      <th>Type</th>
                      <th>Severity Breakdown</th>
                      <th>Status</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.recentScans.map((scan) => {
                      const meta = getTargetMeta(scan.target);
                      const hasIssues = scan.totalFindings > 0;
                      return (
                        <tr key={scan.id}>
                          <td className="monospace-td" title={meta.full}>
                            <div className="target-cell-content">
                              {meta.icon}
                              <span className="target-name truncate">{meta.label}</span>
                              <span className="target-meta-badge">{meta.badge}</span>
                            </div>
                          </td>
                          <td>
                            <span className="badge-type">{scan.scanType}</span>
                          </td>
                          <td>
                            {hasIssues ? (
                              <div className="findings-tags-row">
                                {scan.criticalCount > 0 && (
                                  <span className="scan-count-tag red-tag" title="Critical">
                                    {scan.criticalCount}C
                                  </span>
                                )}
                                {scan.highCount > 0 && (
                                  <span className="scan-count-tag orange-tag" title="High">
                                    {scan.highCount}H
                                  </span>
                                )}
                                {scan.mediumCount > 0 && (
                                  <span className="scan-count-tag yellow-tag" title="Medium">
                                    {scan.mediumCount}M
                                  </span>
                                )}
                                {scan.lowCount > 0 && (
                                  <span className="scan-count-tag blue-tag" title="Low">
                                    {scan.lowCount}L
                                  </span>
                                )}
                              </div>
                            ) : (
                              <span className="clean-posture-tag">✓ 0 Issues</span>
                            )}
                          </td>
                          <td>
                            <span className={`status-badge ${scan.status}`}>
                              <span className="status-dot-mini" />
                              {scan.status}
                            </span>
                          </td>
                          <td>
                            <div className="row-action-buttons">
                              <Link
                                to={`/report/${scan.id}`}
                                className="settings__btn settings__btn--secondary row-btn"
                                title="View Comprehensive Audit Report"
                              >
                                Report
                              </Link>
                              <Link
                                to={`/findings?scan=${scan.id}`}
                                className="settings__btn settings__btn--primary row-btn"
                                title="Inspect Scanned Vulnerabilities"
                              >
                                Findings
                              </Link>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="console-empty-state">
                <FileCode2 size={36} className="text-secondary opacity-40" />
                <p>No codebase scans recorded in database yet.</p>
                <Link to="/scan" className="settings__btn settings__btn--primary">
                  Start Your First Scan
                </Link>
              </div>
            )}
          </div>
        </div>

        {/* Top Vulnerability Classes */}
        <div className="list-card glassmorphism top-vulns-section">
          <div className="table-heading-row">
            <h2>Top Vulnerabilities</h2>
            <Link to="/findings" className="console-new-scan-link">
              View All ({summary.totalFindings})
            </Link>
          </div>

          <div className="vulns-list">
            {summary.topVulnerabilities && summary.topVulnerabilities.length > 0 ? (
              summary.topVulnerabilities.map((vuln) => (
                <div
                  key={vuln.id}
                  className="vuln-item interactive-vuln-card hover-lift"
                  onClick={() => navigate(`/findings?search=${encodeURIComponent(vuln.title)}`)}
                  title={`Inspect '${vuln.title}' in Findings`}
                >
                  <div className="vuln-details">
                    <span className={`severity-indicator ${vuln.severity}`}></span>
                    <div className="vuln-title-wrap">
                      <p className="vuln-name truncate">{vuln.title}</p>
                      <div className="vuln-meta-pills">
                        <span className="vuln-cat">{vuln.category}</span>
                        <span className={`vuln-sev-pill sev-${vuln.severity}`}>
                          {vuln.severity}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="vuln-count-action">
                    <span className={`vuln-count font-${vuln.severity}`}>
                      {vuln.count} {vuln.count === 1 ? 'case' : 'cases'}
                    </span>
                    <ArrowRight size={14} className="vuln-arrow-icon" />
                  </div>
                </div>
              ))
            ) : (
              <div className="clean-vulns-empty-state">
                <ShieldCheck size={42} style={{ color: '#10b981' }} />
                <h4>Zero Active Vulnerabilities</h4>
                <p>All scanned codebases are currently hardened with no critical alerts.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
