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
  PieChart,
  Pie,
} from 'recharts';
import './Dashboard.css';

import { useNavigate, Link } from 'react-router-dom';

const SEVERITY_COLORS = {
  critical: '#f43f5e',
  high: '#fb923c',
  medium: '#60a5fa',
  low: '#c084fc',
  info: '#64748b',
};

const SEVERITY_RGBS = {
  critical: '220, 38, 38',
  high: '234, 88, 12',
  medium: '37, 99, 235',
  low: '139, 92, 246',
  info: '100, 116, 139',
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

const Dashboard: React.FC = () => {
  const { dashboardSummary, loading, fetchDashboard } = useStore();
  const [activeIndex, setActiveIndex] = useState<number | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  if (loading || !dashboardSummary) {
    return (
      <div className="dashboard-loading">
        <div className="spinner"></div>
        <p>Loading security posture summary...</p>
      </div>
    );
  }

  // Format data for vertical threat columns chart
  const barData = ['critical', 'high', 'medium', 'low', 'info'].map((name) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value: dashboardSummary.severityDistribution[name as keyof typeof SEVERITY_COLORS] || 0,
    color: `url(#grad-${name})`,
    rawColor: SEVERITY_COLORS[name as keyof typeof SEVERITY_COLORS],
    sevKey: name,
  }));

  // Preprocess trend data to display slope/area line properly even with a single point
  let trendData = [...dashboardSummary.trendData];
  if (trendData.length === 1) {
    const singlePoint = trendData[0];
    let prevHourStr = 'Start';
    try {
      const dateParts = singlePoint.date.split(' ');
      if (dateParts.length === 2) {
        const timeParts = dateParts[1].split(':');
        const hour = parseInt(timeParts[0]);
        const prevHour = (hour - 1 + 24) % 24;
        prevHourStr = `${dateParts[0]} ${String(prevHour).padStart(2, '0')}:00`;
      }
    } catch (e) {
      // fallback
    }
    trendData = [
      {
        date: prevHourStr,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      },
      singlePoint,
    ];
  }

  return (
    <div className="dashboard-container">
      {/* Top Stats Cards */}
      <div className="stats-grid animate-fade-in stagger-children">
        <div className="stat-card glassmorphism risk-card animate-scan-glow">
          <div className="risk-score-circle">
            <svg viewBox="0 0 36 36" className="circular-chart hud-dial">
              <defs>
                <linearGradient id="risk-grad" x1="0" y1="1" x2="1" y2="0">
                  <stop offset="0%" stopColor="#8b5cf6" />
                  <stop offset="50%" stopColor="#ea580c" />
                  <stop offset="100%" stopColor="#dc2626" />
                </linearGradient>
                <filter id="glow-filter">
                  <feGaussianBlur stdDeviation="1" result="coloredBlur"/>
                  <feMerge>
                    <feMergeNode in="coloredBlur"/>
                    <feMergeNode in="SourceGraphic"/>
                  </feMerge>
                </filter>
              </defs>
              <circle
                className="hud-outer-ring animate-radar-spin"
                cx="18"
                cy="18"
                r="17"
                stroke="rgba(99, 102, 241, 0.25)"
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
                strokeDasharray={`${dashboardSummary.riskScore}, 100`}
                stroke="url(#risk-grad)"
                strokeWidth="2.5"
                strokeLinecap="round"
                filter="url(#glow-filter)"
                d="M18 4 a 14 14 0 1 1 0 28 a 14 14 0 1 1 0 -28"
                fill="none"
              />
              <text x="18" y="18.5" className="percentage">
                {dashboardSummary.riskScore}
              </text>
              <text x="18" y="25" className="hud-label">
                {dashboardSummary.riskScore > 75 ? 'CRITICAL' : dashboardSummary.riskScore > 40 ? 'WARNING' : 'SECURE'}
              </text>
            </svg>
          </div>
          <div className="risk-info">
            <h3>Overall Security Risk</h3>
            <p className="risk-desc">Calculated based on active findings and severity levels.</p>
          </div>
        </div>

        <div className="stat-card glassmorphism scans-card">
          <div className="stat-icon count-icon">🔍</div>
          <div className="stat-details">
            <h3>Total Scans</h3>
            <p className="stat-number">{dashboardSummary.totalScans}</p>
            <span className="stat-sub">Completed codebases & dependencies</span>
          </div>
        </div>

        <div className="stat-card glassmorphism findings-card">
          <div className="stat-icon finding-icon">🦉</div>
          <div className="stat-details">
            <h3>Active Findings</h3>
            <p className="stat-number">{dashboardSummary.totalFindings}</p>
            <span className="stat-sub font-orange">Requires review</span>
          </div>
        </div>

        <div className="stat-card glassmorphism critical-card">
          <div className="stat-icon critical-icon">🔥</div>
          <div className="stat-details">
            <h3>Critical & High</h3>
            <p className="stat-number">
              {dashboardSummary.severityDistribution.critical +
                dashboardSummary.severityDistribution.high}
            </p>
            <span className="stat-sub font-red">Immediate fixing required</span>
          </div>
        </div>
      </div>

      {/* Middle Visualizations */}
      <div className="charts-grid animate-slide-up">
        {/* Severity Distribution */}
        <div className="chart-card glassmorphism">
          <h2>Findings by Severity</h2>
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
                      <stop offset="0%" stopColor="#ff453a" />
                      <stop offset="100%" stopColor="#ff2d55" />
                    </linearGradient>
                    <linearGradient id="grad-high" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#ff9f0a" />
                      <stop offset="100%" stopColor="#ff7b00" />
                    </linearGradient>
                    <linearGradient id="grad-medium" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#6366f1" />
                      <stop offset="100%" stopColor="#3b82f6" />
                    </linearGradient>
                    <linearGradient id="grad-low" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#af52de" />
                      <stop offset="100%" stopColor="#8b5cf6" />
                    </linearGradient>
                    <linearGradient id="grad-info" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#94a3b8" />
                      <stop offset="100%" stopColor="#64748b" />
                    </linearGradient>
                    
                    {/* Glow filter for hovered bar */}
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
                          style={{ transition: 'all 0.25s cubic-bezier(0.25, 0.8, 0.25, 1)', cursor: 'pointer' }}
                          onMouseEnter={() => setActiveIndex(index)}
                          onMouseLeave={() => setActiveIndex(null)}
                        />
                      );
                    })}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Premium Vertical Progress List */}
            <div className="severity-progress-list">
              {['critical', 'high', 'medium', 'low', 'info'].map((sevKey, index) => {
                const count = dashboardSummary.severityDistribution[sevKey as keyof typeof SEVERITY_COLORS] || 0;
                const total = dashboardSummary.totalFindings || 1;
                const percentage = Math.round((count / total) * 100);
                const color = SEVERITY_COLORS[sevKey as keyof typeof SEVERITY_COLORS];
                const label = sevKey.charAt(0).toUpperCase() + sevKey.slice(1);

                // Define icon based on severity (crisp 16x16 pixel-aligned SVGs)
                let icon = null;
                if (sevKey === 'critical') {
                  icon = (
                    <svg className="sev-icon red-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M8 2l6 10H2L8 2z" />
                      <line x1="8" y1="6" x2="8" y2="9" />
                      <line x1="8" y1="12" x2="8.01" y2="12" />
                    </svg>
                  );
                } else if (sevKey === 'high') {
                  icon = (
                    <svg className="sev-icon orange-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="8" cy="8" r="6" />
                      <line x1="8" y1="5" x2="8" y2="8" />
                      <line x1="8" y1="11" x2="8.01" y2="11" />
                    </svg>
                  );
                } else if (sevKey === 'medium') {
                  icon = (
                    <svg className="sev-icon blue-icon" viewBox="0 0 16 16" fill="none">
                      <circle cx="8" cy="8" r="3" fill="#2563eb" />
                    </svg>
                  );
                } else if (sevKey === 'low') {
                  icon = (
                    <svg className="sev-icon purple-icon" viewBox="0 0 16 16" fill="none">
                      <circle cx="8" cy="8" r="3" fill="#8b5cf6" />
                    </svg>
                  );
                } else {
                  icon = (
                    <svg className="sev-icon grey-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
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
                    className={`sev-progress-row ${count === 0 ? 'muted' : ''} ${isRowActive ? 'hovered' : ''}`}
                    onMouseEnter={() => count > 0 && setActiveIndex(index)}
                    onMouseLeave={() => setActiveIndex(null)}
                  >
                    <div className="sev-info-section">
                      <div className="sev-label-row">
                        <span className="sev-icon-wrap">{icon}</span>
                        <span className="sev-label-name">{label}</span>
                      </div>
                      <div className="sev-bar-track">
                        <div className="sev-bar-fill" style={{ width: `${count > 0 ? percentage : 0}%`, backgroundColor: color }}></div>
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
          <h2>Security Trend Over Time</h2>
          <div className="chart-wrapper">
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#dc2626" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#dc2626" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ea580c" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ea580c" stopOpacity={0} />
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
                  tickFormatter={(value) => (typeof value === 'string' && value.includes(' ') ? value.split(' ')[1] : value)}
                />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} dx={-10} />
                <Tooltip content={<CustomTooltip />} />
                <Area
                  type="monotone"
                  dataKey="critical"
                  stroke="#dc2626"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorCritical)"
                  name="Critical"
                  dot={{ r: 3, strokeWidth: 1.5, fill: '#1e293b' }}
                  activeDot={{ r: 5, strokeWidth: 1.5, fill: '#dc2626' }}
                />
                <Area
                  type="monotone"
                  dataKey="high"
                  stroke="#ea580c"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorHigh)"
                  name="High"
                  dot={{ r: 3, strokeWidth: 1.5, fill: '#1e293b' }}
                  activeDot={{ r: 5, strokeWidth: 1.5, fill: '#ea580c' }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Bottom Grid: Recent Scans & Top Vulnerabilities */}
      <div className="bottom-grid animate-slide-up stagger-children">
        {/* Recent Scans Table */}
        <div className="list-card glassmorphism table-section console-window">
          <div className="terminal-header">
            <span className="dot dot-red"></span>
            <span className="dot dot-yellow"></span>
            <span className="dot dot-green"></span>
            <span className="terminal-title">sovascan@history:~</span>
          </div>
          <div className="console-body">
            <h2>Recent Scans</h2>
            <div className="table-responsive">
              <table className="recent-scans-table">
                <thead>
                  <tr>
                    <th>Target Directory</th>
                    <th>Type</th>
                    <th>Findings</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {dashboardSummary.recentScans.map((scan) => (
                    <tr key={scan.id}>
                      <td className="monospace-td" title={scan.target}>{scan.target}</td>
                      <td><span className="badge-type">{scan.scanType}</span></td>
                      <td>
                        <span className="scan-count-tag red-tag">{scan.criticalCount}</span>
                        <span className="scan-count-tag orange-tag">{scan.highCount}</span>
                        <span className="scan-count-tag yellow-tag">{scan.mediumCount}</span>
                      </td>
                      <td>
                        <span className={`status-badge ${scan.status}`}>
                          {scan.status}
                        </span>
                      </td>
                      <td>
                        <Link
                          to={`/report/${scan.id}`}
                          className="settings__btn settings__btn--primary"
                          style={{
                            textDecoration: 'none',
                            display: 'inline-block',
                            fontSize: '11px',
                            padding: '4px 8px',
                          }}
                        >
                          Report
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Top Vulnerability Classes */}
        <div className="list-card glassmorphism top-vulns-section">
          <h2>Top Security Findings</h2>
          <div className="vulns-list">
            {dashboardSummary.topVulnerabilities.map((vuln) => (
              <div
                key={vuln.id}
                className="vuln-item interactive-vuln-card"
                onClick={() => navigate(`/findings?search=${encodeURIComponent(vuln.title)}`)}
              >
                <div className="vuln-details">
                  <span className={`severity-indicator ${vuln.severity}`}></span>
                  <div className="vuln-title-wrap">
                    <p className="vuln-name">{vuln.title}</p>
                    <span className="vuln-cat">{vuln.category}</span>
                  </div>
                </div>
                <div className="vuln-count font-red">{vuln.count} occurrences</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
