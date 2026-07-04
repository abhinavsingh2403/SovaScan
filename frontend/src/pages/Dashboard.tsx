import React, { useEffect } from 'react';
import { useStore } from '../store';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
  CartesianGrid,
} from 'recharts';
import './Dashboard.css';

const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#eab308',
  low: '#2563eb',
  info: '#64748b',
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

const PieTooltip = ({ active, payload }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0];
    return (
      <div className="custom-chart-tooltip glassmorphism">
        <p className="tooltip-value" style={{ color: data.payload.color }}>
          <span className="tooltip-dot" style={{ backgroundColor: data.payload.color }}></span>
          {data.name}: <strong>{data.value}</strong>
        </p>
      </div>
    );
  }
  return null;
};

const Dashboard: React.FC = () => {
  const { dashboardSummary, loading, fetchDashboard } = useStore();

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

  // Format data for severity pie chart
  const pieData = Object.entries(dashboardSummary.severityDistribution).map(
    ([name, value]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1),
      value,
      color: `url(#grad-${name})`,
      rawColor: SEVERITY_COLORS[name as keyof typeof SEVERITY_COLORS],
    })
  );

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
      <div className="stats-grid animate-fade-in">
        <div className="stat-card glassmorphism risk-card">
          <div className="risk-score-circle">
            <svg viewBox="0 0 36 36" className="circular-chart">
              <path
                className="circle-bg"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
              <path
                className="circle"
                strokeDasharray={`${dashboardSummary.riskScore}, 100`}
                stroke={dashboardSummary.riskScore > 70 ? '#dc2626' : '#ea580c'}
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
              <text x="18" y="20.35" className="percentage">
                {dashboardSummary.riskScore}
              </text>
            </svg>
          </div>
          <div className="risk-info">
            <h3>Overall Security Risk</h3>
            <p className="risk-desc">Calculated based on active findings and severity levels.</p>
          </div>
        </div>

        <div className="stat-card glassmorphism">
          <div className="stat-icon count-icon">🔍</div>
          <div className="stat-details">
            <h3>Total Scans</h3>
            <p className="stat-number">{dashboardSummary.totalScans}</p>
            <span className="stat-sub">Completed codebases & dependencies</span>
          </div>
        </div>

        <div className="stat-card glassmorphism">
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
          <div className="chart-wrapper">
            <div className="donut-chart-container">
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <defs>
                    <linearGradient id="grad-critical" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#dc2626" />
                      <stop offset="100%" stopColor="#ef4444" />
                    </linearGradient>
                    <linearGradient id="grad-high" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#ea580c" />
                      <stop offset="100%" stopColor="#f97316" />
                    </linearGradient>
                    <linearGradient id="grad-medium" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#eab308" />
                      <stop offset="100%" stopColor="#facc15" />
                    </linearGradient>
                    <linearGradient id="grad-low" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#2563eb" />
                      <stop offset="100%" stopColor="#3b82f6" />
                    </linearGradient>
                    <linearGradient id="grad-info" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#64748b" />
                      <stop offset="100%" stopColor="#94a3b8" />
                    </linearGradient>
                  </defs>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={65}
                    outerRadius={85}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<PieTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="donut-center-text">
                <span className="donut-center-num">{dashboardSummary.totalFindings}</span>
                <span className="donut-center-label">Findings</span>
              </div>
            </div>
            
            {/* Custom Symmetrical and Interactive Legend */}
            <div className="custom-pie-legend">
              {Object.entries(SEVERITY_COLORS).map(([severity, color]) => {
                const count = dashboardSummary.severityDistribution[severity as keyof typeof SEVERITY_COLORS] || 0;
                return (
                  <div key={severity} className={`legend-item ${count === 0 ? 'inactive' : ''}`}>
                    <span className="legend-dot" style={{ backgroundColor: color }}></span>
                    <span className="legend-name">{severity.charAt(0).toUpperCase() + severity.slice(1)}</span>
                    {count > 0 && <span className="legend-count">({count})</span>}
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
      <div className="bottom-grid animate-slide-up">
        {/* Recent Scans Table */}
        <div className="list-card glassmorphism table-section">
          <h2>Recent Scans</h2>
          <div className="table-responsive">
            <table className="recent-scans-table">
              <thead>
                <tr>
                  <th>Target Directory</th>
                  <th>Type</th>
                  <th>Findings</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {dashboardSummary.recentScans.map((scan) => (
                  <tr key={scan.id}>
                    <td className="monospace-td">{scan.target}</td>
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
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top Vulnerability Classes */}
        <div className="list-card glassmorphism top-vulns-section">
          <h2>Top Security Findings</h2>
          <div className="vulns-list">
            {dashboardSummary.topVulnerabilities.map((vuln) => (
              <div key={vuln.id} className="vuln-item">
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
