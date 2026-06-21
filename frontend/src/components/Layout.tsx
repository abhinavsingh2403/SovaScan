import { NavLink, useLocation } from 'react-router-dom';
import { useState } from 'react';
import './Layout.css';

interface LayoutProps {
  children: React.ReactNode;
}

const navItems = [
  { path: '/', label: 'Dashboard', icon: '📊' },
  { path: '/findings', label: 'Findings', icon: '🔍' },
  { path: '/scan', label: 'New Scan', icon: '🚀' },
  { path: '/compliance', label: 'Compliance', icon: '📋' },
];

const pageTitles: Record<string, string> = {
  '/': 'Dashboard',
  '/findings': 'Security Findings',
  '/scan': 'New Scan',
  '/compliance': 'Compliance Reports',
};

export default function Layout({ children }: LayoutProps) {
  const location = useLocation();
  const [searchQuery, setSearchQuery] = useState('');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const pageTitle = pageTitles[location.pathname] || 'SovaScan';

  return (
    <div className={`layout ${sidebarCollapsed ? 'layout--collapsed' : ''}`}>
      {/* ---- Sidebar ---- */}
      <aside className="sidebar">
        <div className="sidebar__brand">
          <span className="sidebar__logo">🦉</span>
          <span className="sidebar__title">SovaScan</span>
        </div>

        <nav className="sidebar__nav">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) =>
                `sidebar__link ${isActive ? 'sidebar__link--active' : ''}`
              }
            >
              <span className="sidebar__link-icon">{item.icon}</span>
              <span className="sidebar__link-label">{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar__footer">
          <div className="sidebar__version">v0.1.0</div>
          <button className="sidebar__settings" title="Settings">
            ⚙️ <span className="sidebar__link-label">Settings</span>
          </button>
        </div>
      </aside>

      {/* ---- Main ---- */}
      <div className="main-wrapper">
        <header className="topbar">
          <button
            className="topbar__toggle"
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            aria-label="Toggle sidebar"
          >
            ☰
          </button>
          <h1 className="topbar__title">{pageTitle}</h1>

          <div className="topbar__actions">
            <div className="topbar__search">
              <span className="topbar__search-icon">🔎</span>
              <input
                type="text"
                className="topbar__search-input"
                placeholder="Search scans, findings..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <button className="topbar__icon-btn" title="Notifications">
              🔔
              <span className="topbar__notif-dot" />
            </button>
            <div className="topbar__avatar" title="User">
              <span>SS</span>
            </div>
          </div>
        </header>

        <main className="content">{children}</main>
      </div>
    </div>
  );
}
