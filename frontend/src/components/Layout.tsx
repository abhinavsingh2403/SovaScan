import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import { useState, useEffect, useRef } from 'react';
import { useStore } from '../store';
import './Layout.css';

function NetworkBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    const particleCount = 45;
    const particles: Array<{
      x: number;
      y: number;
      vx: number;
      vy: number;
      radius: number;
    }> = [];

    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.35,
        vy: (Math.random() - 0.5) * 0.35,
        radius: Math.random() * 1.5 + 1,
      });
    }

    const mouse = { x: -1000, y: -1000 };

    const handleMouseMove = (e: MouseEvent) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    };

    const handleMouseLeave = () => {
      mouse.x = -1000;
      mouse.y = -1000;
    };

    window.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseleave', handleMouseLeave);

    const draw = () => {
      ctx.clearRect(0, 0, width, height);

      for (let i = 0; i < particleCount; i++) {
        const p1 = particles[i];
        p1.x += p1.vx;
        p1.y += p1.vy;

        if (p1.x < 0 || p1.x > width) p1.vx *= -1;
        if (p1.y < 0 || p1.y > height) p1.vy *= -1;

        ctx.beginPath();
        ctx.arc(p1.x, p1.y, p1.radius, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0, 240, 255, 0.20)';
        ctx.fill();

        const dxMouse = p1.x - mouse.x;
        const dyMouse = p1.y - mouse.y;
        const distMouse = Math.sqrt(dxMouse * dxMouse + dyMouse * dyMouse);
        if (distMouse < 180) {
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.strokeStyle = `rgba(255, 140, 0, ${0.18 * (1 - distMouse / 180)})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }

        for (let j = i + 1; j < particleCount; j++) {
          const p2 = particles[j];
          const dx = p1.x - p2.x;
          const dy = p1.y - p2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 120) {
            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = `rgba(0, 240, 255, ${0.08 * (1 - dist / 120)})`;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      }

      animationFrameId = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseleave', handleMouseLeave);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100vw',
        height: '100vh',
        pointerEvents: 'none',
        zIndex: 0,
        opacity: 0.8,
      }}
    />
  );
}

interface LayoutProps {
  children: React.ReactNode;
}

const SvgRadar = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" opacity="0.3" />
    <circle cx="12" cy="12" r="6" opacity="0.5" />
    <circle cx="12" cy="12" r="2" />
    <line x1="12" y1="2" x2="12" y2="6" />
    <line x1="12" y1="12" x2="18" y2="6" />
  </svg>
);

const SvgBug = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="8" y="6" width="8" height="14" rx="4" />
    <path d="M6 10H4" /><path d="M6 18H2" /><path d="M6 14H3" />
    <path d="M18 10h2" /><path d="M18 18h4" /><path d="M18 14h3" />
    <path d="M9 2l1.5 4" /><path d="M15 2l-1.5 4" />
  </svg>
);

const SvgTerminal = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="4" width="20" height="16" rx="2" />
    <path d="M6 10l4 2-4 2" />
    <line x1="12" y1="16" x2="18" y2="16" />
  </svg>
);

const SvgShield = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 2L3 7v6c0 5.25 3.75 10.08 9 11 5.25-.92 9-5.75 9-11V7l-9-5z" />
    <path d="M9 12l2 2 4-4" />
  </svg>
);

const SvgHexDoc = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <polyline points="14 2 14 8 20 8" />
    <path d="M8 13h2" /><path d="M8 17h2" />
    <path d="M14 13h2" /><path d="M14 17h2" />
  </svg>
);

const SvgWrench = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
  </svg>
);

const navItems = [
  { path: '/', label: 'Dashboard', icon: <SvgRadar /> },
  { path: '/findings', label: 'Findings', icon: <SvgBug /> },
  { path: '/scan', label: 'New Scan', icon: <SvgTerminal /> },
  { path: '/compliance', label: 'Compliance', icon: <SvgShield /> },
  { path: '/report', label: 'Reports', icon: <SvgHexDoc /> },
];

const pageTitles: Record<string, string> = {
  '/': 'Dashboard',
  '/findings': 'Security Findings',
  '/scan': 'New Scan',
  '/compliance': 'Compliance Reports',
  '/settings': 'Settings',
  '/report': 'Security Reports',
};

export default function Layout({ children }: LayoutProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState('');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const notifRef = useRef<HTMLDivElement>(null);
  const [avatarOpen, setAvatarOpen] = useState(false);
  const avatarRef = useRef<HTMLDivElement>(null);

  const handleSearchSubmit = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      if (searchQuery.trim()) {
        navigate(`/findings?search=${encodeURIComponent(searchQuery.trim())}`);
      }
    }
  };

  const {
    notifications,
    markNotificationAsRead,
    markAllNotificationsAsRead,
    clearNotifications,
    theme,
    toggleTheme,
  } = useStore();

  const unreadCount = notifications.filter((n) => !n.read).length;

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(event.target as Node)) {
        setNotifOpen(false);
      }
      if (avatarRef.current && !avatarRef.current.contains(event.target as Node)) {
        setAvatarOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);



  const pageTitle = location.pathname.startsWith('/report') ? 'Security Report' : (pageTitles[location.pathname] || 'SovaScan');

  return (
    <div className={`layout ${sidebarCollapsed ? 'layout--collapsed' : ''}`}>
      <NetworkBackground />
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
          <NavLink
            to="/settings"
            className={({ isActive }) =>
              `sidebar__settings ${isActive ? 'sidebar__link--active' : ''}`
            }
            title="Settings"
          >
            <SvgWrench /> <span className="sidebar__link-label">Settings</span>
          </NavLink>
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
                placeholder="Search rule, path, title... [Enter]"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={handleSearchSubmit}
              />
            </div>
            <button
              className="topbar__icon-btn"
              title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Theme`}
              onClick={toggleTheme}
              style={{ fontSize: '16px' }}
            >
              {theme === 'dark' ? '☀️' : '🌙'}
            </button>

            <div className="topbar__notif-container" ref={notifRef}>
              <button
                className="topbar__icon-btn"
                title="Notifications"
                onClick={() => setNotifOpen(!notifOpen)}
              >
                🔔
                {unreadCount > 0 && <span className="topbar__notif-dot" />}
              </button>

              {notifOpen && (
                <div className="notif-dropdown">
                  <div className="notif-dropdown__header">
                    <h3>Notifications</h3>
                    <div className="notif-dropdown__header-actions">
                      {unreadCount > 0 && (
                        <button onClick={markAllNotificationsAsRead} className="notif-dropdown__btn-link">
                          Mark all read
                        </button>
                      )}
                      {notifications.length > 0 && (
                        <button onClick={clearNotifications} className="notif-dropdown__btn-link text-danger">
                          Clear all
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="notif-dropdown__list">
                    {notifications.length === 0 ? (
                      <div className="notif-dropdown__empty">
                        <span className="notif-dropdown__empty-icon">📭</span>
                        <p>No notifications yet</p>
                      </div>
                    ) : (
                      notifications.map((n) => (
                        <div
                          key={n.id}
                          className={`notif-item notif-item--${n.type} ${!n.read ? 'notif-item--unread' : ''}`}
                          onClick={() => markNotificationAsRead(n.id)}
                        >
                          <div className="notif-item__icon">
                            {n.type === 'success' && '🟢'}
                            {n.type === 'warning' && '🟡'}
                            {n.type === 'error' && '🔴'}
                            {n.type === 'info' && '🔵'}
                          </div>
                          <div className="notif-item__content">
                            <div className="notif-item__title">
                              {n.title}
                              {!n.read && <span className="notif-item__unread-indicator" />}
                            </div>
                            <div className="notif-item__message">{n.message}</div>
                            <div className="notif-item__time">
                              {new Date(n.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>
            <div className="topbar__avatar-container" ref={avatarRef}>
              <button
                className="topbar__avatar-btn"
                onClick={() => setAvatarOpen(!avatarOpen)}
                title="User Profile"
              >
                <div className="topbar__avatar">
                  <span>SA</span>
                </div>
              </button>

              {avatarOpen && (
                <div className="avatar-dropdown">
                  {/* User Profile Summary */}
                  <div className="avatar-dropdown__user-card">
                    <div className="avatar-dropdown__avatar-large">SA</div>
                    <div className="avatar-dropdown__user-info">
                      <div className="avatar-dropdown__name">Sova Admin</div>
                      <div className="avatar-dropdown__email">admin@sovascan.local</div>
                      <span className="avatar-dropdown__role-badge">Security Administrator</span>
                    </div>
                  </div>

                  {/* Quick Stats Grid */}
                  <div className="avatar-dropdown__stats">
                    <div className="avatar-dropdown__stat-item">
                      <span className="avatar-dropdown__stat-value">42</span>
                      <span className="avatar-dropdown__stat-label">Scans Run</span>
                    </div>
                    <div className="avatar-dropdown__stat-item">
                      <span className="avatar-dropdown__stat-value">18</span>
                      <span className="avatar-dropdown__stat-label">Fixes Applied</span>
                    </div>
                  </div>

                  {/* Menu Links */}
                  <div className="avatar-dropdown__menu">
                    <NavLink
                      to="/profile"
                      className="avatar-dropdown__menu-item"
                      onClick={() => setAvatarOpen(false)}
                    >
                      <span className="avatar-dropdown__menu-icon">👤</span>
                      <div className="avatar-dropdown__menu-text">
                        <span className="avatar-dropdown__menu-title">Account Details</span>
                        <span className="avatar-dropdown__menu-desc">Manage profile settings</span>
                      </div>
                    </NavLink>

                    <NavLink
                      to="/profile#api-keys"
                      className="avatar-dropdown__menu-item"
                      onClick={() => setAvatarOpen(false)}
                    >
                      <span className="avatar-dropdown__menu-icon">🔑</span>
                      <div className="avatar-dropdown__menu-text">
                        <span className="avatar-dropdown__menu-title">CLI & API Keys</span>
                        <span className="avatar-dropdown__menu-desc">Manage CI/CD tokens</span>
                      </div>
                    </NavLink>

                    <NavLink
                      to="/profile#activity"
                      className="avatar-dropdown__menu-item"
                      onClick={() => setAvatarOpen(false)}
                    >
                      <span className="avatar-dropdown__menu-icon">🕒</span>
                      <div className="avatar-dropdown__menu-text">
                        <span className="avatar-dropdown__menu-title">User Activity Log</span>
                        <span className="avatar-dropdown__menu-desc">View audit trail logs</span>
                      </div>
                    </NavLink>

                    <NavLink
                      to="/settings"
                      className="avatar-dropdown__menu-item"
                      onClick={() => setAvatarOpen(false)}
                    >
                      <span className="avatar-dropdown__menu-icon">⚙️</span>
                      <div className="avatar-dropdown__menu-text">
                        <span className="avatar-dropdown__menu-title">Global Preferences</span>
                        <span className="avatar-dropdown__menu-desc">Adjust scan defaults</span>
                      </div>
                    </NavLink>
                  </div>
                </div>
              )}
            </div>
          </div>
        </header>

        <main className="content">{children}</main>
      </div>
    </div>
  );
}
