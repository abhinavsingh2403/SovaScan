import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import { useState, useEffect, useRef } from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Terminal,
  ShieldCheck,
  FileText,
  Sliders,
  Search,
  Bell,
  Sun,
  Moon,
  Menu,
  Inbox,
  CheckCircle2,
  AlertTriangle,
  AlertOctagon,
  Info,
  User,
  KeyRound,
  Clock,
  Radio,
  ExternalLink,
} from 'lucide-react';
import { useStore } from '../store';
import './Layout.css';

function NetworkBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const { theme } = useStore();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    // 3D Space & Projection Configuration
    const FOCAL_LENGTH = 650;
    const BOUNDS_X = 900;
    const BOUNDS_Y = 600;
    const BOUNDS_Z = 700;
    const PARTICLE_COUNT = 65;

    interface Particle3D {
      x: number;
      y: number;
      z: number;
      vx: number;
      vy: number;
      vz: number;
      radius: number;
      pulsePhase: number;
      colorType: 'amber' | 'cyan' | 'emerald';
    }

    const particles: Particle3D[] = [];
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      particles.push({
        x: (Math.random() - 0.5) * BOUNDS_X * 2,
        y: (Math.random() - 0.5) * BOUNDS_Y * 2,
        z: (Math.random() - 0.5) * BOUNDS_Z * 2,
        vx: (Math.random() - 0.5) * 0.45,
        vy: (Math.random() - 0.5) * 0.45,
        vz: (Math.random() - 0.5) * 0.5,
        radius: Math.random() * 2.2 + 1.2,
        pulsePhase: Math.random() * Math.PI * 2,
        colorType: i % 5 === 0 ? 'cyan' : i % 8 === 0 ? 'emerald' : 'amber',
      });
    }

    // Interactive 3D Camera Controls with Inertia
    let mouseX = 0;
    let mouseY = 0;
    let targetRotY = 0;
    let targetRotX = 0;
    let rotY = 0;
    let rotX = 0;

    const handleMouseMove = (e: MouseEvent) => {
      const normX = (e.clientX / width - 0.5) * 2;
      const normY = (e.clientY / height - 0.5) * 2;
      mouseX = e.clientX;
      mouseY = e.clientY;
      targetRotY = normX * 0.35; // yaw (-0.35 to +0.35 rad)
      targetRotX = -normY * 0.22; // pitch (-0.22 to +0.22 rad)
    };

    const handleMouseLeave = () => {
      targetRotX = 0;
      targetRotY = 0;
    };

    window.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseleave', handleMouseLeave);

    const isLight = theme === 'light';
    let frame = 0;

    const draw = () => {
      frame++;
      // Smooth camera interpolation
      rotY += (targetRotY - rotY) * 0.05;
      rotX += (targetRotX - rotX) * 0.05;

      const cosY = Math.cos(rotY);
      const sinY = Math.sin(rotY);
      const cosX = Math.cos(rotX);
      const sinX = Math.sin(rotX);

      ctx.clearRect(0, 0, width, height);

      const cx = width / 2;
      const cy = height / 2;

      // --- 1. Draw 3D Perspective Ground Grid (Horizon Matrix) ---
      const gridZStart = 100;
      const gridZEnd = 900;
      const gridZStep = 130;
      const gridY = 280; // ground plane below center
      const gridExtent = 900;
      const gridXStep = 180;

      ctx.save();
      const gridAlphaBase = isLight ? 0.04 : 0.07;

      // Longitudinal lines (Z-depth lines)
      for (let gx = -gridExtent; gx <= gridExtent; gx += gridXStep) {
        // Near point
        const nx = gx * cosY - gridZStart * sinY;
        const nz = gx * sinY + gridZStart * cosY;
        const ny = gridY * cosX - nz * sinX;
        const nrz = gridY * sinX + nz * cosX + FOCAL_LENGTH;

        // Far point
        const fx = gx * cosY - gridZEnd * sinY;
        const fz = gx * sinY + gridZEnd * cosY;
        const fy = gridY * cosX - fz * sinX;
        const frz = gridY * sinX + fz * cosX + FOCAL_LENGTH;

        if (nrz > 50 && frz > 50) {
          const ns = FOCAL_LENGTH / nrz;
          const fs = FOCAL_LENGTH / frz;

          ctx.beginPath();
          ctx.moveTo(cx + nx * ns, cy + ny * ns);
          ctx.lineTo(cx + fx * fs, cy + fy * fs);
          ctx.strokeStyle = isLight
            ? `rgba(2, 132, 199, ${gridAlphaBase * 0.8})`
            : `rgba(6, 182, 212, ${gridAlphaBase})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }

      // Latitudinal lines (X-horizontal rings)
      for (let gz = gridZStart; gz <= gridZEnd; gz += gridZStep) {
        const x1 = -gridExtent;
        const x2 = gridExtent;

        const rx1 = x1 * cosY - gz * sinY;
        const rz1 = x1 * sinY + gz * cosY;
        const ry1 = gridY * cosX - rz1 * sinX;
        const fz1 = gridY * sinX + rz1 * cosX + FOCAL_LENGTH;

        const rx2 = x2 * cosY - gz * sinY;
        const rz2 = x2 * sinY + gz * cosY;
        const ry2 = gridY * cosX - rz2 * sinX;
        const fz2 = gridY * sinX + rz2 * cosX + FOCAL_LENGTH;

        if (fz1 > 50 && fz2 > 50) {
          const s1 = FOCAL_LENGTH / fz1;
          const s2 = FOCAL_LENGTH / fz2;
          const depthFade = Math.max(0, 1 - gz / gridZEnd);

          ctx.beginPath();
          ctx.moveTo(cx + rx1 * s1, cy + ry1 * s1);
          ctx.lineTo(cx + rx2 * s2, cy + ry2 * s2);
          ctx.strokeStyle = isLight
            ? `rgba(217, 119, 6, ${gridAlphaBase * depthFade})`
            : `rgba(245, 158, 11, ${gridAlphaBase * 1.2 * depthFade})`;
          ctx.lineWidth = 0.6;
          ctx.stroke();
        }
      }
      ctx.restore();

      // --- 2. Update and Project 3D Particles ---
      interface ProjectedNode {
        sx: number;
        sy: number;
        sz: number;
        scale: number;
        radius: number;
        alpha: number;
        colorType: 'amber' | 'cyan' | 'emerald';
        pRef: Particle3D;
      }

      const projected: ProjectedNode[] = [];

      for (let i = 0; i < PARTICLE_COUNT; i++) {
        const p = particles[i];

        // Motion update
        p.x += p.vx;
        p.y += p.vy;
        p.z += p.vz;
        p.pulsePhase += 0.02;

        // Wrap around bounds
        if (p.x < -BOUNDS_X) p.x = BOUNDS_X;
        if (p.x > BOUNDS_X) p.x = -BOUNDS_X;
        if (p.y < -BOUNDS_Y) p.y = BOUNDS_Y;
        if (p.y > BOUNDS_Y) p.y = -BOUNDS_Y;
        if (p.z < -BOUNDS_Z) p.z = BOUNDS_Z;
        if (p.z > BOUNDS_Z) p.z = -BOUNDS_Z;

        // 3D Rotation Transform (Yaw around Y, then Pitch around X)
        const xRot = p.x * cosY - p.z * sinY;
        const zRot = p.x * sinY + p.z * cosY;
        const yRot = p.y * cosX - zRot * sinX;
        const finalZ = p.y * sinX + zRot * cosX;

        // Perspective Projection
        const distanceZ = finalZ + FOCAL_LENGTH;
        if (distanceZ <= 60) continue; // Behind camera or clipping plane

        const scale = FOCAL_LENGTH / distanceZ;
        const sx = cx + xRot * scale;
        const sy = cy + yRot * scale;

        // Volumetric depth fading & size scaling
        const depthNorm = Math.max(0, Math.min(1, (distanceZ - 100) / (BOUNDS_Z * 2)));
        const depthAlpha = (1 - depthNorm * 0.75) * (0.85 + Math.sin(p.pulsePhase) * 0.15);

        projected.push({
          sx,
          sy,
          sz: distanceZ,
          scale,
          radius: p.radius * scale,
          alpha: Math.max(0.08, depthAlpha),
          colorType: p.colorType,
          pRef: p,
        });
      }

      // Depth sort so distant nodes render first (painter's algorithm)
      projected.sort((a, b) => b.sz - a.sz);

      // --- 3. Render 3D Constellation Laser Struts ---
      const maxConnectDist = 180;
      for (let i = 0; i < projected.length; i++) {
        const n1 = projected[i];
        for (let j = i + 1; j < projected.length; j++) {
          const n2 = projected[j];

          // 3D Euclidean distance in world space
          const dx = n1.pRef.x - n2.pRef.x;
          const dy = n1.pRef.y - n2.pRef.y;
          const dz = n1.pRef.z - n2.pRef.z;
          const dist3D = Math.sqrt(dx * dx + dy * dy + dz * dz);

          if (dist3D < maxConnectDist) {
            const proximityFactor = 1 - dist3D / maxConnectDist;
            const linkAlpha = proximityFactor * Math.min(n1.alpha, n2.alpha) * (isLight ? 0.35 : 0.45);

            ctx.beginPath();
            ctx.moveTo(n1.sx, n1.sy);
            ctx.lineTo(n2.sx, n2.sy);

            if (n1.colorType === 'cyan' || n2.colorType === 'cyan') {
              ctx.strokeStyle = isLight
                ? `rgba(2, 132, 199, ${linkAlpha})`
                : `rgba(6, 182, 212, ${linkAlpha})`;
            } else if (n1.colorType === 'emerald' || n2.colorType === 'emerald') {
              ctx.strokeStyle = isLight
                ? `rgba(16, 185, 129, ${linkAlpha})`
                : `rgba(52, 211, 153, ${linkAlpha})`;
            } else {
              ctx.strokeStyle = isLight
                ? `rgba(217, 119, 6, ${linkAlpha})`
                : `rgba(245, 158, 11, ${linkAlpha})`;
            }

            ctx.lineWidth = Math.max(0.4, 1.2 * n1.scale);
            ctx.stroke();
          }
        }

        // Mouse interactive 3D tractor beam
        const mouseDist = Math.hypot(n1.sx - mouseX, n1.sy - mouseY);
        if (mouseDist < 160 && mouseX > 0) {
          const beamFactor = (1 - mouseDist / 160) * n1.alpha;
          ctx.beginPath();
          ctx.moveTo(n1.sx, n1.sy);
          ctx.lineTo(mouseX, mouseY);
          ctx.strokeStyle = isLight
            ? `rgba(217, 119, 6, ${beamFactor * 0.4})`
            : `rgba(245, 158, 11, ${beamFactor * 0.55})`;
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }
      }

      // --- 4. Render 3D Volumetric Glowing Nodes ---
      for (const node of projected) {
        ctx.save();
        ctx.beginPath();
        ctx.arc(node.sx, node.sy, Math.max(1, node.radius), 0, Math.PI * 2);

        // Core fill & outer glow
        if (node.colorType === 'cyan') {
          ctx.fillStyle = isLight
            ? `rgba(2, 132, 199, ${node.alpha * 0.9})`
            : `rgba(6, 182, 212, ${node.alpha})`;
          ctx.shadowColor = '#06b6d4';
        } else if (node.colorType === 'emerald') {
          ctx.fillStyle = isLight
            ? `rgba(16, 185, 129, ${node.alpha * 0.9})`
            : `rgba(52, 211, 153, ${node.alpha})`;
          ctx.shadowColor = '#10b981';
        } else {
          ctx.fillStyle = isLight
            ? `rgba(217, 119, 6, ${node.alpha * 0.95})`
            : `rgba(245, 158, 11, ${node.alpha})`;
          ctx.shadowColor = '#f59e0b';
        }

        ctx.shadowBlur = Math.max(3, 8 * node.scale);
        ctx.fill();

        // 3D Orbital ring on select hero nodes
        if (node.scale > 0.8 && node.colorType === 'amber') {
          ctx.beginPath();
          ctx.ellipse(
            node.sx,
            node.sy,
            node.radius * 2.8,
            node.radius * 1.2,
            (frame * 0.02) % (Math.PI * 2),
            0,
            Math.PI * 2
          );
          ctx.strokeStyle = isLight
            ? `rgba(217, 119, 6, ${node.alpha * 0.35})`
            : `rgba(245, 158, 11, ${node.alpha * 0.45})`;
          ctx.lineWidth = 0.7;
          ctx.stroke();
        }

        ctx.restore();
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
  }, [theme]);

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
        opacity: 0.9,
      }}
    />
  );
}

interface LayoutProps {
  children: React.ReactNode;
}

const navItems = [
  { path: '/', label: 'Dashboard', icon: <LayoutDashboard size={18} strokeWidth={1.8} /> },
  { path: '/findings', label: 'Findings', icon: <ShieldAlert size={18} strokeWidth={1.8} /> },
  { path: '/scan', label: 'New Scan', icon: <Terminal size={18} strokeWidth={1.8} /> },
  { path: '/compliance', label: 'Compliance', icon: <ShieldCheck size={18} strokeWidth={1.8} /> },
  { path: '/report', label: 'Reports', icon: <FileText size={18} strokeWidth={1.8} /> },
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

  const searchInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(event.target as Node)) {
        setNotifOpen(false);
      }
      if (avatarRef.current && !avatarRef.current.contains(event.target as Node)) {
        setAvatarOpen(false);
      }
    }

    function handleGlobalKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key === 'k') {
        event.preventDefault();
        searchInputRef.current?.focus();
        searchInputRef.current?.select();
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    window.addEventListener('keydown', handleGlobalKeyDown);

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      window.removeEventListener('keydown', handleGlobalKeyDown);
    };
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
            <Sliders size={16} strokeWidth={1.8} /> <span className="sidebar__link-label">Settings</span>
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
            <Menu size={18} strokeWidth={2} />
          </button>
          <div className="topbar__title-wrap">
            <h1 className="topbar__title">{pageTitle}</h1>
            <div className="topbar__status-pill">
              <span className="topbar__status-dot"></span>
              <span className="topbar__status-label">ENGINE ONLINE</span>
            </div>
          </div>

          <div className="topbar__actions">
            <div className="topbar__search">
              <span className="topbar__search-icon">
                <Search size={15} strokeWidth={2} />
              </span>
              <input
                ref={searchInputRef}
                type="text"
                className="topbar__search-input"
                placeholder="Search rule, path, title..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={handleSearchSubmit}
              />
              <kbd className="topbar__search-kbd">⌘K</kbd>
            </div>
            <button
              className="topbar__icon-btn"
              title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Theme`}
              onClick={toggleTheme}
            >
              {theme === 'dark' ? <Sun size={17} strokeWidth={2} /> : <Moon size={17} strokeWidth={2} />}
            </button>

            <div className="topbar__notif-container" ref={notifRef}>
              <button
                className="topbar__icon-btn"
                title="Notifications"
                onClick={() => setNotifOpen(!notifOpen)}
              >
                <Bell size={17} strokeWidth={2} />
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
                        <span className="notif-dropdown__empty-icon">
                          <Inbox size={28} strokeWidth={1.5} color="var(--text-muted)" />
                        </span>
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
                            {n.type === 'success' && <CheckCircle2 size={16} color="#00FF88" />}
                            {n.type === 'warning' && <AlertTriangle size={16} color="#FF9F1C" />}
                            {n.type === 'error' && <AlertOctagon size={16} color="#FF1E56" />}
                            {n.type === 'info' && <Info size={16} color="#00F2FE" />}
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
                      <span className="avatar-dropdown__menu-icon">
                        <User size={15} strokeWidth={1.8} />
                      </span>
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
                      <span className="avatar-dropdown__menu-icon">
                        <KeyRound size={15} strokeWidth={1.8} />
                      </span>
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
                      <span className="avatar-dropdown__menu-icon">
                        <Clock size={15} strokeWidth={1.8} />
                      </span>
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
                      <span className="avatar-dropdown__menu-icon">
                        <Sliders size={15} strokeWidth={1.8} />
                      </span>
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
