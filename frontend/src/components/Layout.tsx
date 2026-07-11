import { NavLink, useLocation } from 'react-router-dom';
import { useState, useEffect, useRef } from 'react';
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
        ctx.fillStyle = 'rgba(99, 102, 241, 0.25)';
        ctx.fill();

        const dxMouse = p1.x - mouse.x;
        const dyMouse = p1.y - mouse.y;
        const distMouse = Math.sqrt(dxMouse * dxMouse + dyMouse * dyMouse);
        if (distMouse < 180) {
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.strokeStyle = `rgba(99, 102, 241, ${0.15 * (1 - distMouse / 180)})`;
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
            ctx.strokeStyle = `rgba(99, 102, 241, ${0.1 * (1 - dist / 120)})`;
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
  '/settings': 'Settings',
};

export default function Layout({ children }: LayoutProps) {
  const location = useLocation();
  const [searchQuery, setSearchQuery] = useState('');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const pageTitle = pageTitles[location.pathname] || 'SovaScan';

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
            ⚙️ <span className="sidebar__link-label">Settings</span>
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
