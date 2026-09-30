import React, { useEffect, useRef, useState } from 'react';
import './CyberRadarHUD.css';

interface CyberRadarHUDProps {
  active?: boolean;
  phase?: string;
  percent?: number;
  findingsCount?: number;
  target?: string;
}

interface Blip {
  id: number;
  angle: number; // degrees
  radius: number; // 0 to 1
  color: string;
  size: number;
  life: number;
}

export const CyberRadarHUD: React.FC<CyberRadarHUDProps> = ({
  active = true,
  phase = 'Scanning...',
  percent = 0,
  findingsCount = 0,
}) => {
  const [blips, setBlips] = useState<Blip[]>([]);
  const sweepAngleRef = useRef(0);
  const animFrameRef = useRef<number>(0);

  // Spawn random radar detection blips when active
  useEffect(() => {
    if (!active) {
      setBlips([]);
      return;
    }

    const interval = setInterval(() => {
      setBlips((prev) => {
        // Keep max 5 blips alive
        const filtered = prev.filter((b) => b.life > 0.1).map((b) => ({ ...b, life: b.life - 0.08 }));
        if (filtered.length < 4 && Math.random() > 0.3) {
          const colors = ['#f43f5e', '#fb923c', '#facc15', '#06b6d4', '#10b981'];
          filtered.push({
            id: Date.now() + Math.random(),
            angle: Math.random() * 360,
            radius: 0.35 + Math.random() * 0.5,
            color: colors[Math.floor(Math.random() * colors.length)],
            size: Math.random() * 3 + 3,
            life: 1.0,
          });
        }
        return filtered;
      });
    }, 350);

    return () => clearInterval(interval);
  }, [active]);

  // Smooth 360° sweep rotation
  const [sweepDeg, setSweepDeg] = useState(0);
  useEffect(() => {
    if (!active) return;
    let lastTime = performance.now();

    const loop = (now: number) => {
      const dt = (now - lastTime) / 1000;
      lastTime = now;
      sweepAngleRef.current = (sweepAngleRef.current + dt * 110) % 360;
      setSweepDeg(sweepAngleRef.current);
      animFrameRef.current = requestAnimationFrame(loop);
    };

    animFrameRef.current = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(animFrameRef.current);
  }, [active]);

  return (
    <div className={`cyber-hud-root ${active ? 'is-active' : 'is-idle'}`}>
      {/* Outer Glow Halo */}
      <div className="cyber-hud-halo" />

      {/* SVG Vector Orbital System */}
      <svg className="cyber-hud-svg" viewBox="0 0 240 240">
        <defs>
          {/* Holographic Sova Amber/Cyan Radial Glow */}
          <radialGradient id="hud-radar-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.22" />
            <stop offset="65%" stopColor="#06b6d4" stopOpacity="0.08" />
            <stop offset="100%" stopColor="#030712" stopOpacity="0" />
          </radialGradient>

          {/* Radar Sweep Conic Gradient */}
          <linearGradient id="laser-line-grad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#06b6d4" stopOpacity="0" />
            <stop offset="60%" stopColor="#f59e0b" stopOpacity="0.5" />
            <stop offset="100%" stopColor="#ffffff" stopOpacity="1" />
          </linearGradient>

          {/* Wedge Gradient */}
          <linearGradient id="hud-wedge-grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.4" />
            <stop offset="70%" stopColor="#f59e0b" stopOpacity="0.1" />
            <stop offset="100%" stopColor="#06b6d4" stopOpacity="0" />
          </linearGradient>

          {/* Grid Pattern */}
          <filter id="hud-bloom" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Radar Background Glass Disc */}
        <circle cx="120" cy="120" r="108" className="hud-disc-bg" fill="url(#hud-radar-glow)" />

        {/* Concentric Crosshairs */}
        <line x1="12" y1="120" x2="228" y2="120" className="hud-grid-line" />
        <line x1="120" y1="12" x2="120" y2="228" className="hud-grid-line" />

        {/* Concentric Range Rings */}
        <circle cx="120" cy="120" r="106" className="hud-range-ring outer" />
        <circle cx="120" cy="120" r="82" className="hud-range-ring mid" />
        <circle cx="120" cy="120" r="54" className="hud-range-ring inner" />
        <circle cx="120" cy="120" r="28" className="hud-range-ring core" />

        {/* Outer Telemetry Compass Ticks */}
        {Array.from({ length: 24 }).map((_, i) => {
          const angle = (i * 360) / 24;
          const isMajor = i % 6 === 0;
          const r1 = isMajor ? 101 : 104;
          const r2 = 108;
          const rad = (angle * Math.PI) / 180;
          return (
            <line
              key={i}
              x1={120 + Math.cos(rad) * r1}
              y1={120 + Math.sin(rad) * r1}
              x2={120 + Math.cos(rad) * r2}
              y2={120 + Math.sin(rad) * r2}
              className={`hud-tick ${isMajor ? 'major' : 'minor'}`}
            />
          );
        })}

        {/* Rotating Outer Gyro Track (Clockwise) */}
        <g className="hud-gyro-clockwise">
          <circle
            cx="120"
            cy="120"
            r="98"
            className="hud-dashed-arc cyan"
            strokeDasharray="42 22 18 36"
            fill="none"
          />
        </g>

        {/* Rotating Middle Gyro Track (Counter-Clockwise) */}
        <g className="hud-gyro-counter">
          <circle
            cx="120"
            cy="120"
            r="89"
            className="hud-dashed-arc amber"
            strokeDasharray="60 30 20 40"
            fill="none"
          />
        </g>

        {/* Rotary Scanning Beam (Phosphor Sweep) */}
        {active && (
          <g transform={`rotate(${sweepDeg}, 120, 120)`}>
            {/* Volumetric Conic Sweep Wedge using SVG Path */}
            <path
              d="M 120 120 L 226 120 A 106 106 0 0 0 178 30 Z"
              className="hud-sweep-wedge"
            />
            {/* Leading Sharp Laser Beam Line */}
            <line
              x1="120"
              y1="120"
              x2="226"
              y2="120"
              className="hud-laser-line"
              stroke="url(#laser-line-grad)"
              filter="url(#hud-bloom)"
            />
            {/* Laser Tip Spark */}
            <circle cx="226" cy="120" r="2.5" className="hud-laser-tip" />
          </g>
        )}

        {/* Dynamic Threat Blips (Echoes on Radar) */}
        {active &&
          blips.map((blip) => {
            const rad = (blip.angle * Math.PI) / 180;
            const dist = blip.radius * 96;
            const bx = 120 + Math.cos(rad) * dist;
            const by = 120 + Math.sin(rad) * dist;
            return (
              <g key={blip.id} opacity={blip.life}>
                <circle
                  cx={bx}
                  cy={by}
                  r={blip.size * (2 - blip.life)}
                  fill="none"
                  stroke={blip.color}
                  strokeWidth="0.8"
                  opacity={blip.life * 0.8}
                />
                <circle cx={bx} cy={by} r={blip.size * 0.7} fill={blip.color} filter="url(#hud-bloom)" />
              </g>
            );
          })}

        {/* 4 Corner Target Lock Brackets */}
        <path d="M 52 70 L 46 70 L 46 76" className="hud-bracket" />
        <path d="M 188 70 L 194 70 L 194 76" className="hud-bracket" />
        <path d="M 52 170 L 46 170 L 46 164" className="hud-bracket" />
        <path d="M 188 170 L 194 170 L 194 164" className="hud-bracket" />

        {/* Cardinal Hex Legend */}
        <text x="120" y="24" className="hud-legend-text top" textAnchor="middle">000° // NOR</text>
        <text x="216" y="124" className="hud-legend-text right">090°</text>
        <text x="120" y="222" className="hud-legend-text btm" textAnchor="middle">180° // SOV</text>
        <text x="24" y="124" className="hud-legend-text left" textAnchor="end">270°</text>
      </svg>

      {/* Holographic Center Mascot Stage */}
      <div className="cyber-mascot-pod">
        {/* Hologram Pedestal Light Disc */}
        <div className="mascot-pedestal-glow" />
        <div className="mascot-pedestal-ring" />

        {/* Center Floating Sova Owl */}
        <div className="cyber-owl-container">
          <span className="cyber-owl-glyph">🦉</span>
          {/* Scanning Laser Beam Line passing through the owl */}
          {active && <div className="cyber-mascot-laser-scan" />}
        </div>
      </div>

      {/* Live Cyber Frequency Bars & Telemetry Pill */}
      {active && (
        <div className="cyber-telemetry-hud">
          <div className="telemetry-tag">
            <span className="telemetry-dot" />
            <span className="telemetry-label">SYS_FREQ // {Math.round(100 + percent * 1.4)} MHz</span>
          </div>

          {/* Equalizer Frequency Wave */}
          <div className="cyber-eq-bars">
            {Array.from({ length: 12 }).map((_, idx) => (
              <span
                key={idx}
                className="eq-bar"
                style={{
                  animationDelay: `${idx * 0.08}s`,
                  height: `${Math.max(4, Math.sin(idx * 0.6 + percent * 0.1) * 12 + 6)}px`,
                }}
              />
            ))}
          </div>

          <div className="telemetry-tag right">
            <span className="telemetry-label font-cyan">VULN_LOGS [{findingsCount}]</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default CyberRadarHUD;
