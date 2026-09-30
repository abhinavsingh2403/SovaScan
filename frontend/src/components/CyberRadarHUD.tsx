import React from 'react';
import { SovaIcon } from './SovaIcon';
import './CyberRadarHUD.css';

interface CyberRadarHUDProps {
  active?: boolean;
  phase?: string;
  percent?: number;
  findingsCount?: number;
  target?: string;
}

export const CyberRadarHUD: React.FC<CyberRadarHUDProps> = ({
  active = true,
  phase = 'Scanning...',
  percent = 0,
  findingsCount = 0,
  target,
}) => {
  // SVG circular progress calculation
  const radius = 86;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (Math.min(100, Math.max(0, percent)) / 100) * circumference;

  return (
    <div className={`telemetry-hud-wrapper ${active ? 'is-active' : 'is-idle'}`}>
      {/* Top Status Header */}
      <div className="telemetry-hud__status">
        {active ? (
          <div className="status-pill status-pill--active">
            <span className="status-indicator-dot animate-pulse-soft" />
            <span className="status-pill__label">ANALYSIS IN PROGRESS</span>
          </div>
        ) : (
          <div className="status-pill status-pill--idle">
            <span className="status-indicator-dot dot--idle" />
            <span className="status-pill__label">ENGINE STANDBY</span>
          </div>
        )}
      </div>

      {/* Main Precision Telemetry Dial */}
      <div className="telemetry-dial-container">
        <svg
          className="telemetry-dial-svg"
          viewBox="0 0 220 220"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            {/* Ambient Center Glow */}
            <radialGradient id="dial-ambient-glow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#6366f1" stopOpacity={active ? '0.18' : '0.06'} />
              <stop offset="70%" stopColor="#06b6d4" stopOpacity={active ? '0.06' : '0.02'} />
              <stop offset="100%" stopColor="transparent" stopOpacity="0" />
            </radialGradient>

            {/* Precision Progress Gradient */}
            <linearGradient id="telemetry-progress-grad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#818cf8" />
              <stop offset="50%" stopColor="#6366f1" />
              <stop offset="100%" stopColor="#06b6d4" />
            </linearGradient>

            {/* Subtle Sweep Gradient */}
            <linearGradient id="soothing-sweep-grad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#6366f1" stopOpacity="0" />
              <stop offset="85%" stopColor="#818cf8" stopOpacity="0.12" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.45" />
            </linearGradient>
          </defs>

          {/* Background Ambient Disc */}
          <circle cx="110" cy="110" r="98" fill="url(#dial-ambient-glow)" />

          {/* Outer Calibration Ring */}
          <circle
            cx="110"
            cy="110"
            r="102"
            fill="none"
            className="dial-ring dial-ring--outer"
          />

          {/* Precision Micro Ticks (36 calibrated ticks) */}
          {Array.from({ length: 36 }).map((_, idx) => {
            const angle = (idx * 360) / 360 * 10;
            const isMajor = idx % 9 === 0;
            const r1 = isMajor ? 95 : 98;
            const r2 = 102;
            const rad = (angle * Math.PI) / 180;
            return (
              <line
                key={idx}
                x1={110 + Math.cos(rad) * r1}
                y1={110 + Math.sin(rad) * r1}
                x2={110 + Math.cos(rad) * r2}
                y2={110 + Math.sin(rad) * r2}
                className={`dial-tick ${isMajor ? 'dial-tick--major' : 'dial-tick--minor'}`}
              />
            );
          })}

          {/* Progress Track Background */}
          <circle
            cx="110"
            cy="110"
            r={radius}
            fill="none"
            className="dial-track"
          />

          {/* Active Mathematical Progress Arc */}
          <circle
            cx="110"
            cy="110"
            r={radius}
            fill="none"
            stroke="url(#telemetry-progress-grad)"
            strokeWidth="3.5"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            className="dial-progress-bar"
            transform="rotate(-90 110 110)"
          />

          {/* Inner Restrained Reticle Ring */}
          <circle
            cx="110"
            cy="110"
            r="62"
            fill="none"
            className="dial-ring dial-ring--inner"
          />

          {/* Soothing Hairline Rotary Sweep (Active Only) */}
          {active && (
            <g className="dial-sweep-rotator">
              <line
                x1="110"
                y1="110"
                x2="110"
                y2="18"
                stroke="url(#soothing-sweep-grad)"
                strokeWidth="1.5"
                strokeLinecap="round"
              />
              <circle cx="110" cy="18" r="2" fill="#38bdf8" opacity="0.8" />
            </g>
          )}
        </svg>

        {/* Center Stage: Bespoke Sova Crest */}
        <div className="dial-center-content">
          <div className="dial-crest-stage">
            <SovaIcon size={46} glow={active} className={active ? 'crest-active-pulse' : 'crest-idle'} />
          </div>
          <div className="dial-percent-label">
            <span className="percent-val">{percent}</span>
            <span className="percent-sym">%</span>
          </div>
        </div>
      </div>

      {/* Telemetry Readout Pill */}
      <div className="telemetry-readout">
        <div className="telemetry-phase-badge truncate">
          {active ? phase : 'Engine Ready'}
        </div>
        {target && (
          <div className="telemetry-target-caption truncate" title={target}>
            {target}
          </div>
        )}
      </div>
    </div>
  );
};
