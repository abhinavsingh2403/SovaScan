import React from 'react';

interface SovaIconProps {
  size?: number;
  className?: string;
  style?: React.CSSProperties;
  glow?: boolean;
}

/**
 * SovaIcon - Bespoke Vector Security Crest for SovaScan.
 * Minimalist geometric owl shield with attentive cyber optics and precision hairline contours.
 */
export const SovaIcon: React.FC<SovaIconProps> = ({
  size = 24,
  className = '',
  style,
  glow = false,
}) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`sova-icon ${className}`}
      style={{
        display: 'inline-block',
        verticalAlign: 'middle',
        flexShrink: 0,
        filter: glow ? 'drop-shadow(0 0 8px rgba(99, 102, 241, 0.45))' : undefined,
        ...style,
      }}
    >
      <defs>
        <linearGradient id="sova-crest-grad" x1="4" y1="2" x2="28" y2="30" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#818cf8" />
          <stop offset="50%" stopColor="#6366f1" />
          <stop offset="100%" stopColor="#4f46e5" />
        </linearGradient>
        <linearGradient id="sova-eye-grad" x1="10" y1="12" x2="22" y2="18" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38bdf8" />
          <stop offset="100%" stopColor="#06b6d4" />
        </linearGradient>
      </defs>

      {/* Outer Tactical Shield Silhouette */}
      <path
        d="M16 2.5 L27 7.5 V15 C27 21.8 22.2 27.5 16 29.5 C9.8 27.5 5 21.8 5 15 V7.5 L16 2.5 Z"
        fill="url(#sova-crest-grad)"
        fillOpacity="0.16"
        stroke="url(#sova-crest-grad)"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />

      {/* Inner Owl Brow / Feather Contours */}
      <path
        d="M7.5 10 L16 15 L24.5 10"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity="0.85"
      />

      {/* Attentive Left Eye */}
      <circle
        cx="11.5"
        cy="15"
        r="2.75"
        fill="url(#sova-eye-grad)"
        fillOpacity="0.25"
        stroke="url(#sova-eye-grad)"
        strokeWidth="1.3"
      />
      <circle cx="11.5" cy="15" r="1" fill="#38bdf8" />

      {/* Attentive Right Eye */}
      <circle
        cx="20.5"
        cy="15"
        r="2.75"
        fill="url(#sova-eye-grad)"
        fillOpacity="0.25"
        stroke="url(#sova-eye-grad)"
        strokeWidth="1.3"
      />
      <circle cx="20.5" cy="15" r="1" fill="#38bdf8" />

      {/* Geometric Beak */}
      <polygon
        points="16,16 14.2,19.2 16,21.5 17.8,19.2"
        fill="#f59e0b"
        stroke="#f59e0b"
        strokeWidth="0.8"
        strokeLinejoin="round"
      />

      {/* Tactical Center Line */}
      <line
        x1="16"
        y1="22"
        x2="16"
        y2="26.5"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinecap="round"
        opacity="0.5"
      />
    </svg>
  );
};
