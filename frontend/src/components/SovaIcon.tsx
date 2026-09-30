import React from 'react';

interface SovaIconProps {
  size?: number;
  className?: string;
  style?: React.CSSProperties;
  glow?: boolean;
}

/**
 * SovaIcon - The authentic SovaScan Project Owl.
 * Renders the project's canonical owl brand icon (matching the sidebar & header).
 */
export const SovaIcon: React.FC<SovaIconProps> = ({
  size = 32,
  className = '',
  style,
  glow = false,
}) => {
  return (
    <span
      role="img"
      aria-label="SovaScan Owl"
      className={`sova-project-owl ${className}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: `${size}px`,
        lineHeight: 1,
        userSelect: 'none',
        filter: glow
          ? 'drop-shadow(0 0 14px rgba(99, 102, 241, 0.8)) drop-shadow(0 0 6px rgba(56, 189, 248, 0.6))'
          : 'drop-shadow(0 2px 5px rgba(0, 0, 0, 0.45))',
        transition: 'filter 0.3s ease, transform 0.3s ease',
        ...style,
      }}
    >
      🦉
    </span>
  );
};

export default SovaIcon;
