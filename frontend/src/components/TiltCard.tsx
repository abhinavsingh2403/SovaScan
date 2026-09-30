import React, { useRef, useState, useCallback } from 'react';

interface TiltCardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  maxTilt?: number; // max tilt rotation degrees (default: 8)
  glare?: boolean;  // enable holographic specular glare
  className?: string;
  style?: React.CSSProperties;
  perspective?: number; // perspective depth in px (default: 1000)
  elevation?: number;  // translateZ lift on hover (default: 8)
}

/**
 * TiltCard: High-performance 3D perspective card with hardware-accelerated
 * pointer tracking, holographic sheen glare, and depth elevation.
 */
export const TiltCard: React.FC<TiltCardProps> = ({
  children,
  maxTilt = 8,
  glare = true,
  className = '',
  style = {},
  perspective = 1000,
  elevation = 8,
  ...rest
}) => {
  const cardRef = useRef<HTMLDivElement>(null);
  const [transform, setTransform] = useState<string>('perspective(1000px) rotateX(0deg) rotateY(0deg) translateZ(0px)');
  const [glareStyle, setGlareStyle] = useState<{ opacity: number; x: number; y: number }>({
    opacity: 0,
    x: 50,
    y: 50,
  });
  const [isHovered, setIsHovered] = useState(false);

  const handleMouseMove = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      const card = cardRef.current;
      if (!card) return;

      const rect = card.getBoundingClientRect();
      const clientX = e.clientX - rect.left;
      const clientY = e.clientY - rect.top;

      const xNorm = clientX / rect.width;   // 0 to 1
      const yNorm = clientY / rect.height;  // 0 to 1

      // Tilt angles: moving cursor left tilts Y positive, moving up tilts X negative
      const tiltX = (0.5 - yNorm) * (maxTilt * 2);
      const tiltY = (xNorm - 0.5) * (maxTilt * 2);

      setTransform(
        `perspective(${perspective}px) rotateX(${tiltX.toFixed(2)}deg) rotateY(${tiltY.toFixed(2)}deg) translateZ(${elevation}px)`
      );

      if (glare) {
        setGlareStyle({
          opacity: 0.18,
          x: Math.round(xNorm * 100),
          y: Math.round(yNorm * 100),
        });
      }
    },
    [maxTilt, perspective, elevation, glare]
  );

  const handleMouseEnter = useCallback(() => {
    setIsHovered(true);
  }, []);

  const handleMouseLeave = useCallback(() => {
    setIsHovered(false);
    setTransform(`perspective(${perspective}px) rotateX(0deg) rotateY(0deg) translateZ(0px)`);
    if (glare) {
      setGlareStyle((prev) => ({ ...prev, opacity: 0 }));
    }
  }, [perspective, glare]);

  return (
    <div
      ref={cardRef}
      className={`tilt-card-root ${className}`}
      onMouseMove={handleMouseMove}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      style={{
        transform,
        transformStyle: 'preserve-3d',
        transition: isHovered
          ? 'transform 0.08s ease-out, box-shadow 0.25s ease'
          : 'transform 0.5s cubic-bezier(0.2, 0.8, 0.2, 1), box-shadow 0.5s ease',
        position: 'relative',
        willChange: 'transform',
        ...style,
      }}
      {...rest}
    >
      {/* 3D Content Container with nested preserve-3d */}
      <div style={{ transformStyle: 'preserve-3d', width: '100%', height: '100%' }}>
        {children}
      </div>

      {/* Holographic Specular Glare Overlay */}
      {glare && (
        <div
          aria-hidden="true"
          style={{
            position: 'absolute',
            inset: 0,
            pointerEvents: 'none',
            borderRadius: 'inherit',
            background: `radial-gradient(circle at ${glareStyle.x}% ${glareStyle.y}%, rgba(255, 255, 255, 0.28) 0%, rgba(245, 158, 11, 0.08) 35%, transparent 70%)`,
            opacity: glareStyle.opacity,
            transition: 'opacity 0.25s ease-out',
            zIndex: 10,
            mixBlendMode: 'overlay',
          }}
        />
      )}
    </div>
  );
};

export default TiltCard;
