import type { ReactNode } from "react";
import { useEffect, useRef, useState } from "react";

/**
 * ScoreRadial — animated SVG donut + per-domain arc breakdown.
 *
 * Renders a large center donut arc for the overall security score
 * (0–100) surrounded by six thin domain rings, each animating from
 * 0 → their actual value on mount via a CSS transition.
 *
 * Color semantics (always paired with ARIA labels — no color-only meaning):
 *   ≥ 80  → #4ade80  (green — strong)
 *   50–79 → #fbbf24  (amber — partial)
 *   < 50  → #f87171  (red — weak)
 *   null  → steel    (withheld)
 */

export interface DomainScore {
  /** Short label shown on the legend */
  label: string;
  /** 0–100, or null if withheld */
  value: number | null;
}

export interface ScoreRadialProps {
  /** Overall security score 0–100, or null if withheld */
  securityScore: number | null;
  /** Overall risk score 0–100, or null if withheld */
  riskScore: number | null;
  /** Per-domain breakdown (up to 6 rings shown) */
  domains: DomainScore[];
  /** Evidence coverage percentage 0–100 */
  coverage: number;
}

function scoreColor(value: number | null): string {
  if (value === null) return "#86868b";
  if (value >= 80) return "#34c759";
  if (value >= 50) return "#ff9500";
  return "#ff3b30";
}

function scoreLabel(value: number | null): string {
  if (value === null) return "Withheld";
  if (value >= 80) return "Strong";
  if (value >= 50) return "Moderate";
  return "Weak";
}

/** Compute SVG arc path for a partial circle (donut ring segment). */
function arcPath(cx: number, cy: number, r: number, startAngle: number, endAngle: number): string {
  const toRad = (deg: number) => ((deg - 90) * Math.PI) / 180;
  const x1 = cx + r * Math.cos(toRad(startAngle));
  const y1 = cy + r * Math.sin(toRad(startAngle));
  const x2 = cx + r * Math.cos(toRad(endAngle));
  const y2 = cy + r * Math.sin(toRad(endAngle));
  const large = endAngle - startAngle > 180 ? 1 : 0;
  return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
}

// SVG canvas constants
const CX = 110;
const CY = 110;
const OUTER_R = 82; // main donut ring radius
const STROKE_W = 16; // donut stroke width
const DOMAIN_GAP = 5; // gap between domain rings
const DOMAIN_STROKE = 5; // domain ring stroke width

// Six domain ring radii (inside the donut)
const DOMAIN_RADII = [
  OUTER_R - STROKE_W / 2 - DOMAIN_GAP - DOMAIN_STROKE / 2,
  OUTER_R - STROKE_W / 2 - DOMAIN_GAP * 2 - (DOMAIN_STROKE * 3) / 2,
  OUTER_R - STROKE_W / 2 - DOMAIN_GAP * 3 - (DOMAIN_STROKE * 5) / 2,
  OUTER_R - STROKE_W / 2 - DOMAIN_GAP * 4 - (DOMAIN_STROKE * 7) / 2,
  OUTER_R - STROKE_W / 2 - DOMAIN_GAP * 5 - (DOMAIN_STROKE * 9) / 2,
  OUTER_R - STROKE_W / 2 - DOMAIN_GAP * 6 - (DOMAIN_STROKE * 11) / 2,
];

function AnimatedArc({
  cx,
  cy,
  r,
  value,
  color,
  strokeWidth,
  delay = 0,
}: {
  cx: number;
  cy: number;
  r: number;
  value: number | null;
  color: string;
  strokeWidth: number;
  delay?: number;
}): ReactNode {
  const [progress, setProgress] = useState(0);
  const rafRef = useRef<number | null>(null);
  const startRef = useRef<number | null>(null);
  const DURATION = 900; // ms

  const target = value !== null ? value / 100 : 0;

  useEffect(() => {
    const timeout = setTimeout(() => {
      const animate = (ts: number) => {
        if (startRef.current === null) startRef.current = ts;
        const elapsed = ts - startRef.current;
        const t = Math.min(elapsed / DURATION, 1);
        // Ease out cubic
        const eased = 1 - Math.pow(1 - t, 3);
        setProgress(eased * target);
        if (t < 1) {
          rafRef.current = requestAnimationFrame(animate);
        }
      };
      rafRef.current = requestAnimationFrame(animate);
    }, delay);

    return () => {
      clearTimeout(timeout);
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
      startRef.current = null;
    };
  }, [target, delay]);

  // We draw a full 330° arc (leaving a 30° gap at bottom) for aesthetics
  const ARC_DEG = 330;

  const trackPath = arcPath(cx, cy, r, -15, ARC_DEG - 15);
  const fillPath = arcPath(cx, cy, r, -15, ARC_DEG * progress - 15);

  return (
    <>
      {/* Light Apple Studio track */}
      <path
        d={trackPath}
        fill="none"
        stroke="#e6e6e8"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
      />
      {/* Animated fill */}
      {progress > 0.005 && (
        <path
          d={fillPath}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />
      )}
    </>
  );
}

export function ScoreRadial({
  securityScore,
  riskScore,
  domains,
  coverage,
}: ScoreRadialProps): ReactNode {
  const mainColor = scoreColor(securityScore);
  const mainLabel = scoreLabel(securityScore);

  const shownDomains = domains.slice(0, DOMAIN_RADII.length);

  return (
    <div
      className="flex flex-col items-center gap-4"
      role="region"
      aria-label="Security score radial chart"
    >
      {/* SVG chart */}
      <div className="relative">
        <svg
          width={220}
          height={220}
          viewBox="0 0 220 220"
          aria-hidden="true"
          className="overflow-visible"
        >
          {/* Main security score donut */}
          <g>
            <AnimatedArc
              cx={CX}
              cy={CY}
              r={OUTER_R}
              value={securityScore}
              color={mainColor}
              strokeWidth={STROKE_W}
              delay={0}
            />
          </g>

          {/* Domain breakdown rings */}
          {shownDomains.map((d, i) => (
            <AnimatedArc
              key={d.label}
              cx={CX}
              cy={CY}
              r={DOMAIN_RADII[i] ?? 10}
              value={d.value}
              color={scoreColor(d.value)}
              strokeWidth={DOMAIN_STROKE}
              delay={180 + i * 80}
            />
          ))}

          {/* Center text */}
          {securityScore !== null ? (
            <>
              <text
                x={CX}
                y={CY - 10}
                textAnchor="middle"
                fill="#1d1d1f"
                fontSize="32"
                fontWeight="700"
                fontFamily="-apple-system, BlinkMacSystemFont, 'SF Pro Display', sans-serif"
                letterSpacing="-0.03em"
              >
                {securityScore}
              </text>
              <text
                x={CX}
                y={CY + 10}
                textAnchor="middle"
                fill="#707070"
                fontSize="11"
                fontFamily="-apple-system, BlinkMacSystemFont, 'SF Pro Text', sans-serif"
                letterSpacing="-0.01em"
              >
                / 100
              </text>
              <text
                x={CX}
                y={CY + 25}
                textAnchor="middle"
                fill={mainColor}
                fontSize="10"
                fontWeight="600"
                fontFamily="-apple-system, BlinkMacSystemFont, 'SF Pro Text', sans-serif"
                letterSpacing="0.04em"
              >
                {mainLabel.toUpperCase()}
              </text>
            </>
          ) : (
            <>
              <text
                x={CX}
                y={CY - 5}
                textAnchor="middle"
                fill="#86868b"
                fontSize="12"
                fontWeight="600"
                fontFamily="-apple-system, BlinkMacSystemFont, 'SF Pro Text', sans-serif"
                letterSpacing="0.04em"
              >
                WITHHELD
              </text>
              <text
                x={CX}
                y={CY + 12}
                textAnchor="middle"
                fill="#86868b"
                fontSize="9"
                fontFamily="-apple-system, BlinkMacSystemFont, 'SF Pro Text', sans-serif"
              >
                insufficient evidence
              </text>
            </>
          )}
        </svg>

        {/* Risk score pill — bottom overlay */}
        {riskScore !== null && (
          <div
            className="absolute bottom-1 left-1/2 -translate-x-1/2 rounded-full border border-[#d6d6d6] bg-[#ffffff] px-2.5 py-0.5 text-[10px] font-semibold text-[#b64400] tnum shadow-none"
            aria-label={`Risk score: ${riskScore}`}
          >
            Risk {riskScore}
          </div>
        )}
      </div>

      {/* Domain legend */}
      {shownDomains.length > 0 && (
        <ol className="w-full space-y-1.5" aria-label="Per-domain score breakdown">
          {shownDomains.map((d, i) => {
            const color = scoreColor(d.value);
            const ringColor = DOMAIN_RADII[i] !== undefined ? color : "#86868b";
            return (
              <li key={d.label} className="flex items-center gap-2 text-xs">
                {/* Color swatch matches the ring */}
                <span
                  aria-hidden="true"
                  className="inline-block h-1.5 w-4 rounded-full flex-shrink-0"
                  style={{ background: ringColor }}
                />
                <span className="flex-1 truncate text-ink-muted">{d.label}</span>
                <span
                  className="tnum font-mono font-medium"
                  style={{ color: ringColor }}
                  aria-label={`${d.label}: ${d.value ?? "withheld"}`}
                >
                  {d.value !== null ? d.value : "—"}
                </span>
              </li>
            );
          })}
        </ol>
      )}

      {/* Evidence coverage */}
      <p className="text-xs text-ink-muted">
        Evidence coverage: <strong className="text-ink tnum">{coverage}%</strong>
      </p>
    </div>
  );
}
