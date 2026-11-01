import { AnimatePresence, motion } from "framer-motion";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  ClipboardCopy,
  DatabaseZap,
  Info,
  Loader2,
  Search,
  ShieldAlert,
  X,
  XCircle,
} from "lucide-react";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import clsx from "clsx";
import { fmtNumber, riskColor, severityMeta, STATUS_TONE, titleCase } from "../lib/format";
import { tone } from "../lib/theme";

/* ------------------------------------------------------------------ */
/* Brand                                                               */
/* ------------------------------------------------------------------ */

export function LogoMark({ size = 30, animated = false, onLight = false }: { size?: number; animated?: boolean; onLight?: boolean }) {
  const id = onLight ? "lg-light" : "lg";
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none" aria-hidden="true">
      <path d="M20 2.8 34 10v12.2c0 7.2-5.5 12.4-14 15-8.5-2.6-14-7.8-14-15V10L20 2.8Z" stroke={`url(#${id})`} strokeWidth="1.4" />
      <path d="M20 8.4 29.2 13v8.6c0 4.8-3.6 8.4-9.2 10.4-5.6-2-9.2-5.6-9.2-10.4V13L20 8.4Z" fill={onLight ? "rgba(10,23,40,0.06)" : "rgba(73,184,255,0.06)"} stroke={onLight ? "rgba(10,40,62,0.55)" : "rgba(73,184,255,0.55)"} strokeWidth="1" />
      <ellipse cx="20" cy="19.5" rx="8.1" ry="3.3" stroke={onLight ? "#246080" : "#64d8ff"} strokeWidth="1" opacity="0.8" transform="rotate(-24 20 19.5)" />
      <ellipse cx="20" cy="19.5" rx="8.1" ry="3.3" stroke={onLight ? "#4b55a8" : "#9a8cff"} strokeWidth="1" opacity="0.5" transform="rotate(48 20 19.5)" />
      <circle cx="20" cy="19.5" r="2.1" fill={onLight ? "#0a1728" : "#8be4ff"} />
      {animated && <circle cx="20" cy="19.5" r="11" stroke={onLight ? "rgba(10,40,62,0.3)" : "rgba(100,216,255,0.35)"} strokeWidth="0.6" strokeDasharray="3 8" />}
      <defs>
        <linearGradient id={id} x1="6" y1="4" x2="34" y2="36" gradientUnits="userSpaceOnUse">
          <stop stopColor={onLight ? "#1e5674" : "#a3ecff"} />
          <stop offset="0.55" stopColor={onLight ? "#0a2d49" : "#49b8ff"} />
          <stop offset="1" stopColor={onLight ? "#4d5bb5" : "#9a8cff"} />
        </linearGradient>
      </defs>
    </svg>
  );
}

export function Wordmark({ compact = false, onLight = false }: { compact?: boolean; onLight?: boolean }) {
  return (
    <span className="flex items-center gap-2.5">
      <LogoMark size={compact ? 26 : 30} onLight={onLight} />
      <span className={clsx("font-display font-semibold tracking-[-0.03em]", onLight ? "text-midnight" : "text-ink", compact ? "text-[14px]" : "text-[15px]")}>
        CYBER<span className={clsx("ml-1 text-[10px] font-medium tracking-[0.22em]", onLight ? "text-[#246080]" : "text-ion/90")}>GUARD</span>
      </span>
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Badges & chips                                                      */
/* ------------------------------------------------------------------ */

export function SeverityBadge({ severity, className }: { severity?: string | null; className?: string }) {
  const meta = severityMeta(severity);
  return (
    <span
      className={clsx(
        "inline-flex h-[21px] items-center gap-1.5 rounded-[5px] border px-2 font-mono text-[9px] uppercase tracking-[0.12em]",
        meta.bg,
        meta.border,
        meta.text,
        className,
      )}
    >
      <span className={clsx("h-1 w-1 rounded-full", meta.dot)} />
      {meta.label}
    </span>
  );
}

export function StatusBadge({ status, className }: { status?: string | null; className?: string }) {
  if (!status) return <span className="text-dim">—</span>;
  return (
    <span
      className={clsx(
        "inline-flex h-[21px] items-center rounded-[5px] border px-2 font-mono text-[9px] uppercase tracking-[0.1em]",
        STATUS_TONE[status] || "border-veil/10 bg-veil/5 text-mist",
        className,
      )}
    >
      {titleCase(status)}
    </span>
  );
}

export function LiveDot({ tone = "low", label }: { tone?: "low" | "med" | "crit" | "ion"; label?: string }) {
  const color = tone === "crit" ? "bg-crit" : tone === "med" ? "bg-med" : tone === "ion" ? "bg-ion" : "bg-low";
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-[0.14em] text-mist">
      <span className="relative flex h-1.5 w-1.5">
        <span className={clsx("absolute inline-flex h-full w-full animate-ping rounded-full opacity-60", color)} />
        <span className={clsx("relative inline-flex h-1.5 w-1.5 rounded-full", color)} />
      </span>
      {label}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Layout primitives                                                   */
/* ------------------------------------------------------------------ */

export function PageHeader({
  title,
  description,
  actions,
  aside,
  kicker,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  aside?: ReactNode;
  kicker?: ReactNode;
}) {
  return (
    <div className="relative mb-5 flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
      <div className="relative min-w-0">
        {kicker && <div className="page-eyebrow mb-2.5">{kicker}</div>}
        <h1 className="page-title">{title}</h1>
        {description && <p className="mt-2.5 max-w-[74ch] text-[13px] leading-relaxed text-mist">{description}</p>}
        {aside && <div className="mt-3">{aside}</div>}
      </div>
      {actions && <div className="relative flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Panel({
  children,
  className,
  ticks = false,
  as: Component = "section",
}: {
  children: ReactNode;
  className?: string;
  ticks?: boolean;
  as?: any;
}) {
  return (
    <Component className={clsx("panel", ticks && "panel-ticks", className)}>
      <span className="panel-glass" aria-hidden="true" />
      {children}
    </Component>
  );
}

export function PanelHead({
  title,
  kicker,
  right,
  className,
}: {
  title: ReactNode;
  kicker?: ReactNode;
  right?: ReactNode;
  className?: string;
}) {
  return (
    <div className={clsx("panel-head", className)}>
      <div className="min-w-0">
        {kicker && <div className="panel-kicker mb-1">{kicker}</div>}
        <div className="panel-title truncate">{title}</div>
      </div>
      {right && <div className="flex shrink-0 items-center gap-2">{right}</div>}
    </div>
  );
}

export function Kpi({
  label,
  value,
  detail,
  icon,
  tone = "ion",
  className,
}: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  icon?: ReactNode;
  tone?: "ion" | "crit" | "high" | "med" | "low" | "violet";
  className?: string;
}) {
  const toneMap = {
    ion: "text-ion border-ion/25 bg-ion/[0.06]",
    crit: "text-crit border-crit/25 bg-crit/[0.06]",
    high: "text-high border-high/25 bg-high/[0.06]",
    med: "text-med border-med/25 bg-med/[0.06]",
    low: "text-low border-low/25 bg-low/[0.06]",
    violet: "text-violet border-violet/25 bg-violet/[0.06]",
  };
  const accent: Record<keyof typeof toneMap, string> = {
    ion: "#64d8ff",
    crit: "#ff4d5e",
    high: "#ff963d",
    med: "#ffd166",
    low: "#42c98a",
    violet: "#9a8cff",
  };
  return (
    <div
      className={clsx(
        "stat-tile group px-4 py-4 transition-[border-color,box-shadow,transform] duration-300 hover:-translate-y-[1px] hover:border-line-strong",
        className,
      )}
    >
      <span className="panel-glass" aria-hidden="true" />
      <span
        className="pointer-events-none absolute inset-x-4 top-0 h-px opacity-80"
        style={{ background: `linear-gradient(90deg, transparent, ${accent[tone]}, transparent)` }}
        aria-hidden="true"
      />
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-start gap-1.5 text-[12px] font-medium leading-[1.4] tracking-[-0.005em] text-mist">
            <span className="mt-[5px] h-1 w-1 shrink-0 rounded-full" style={{ background: accent[tone] }} />
            <span className="min-w-0">{label}</span>
          </div>
          <div className="tnum mt-2.5 font-display text-[32px] font-semibold leading-none tracking-[-0.025em] text-ink">{value}</div>
          {detail && <div className="mt-2 text-[10.5px] leading-relaxed text-dim">{detail}</div>}
        </div>
        {icon && (
          <span className={clsx("grid h-8 w-8 shrink-0 place-items-center rounded-[10px] border shadow-[inset_0_1px_0_rgba(255,255,255,0.08)]", toneMap[tone])}>
            {icon}
          </span>
        )}
      </div>
      <span
        className="pointer-events-none absolute -bottom-10 right-0 h-20 w-20 rounded-full opacity-[0.14] blur-2xl transition-opacity duration-300 group-hover:opacity-[0.24]"
        style={{ background: accent[tone] }}
        aria-hidden="true"
      />
    </div>
  );
}

export function AnimatedNumber({
  value,
  decimals = 0,
  prefix,
  suffix,
  className,
}: {
  value?: number | null;
  decimals?: number;
  prefix?: string;
  suffix?: string;
  className?: string;
}) {
  const [display, setDisplay] = useState<number | null>(typeof value === "number" ? value : null);
  const current = useRef(typeof value === "number" ? value : 0);

  useEffect(() => {
    if (typeof value !== "number" || !Number.isFinite(value)) {
      setDisplay(null);
      return;
    }
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) {
      current.current = value;
      setDisplay(value);
      return;
    }
    const from = current.current;
    const start = performance.now();
    let raf = 0;
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / 850);
      const eased = 1 - Math.pow(1 - progress, 4);
      const next = from + (value - from) * eased;
      current.current = next;
      setDisplay(next);
      if (progress < 1) raf = requestAnimationFrame(tick);
      else current.current = value;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);

  return (
    <span className={clsx("tnum", className)}>
      {display === null ? "—" : `${prefix || ""}${display.toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals })}${suffix || ""}`}
    </span>
  );
}

export function RadialGauge({
  value,
  size = 104,
  label,
  className,
}: {
  value?: number | null;
  size?: number;
  label?: string;
  className?: string;
}) {
  const safe = typeof value === "number" && Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0;
  const radius = size / 2 - 8;
  const circumference = Math.PI * radius;
  const offset = circumference - (safe / 100) * circumference;
  const color = riskColor(safe);
  return (
    <div className={clsx("relative shrink-0", className)} style={{ width: size, height: size / 2 + 22 }}>
      <svg viewBox={`0 0 ${size} ${size / 2 + 22}`} width={size} height={size / 2 + 22} aria-hidden="true">
        <path
          d={`M 8 ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 8} ${size / 2}`}
          fill="none"
          stroke="rgb(var(--line-rgb) / 0.15)"
          strokeWidth={5}
          strokeLinecap="round"
        />
        <path
          d={`M 8 ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 8} ${size / 2}`}
          fill="none"
          stroke={color}
          strokeWidth={5}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 900ms cubic-bezier(0.16,1,0.3,1)", filter: `drop-shadow(0 0 6px ${color}88)` }}
        />
        {[0.25, 0.5, 0.75].map((tick) => {
          const angle = Math.PI - tick * Math.PI;
          const x1 = size / 2 + Math.cos(angle) * (radius - 9);
          const y1 = size / 2 - Math.sin(angle) * (radius - 9);
          const x2 = size / 2 + Math.cos(angle) * (radius - 3);
          const y2 = size / 2 - Math.sin(angle) * (radius - 3);
          return <line key={tick} x1={x1} y1={y1} x2={x2} y2={y2} stroke="rgb(var(--line-rgb) / 0.3)" strokeWidth={1} />;
        })}
      </svg>
      <div className="absolute inset-x-0 bottom-1 text-center">
        <div className="tnum font-display text-[19px] font-semibold leading-none text-ink">
          {typeof value === "number" ? <AnimatedNumber value={value} /> : "—"}
        </div>
        {label && <div className="mt-1 font-mono text-[7.5px] uppercase tracking-[0.16em] text-dim">{label}</div>}
      </div>
    </div>
  );
}

export function NeedleGauge({
  value,
  size = 148,
  className,
}: {
  value?: number | null;
  size?: number;
  className?: string;
}) {
  const safe = typeof value === "number" && Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0;
  const w = size;
  const h = Math.round(size * 0.6);
  const cx = w / 2;
  const cy = h - 8;
  const r = w / 2 - 14;
  const angle = Math.PI + (safe / 100) * Math.PI;
  const needleLength = r - 16;
  const nx = cx + Math.cos(angle) * needleLength;
  const ny = cy + Math.sin(angle) * needleLength;
  const id = useId().replace(/:/g, "");
  return (
    <div className={clsx("relative shrink-0", className)} style={{ width: w, height: h }} aria-hidden="true">
      <svg viewBox={`0 0 ${w} ${h}`} width={w} height={h}>
        <defs>
          <linearGradient id={`arc-${id}`} x1={cx - r} y1={cy} x2={cx + r} y2={cy} gradientUnits="userSpaceOnUse">
            <stop stopColor="var(--pulse)" />
            <stop offset="0.55" stopColor="var(--ion)" />
            <stop offset="1" stopColor="var(--crystal)" />
          </linearGradient>
          <radialGradient id={`pivot-${id}`} cx="50%" cy="50%" r="50%">
            <stop stopColor="var(--crystal)" />
            <stop offset="0.55" stopColor="var(--ion)" />
            <stop offset="1" stopColor="var(--pulse)" />
          </radialGradient>
        </defs>
        <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`} fill="none" stroke="rgb(var(--line-rgb) / 0.16)" strokeWidth={9} strokeLinecap="round" />
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke={`url(#arc-${id})`}
          strokeWidth={9}
          strokeLinecap="round"
          style={{ filter: "drop-shadow(0 4px 10px rgb(var(--ion-rgb) / 0.28))" }}
        />
        <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`} fill="none" stroke="rgb(var(--surface-rgb) / 0.55)" strokeWidth={11} strokeDasharray="1 13" opacity={0.55} />
        {Array.from({ length: 9 }, (_, index) => {
          const t = index / 8;
          const tickAngle = Math.PI + t * Math.PI;
          const inner = r - 4;
          const outer = r + 4;
          return (
            <line
              key={t}
              x1={cx + Math.cos(tickAngle) * inner}
              y1={cy + Math.sin(tickAngle) * inner}
              x2={cx + Math.cos(tickAngle) * outer}
              y2={cy + Math.sin(tickAngle) * outer}
              stroke="rgb(var(--line-rgb) / 0.35)"
              strokeWidth={1}
            />
          );
        })}
        <line
          x1={cx - Math.cos(angle) * 8}
          y1={cy - Math.sin(angle) * 8}
          x2={nx}
          y2={ny}
          stroke="var(--ink)"
          strokeWidth={2.4}
          strokeLinecap="round"
          style={{ filter: "drop-shadow(0 0 6px rgb(var(--ion-rgb) / 0.55))", transition: "all 900ms cubic-bezier(0.16,1,0.3,1)" }}
        />
        <circle cx={cx} cy={cy} r={7} fill="var(--surface)" stroke="rgb(var(--line-rgb) / 0.35)" strokeWidth={1} />
        <circle cx={cx} cy={cy} r={4} fill={`url(#pivot-${id})`} />
        <text x={cx - r} y={cy} dy="14" textAnchor="middle" fontSize="7.5" fill="var(--dim)" fontFamily="JetBrains Mono, monospace">0</text>
        <text x={cx + r} y={cy} dy="14" textAnchor="middle" fontSize="7.5" fill="var(--dim)" fontFamily="JetBrains Mono, monospace">100</text>
      </svg>
    </div>
  );
}

export function MetricCard({
  label,
  value,
  detail,
  icon,
  tone = "ion",
  gauge,
  badge,
  footer,
  footerLabel,
  className,
}: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  icon?: ReactNode;
  tone?: "ion" | "crit" | "high" | "med" | "low" | "violet";
  gauge?: number | null;
  badge?: ReactNode;
  footer?: ReactNode;
  footerLabel?: string;
  className?: string;
}) {
  const accent: Record<string, string> = {
    ion: "#64d8ff",
    crit: "#ff4d5e",
    high: "#ff963d",
    med: "#ffd166",
    low: "#42c98a",
    violet: "#9a8cff",
  };
  const chip: Record<string, string> = {
    ion: "text-ion border-ion/25 bg-ion/[0.07]",
    crit: "text-crit border-crit/25 bg-crit/[0.07]",
    high: "text-high border-high/25 bg-high/[0.07]",
    med: "text-med border-med/25 bg-med/[0.07]",
    low: "text-low border-low/25 bg-low/[0.07]",
    violet: "text-violet border-violet/25 bg-violet/[0.07]",
  };
  return (
    <div className={clsx("metric-card group flex flex-col p-4", className)}>
      <span className="metric-sheen" aria-hidden="true" />
      <div className="relative flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-start gap-1.5 text-[12.5px] font-medium leading-[1.4] tracking-[-0.005em] text-mist">
            <span className="mt-[5px] h-1 w-1 shrink-0 rounded-full" style={{ background: accent[tone] }} />
            <span className="min-w-0">{label}</span>
          </div>
          <div className="mt-2.5 flex items-end gap-2">
            <span className="tnum font-display text-[36px] font-semibold leading-none tracking-[-0.03em] text-ink">{value}</span>
          </div>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-2">
          {icon && (
            <span className={clsx("grid h-8 w-8 place-items-center rounded-[10px] border", chip[tone])}>{icon}</span>
          )}
          {badge}
        </div>
      </div>
      {typeof gauge === "number" && (
        <div className="relative mt-3">
          <ProgressBar value={gauge} color={accent[tone]} height={3} />
        </div>
      )}
      {detail && (
        <div className={clsx("relative mt-2.5 pb-1 text-[10.5px] leading-relaxed text-dim", !footer && "border-t border-veil/[0.055] pt-2")}>
          {detail}
        </div>
      )}
      {footer && (
        <div className="metric-action relative">
          <span className="inline-flex items-center gap-1.5 truncate">{footerLabel || footer}</span>
          <ArrowRight size={12} />
        </div>
      )}
      <span
        className="pointer-events-none absolute -bottom-12 -right-8 h-24 w-24 rounded-full opacity-[0.12] blur-2xl transition-opacity duration-300 group-hover:opacity-20"
        style={{ background: accent[tone] }}
        aria-hidden="true"
      />
    </div>
  );
}

export function DefinitionList({ rows, className }: { rows: Array<{ label: string; value: ReactNode }>; className?: string }) {
  return (
    <dl className={clsx("divide-y divide-veil/[0.05]", className)}>
      {rows.map((row) => (
        <div key={row.label} className="grid grid-cols-[140px_1fr] gap-4 py-2.5 max-sm:grid-cols-1 max-sm:gap-1">
          <dt className="font-mono text-[9px] uppercase tracking-[0.12em] text-dim">{row.label}</dt>
          <dd className="min-w-0 break-words text-[12px] leading-relaxed text-ink">{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function RiskMeter({ score, size = 66, label = true }: { score?: number | null; size?: number; label?: boolean }) {
  const value = typeof score === "number" ? Math.max(0, Math.min(100, score)) : 0;
  const radius = size / 2 - 5;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (value / 100) * circumference;
  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }} title={`Risk score ${value.toFixed(1)} of 100`}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgb(var(--line-rgb) / 0.28)" strokeWidth="3.5" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={riskColor(value)}
          strokeWidth="3.5"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 700ms cubic-bezier(0.16,1,0.3,1)" }}
        />
      </svg>
      {label && (
        <div className="absolute text-center">
          <div className="tnum font-display text-[16px] font-semibold leading-none text-ink">{value.toFixed(0)}</div>
          <div className="font-mono text-[7px] uppercase tracking-[0.14em] text-dim">risk</div>
        </div>
      )}
    </div>
  );
}

export function ProgressBar({ value, color, height = 4 }: { value: number; color?: string; height?: number }) {
  return (
    <div className="w-full overflow-hidden rounded-full bg-veil/[0.06]" style={{ height }}>
      <div
        className="h-full rounded-full transition-all duration-700"
        style={{ width: `${Math.max(2, Math.min(100, value))}%`, background: color || "#64d8ff" }}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* States                                                              */
/* ------------------------------------------------------------------ */

export function Skeleton({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return <div className={clsx("animate-pulse rounded-md bg-veil/[0.055]", className)} style={style} />;
}

export function LoadingBlock({ rows = 5, label = "Loading telemetry" }: { rows?: number; label?: string }) {
  return (
    <div className="flex flex-col gap-2 p-4" role="status" aria-label={label}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-4">
          <Skeleton className="h-8 w-8 rounded-lg" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-2.5" style={{ width: `${50 + ((i * 13) % 40)}%` }} />
            <Skeleton className="h-2 w-[28%]" />
          </div>
          <Skeleton className="h-4 w-14" />
        </div>
      ))}
      <span className="sr-only">{label}</span>
    </div>
  );
}

export function EmptyState({
  title = "No records match this view",
  detail,
  icon,
  action,
}: {
  title?: string;
  detail?: string;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
      <div className="mb-4 grid h-12 w-12 place-items-center rounded-xl border border-line bg-veil/[0.02] text-dim">
        {icon || <Search size={20} />}
      </div>
      <h3 className="font-display text-base font-medium text-ink">{title}</h3>
      {detail && <p className="mt-2 max-w-[46ch] text-[12px] leading-relaxed text-mist">{detail}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function ErrorState({ message, retry, compact = false }: { message?: string; retry?: () => void; compact?: boolean }) {
  return (
    <div className={clsx("flex flex-col items-center justify-center text-center", compact ? "px-5 py-10" : "px-6 py-16")} role="alert">
      <div className="mb-4 grid h-11 w-11 place-items-center rounded-xl border border-crit/25 bg-crit/[0.06] text-crit">
        <AlertTriangle size={19} />
      </div>
      <h3 className="font-display text-base font-medium text-ink">The data could not be loaded</h3>
      <p className="mt-2 max-w-[52ch] text-[12px] leading-relaxed text-mist">
        {message || "The API did not respond as expected. This surface shows the failure rather than a cached or partial result."}
      </p>
      {retry && (
        <button className="btn btn-ghost btn-sm mt-5" onClick={retry}>
          Retry request
        </button>
      )}
    </div>
  );
}

export function InlineNotice({
  tone = "ion",
  title,
  children,
  className,
}: {
  tone?: "ion" | "med" | "crit" | "violet" | "low";
  title?: string;
  children: ReactNode;
  className?: string;
}) {
  const tones = {
    ion: "border-ion/20 bg-ion/[0.045] text-ion",
    med: "border-med/20 bg-med/[0.05] text-med",
    crit: "border-crit/25 bg-crit/[0.05] text-crit",
    violet: "border-violet/25 bg-violet/[0.05] text-violet",
    low: "border-low/20 bg-low/[0.045] text-low",
  };
  return (
    <div className={clsx("rounded-lg border px-3.5 py-3", tones[tone], className)}>
      <div className="flex gap-2.5">
        <Info size={14} className="mt-0.5 shrink-0" />
        <div className="min-w-0">
          {title && <div className="mb-1 font-mono text-[9px] uppercase tracking-[0.14em]">{title}</div>}
          <div className="text-[11.5px] leading-relaxed text-mist">{children}</div>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Controls                                                            */
/* ------------------------------------------------------------------ */

export function SearchField({
  value,
  onChange,
  placeholder = "Search records",
  className,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
}) {
  const [local, setLocal] = useState(value);
  useEffect(() => setLocal(value), [value]);
  useEffect(() => {
    const timer = setTimeout(() => {
      if (local !== value) onChange(local);
    }, 280);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [local]);
  return (
    <div className={clsx("relative", className)}>
      <Search size={13} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-dim" />
      <input
        className="field pl-8"
        value={local}
        onChange={(event) => setLocal(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter") onChange(local);
        }}
        placeholder={placeholder}
        aria-label={placeholder}
      />
      {local && (
        <button
          className="absolute right-2 top-1/2 grid h-6 w-6 -translate-y-1/2 place-items-center rounded text-dim hover:text-ink"
          onClick={() => {
            setLocal("");
            onChange("");
          }}
          aria-label="Clear search"
        >
          <X size={12} />
        </button>
      )}
    </div>
  );
}

export function RangeTabs({
  value,
  onChange,
  options = [
    { value: "24h", label: "24H" },
    { value: "7d", label: "7D" },
    { value: "30d", label: "30D" },
    { value: "90d", label: "90D" },
  ],
  className,
}: {
  value: string;
  onChange: (value: string) => void;
  options?: Array<{ value: string; label: string }>;
  className?: string;
}) {
  return (
    <div className={clsx("inline-flex items-center rounded-lg border border-line bg-shade/20 p-0.5", className)} role="group" aria-label="Time range">
      {options.map((opt) => (
        <button
          key={opt.value}
          onClick={() => onChange(opt.value)}
          aria-pressed={value === opt.value}
          className={clsx(
            "h-[29px] rounded-[6px] px-2.5 font-mono text-[9px] tracking-[0.1em] transition-colors",
            value === opt.value ? "bg-ion/15 text-ink shadow-[inset_0_0_0_1px_rgb(var(--ion-rgb)/0.45)]" : "text-dim hover:text-ink",
          )}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

export function Tabs({
  tabs,
  value,
  onChange,
  className,
}: {
  tabs: Array<{ value: string; label: string; count?: number }>;
  value: string;
  onChange: (value: string) => void;
  className?: string;
}) {
  return (
    <div className={clsx("flex flex-wrap gap-1 border-b border-line", className)} role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.value}
          role="tab"
          aria-selected={value === tab.value}
          onClick={() => onChange(tab.value)}
          className={clsx(
            "relative px-3 pb-2.5 pt-1 text-[11.5px] transition-colors",
            value === tab.value ? "text-ink" : "text-dim hover:text-mist",
          )}
        >
          {tab.label}
          {typeof tab.count === "number" && <span className="ml-1.5 font-mono text-[9px] text-dim">{tab.count}</span>}
          {value === tab.value && <span className="absolute inset-x-2 -bottom-px h-[1.5px] bg-ion" />}
        </button>
      ))}
    </div>
  );
}

export function Toggle({ checked, onChange, label, disabled }: { checked: boolean; onChange: (next: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={clsx(
        "relative h-[22px] w-[38px] shrink-0 rounded-full border transition-colors disabled:opacity-40",
        checked ? "border-ion/50 bg-ion/25" : "border-line bg-veil/[0.04]",
      )}
    >
      <span
        className={clsx(
          "absolute top-[3px] h-[14px] w-[14px] rounded-full transition-all",
          checked ? "left-[19px] bg-ion shadow-[0_0_10px_rgba(100, 216, 255,0.55)]" : "left-[3px] bg-dim",
        )}
      />
    </button>
  );
}

export function Pagination({ page, pages, total, onPage }: { page: number; pages: number; total: number; onPage: (page: number) => void }) {
  return (
    <div className="flex items-center justify-between gap-3 border-t border-line px-4 py-2.5">
      <span className="font-mono text-[9px] uppercase tracking-[0.12em] text-dim">
        {fmtNumber(total)} records · page {page} / {Math.max(1, pages)}
      </span>
      <div className="flex items-center gap-1">
        <button className="btn btn-quiet btn-icon btn-sm" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page">
          <ChevronLeft size={14} />
        </button>
        <button className="btn btn-quiet btn-icon btn-sm" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page">
          <ChevronRight size={14} />
        </button>
      </div>
    </div>
  );
}

export function InfoTip({ text, children }: { text: string; children?: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <span
      className="relative inline-flex"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      <button type="button" className="text-dim transition-colors hover:text-ion" aria-label={text} onClick={() => setOpen((v) => !v)}>
        {children || <Info size={12} />}
      </button>
      <AnimatePresence>
        {open && (
          <motion.span
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 2 }}
            className="absolute bottom-full left-1/2 z-40 mb-2 w-56 -translate-x-1/2 rounded-lg border border-line-strong bg-surface px-3 py-2 text-left text-[10.5px] font-normal leading-relaxed text-mist shadow-lift"
            role="tooltip"
          >
            {text}
          </motion.span>
        )}
      </AnimatePresence>
    </span>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="btn btn-quiet btn-sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1600);
        } catch {
          /* clipboard may be blocked; the user can select the value */
        }
      }}
      aria-label={`${label} ${value}`}
    >
      {copied ? <Check size={12} /> : <ClipboardCopy size={12} />}
      {copied ? "Copied" : label}
    </button>
  );
}

/* ------------------------------------------------------------------ */
/* Overlays                                                            */
/* ------------------------------------------------------------------ */

function Overlay({
  open,
  onClose,
  children,
  panelClass,
  labelledBy,
  variant,
}: {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  panelClass?: string;
  labelledBy?: string;
  variant: "modal" | "drawer";
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
      if (event.key === "Tab" && panelRef.current) {
        const nodes = panelRef.current.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        );
        if (!nodes.length) return;
        const first = nodes[0];
        const last = nodes[nodes.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    const timer = setTimeout(() => {
      const focusable = panelRef.current?.querySelector<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      (focusable || panelRef.current)?.focus();
    }, 30);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = overflow;
      clearTimeout(timer);
      previous?.focus();
    };
  }, [open, onClose]);

  return createPortal(
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-[80]" role="presentation">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.18 }}
            className="absolute inset-0 bg-sunken/75 backdrop-blur-[3px]"
            onClick={onClose}
          />
          {variant === "modal" ? (
            <div className="absolute inset-0 grid place-items-center overflow-y-auto p-4">
              <motion.div
                ref={panelRef}
                tabIndex={-1}
                role="dialog"
                aria-modal="true"
                aria-labelledby={labelledBy}
                initial={{ opacity: 0, y: 18, scale: 0.985 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 10, scale: 0.99 }}
                transition={{ duration: 0.26, ease: [0.16, 1, 0.3, 1] }}
                className={clsx(
                  "relative max-h-[86vh] w-[min(560px,calc(100vw-32px))] overflow-y-auto rounded-2xl border border-line-strong bg-surface shadow-lift outline-none",
                  panelClass,
                )}
              >
                {children}
              </motion.div>
            </div>
          ) : (
            <motion.div
              ref={panelRef}
              tabIndex={-1}
              role="dialog"
              aria-modal="true"
              aria-labelledby={labelledBy}
              initial={{ x: "100%" }}
              animate={{ x: 0 }}
              exit={{ x: "100%" }}
              transition={{ duration: 0.26, ease: [0.16, 1, 0.3, 1] }}
              className={clsx(
                "absolute bottom-2 right-2 top-2 flex w-[calc(100%-16px)] flex-col overflow-hidden rounded-[22px] border border-line-strong bg-surface shadow-[0_40px_110px_-40px_rgba(0,0,0,0.95)] outline-none",
                panelClass,
              )}
            >
              {children}
            </motion.div>
          )}
        </div>
      )}
    </AnimatePresence>,
    document.body,
  );
}

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  labelledBy,
  className,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  labelledBy?: string;
  className?: string;
}) {
  const autoId = useId();
  const titleId = labelledBy || `modal-${autoId}`;
  return (
    <Overlay open={open} onClose={onClose} labelledBy={titleId} variant="modal" panelClass={className}>
      <div className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
        <div>
          <h2 id={titleId} className="font-display text-[17px] font-semibold text-ink">{title}</h2>
          {description && <p className="mt-1 max-w-[46ch] text-[11.5px] leading-relaxed text-mist">{description}</p>}
        </div>
        <button className="btn btn-quiet btn-icon" onClick={onClose} aria-label="Close dialog">
          <X size={16} />
        </button>
      </div>
      <div className="px-5 py-4">{children}</div>
      {footer && <div className="flex items-center justify-end gap-2 border-t border-line px-5 py-3.5">{footer}</div>}
    </Overlay>
  );
}

export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
  width,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  const id = useId();
  return (
    <Overlay open={open} onClose={onClose} labelledBy={`drawer-${id}`} variant="drawer" panelClass={width || "max-w-[620px]"}>
      <div className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
        <div className="min-w-0">
          <div id={`drawer-${id}`} className="min-w-0">{title}</div>
          {subtitle && <div className="mt-1.5">{subtitle}</div>}
        </div>
        <button className="btn btn-quiet btn-icon shrink-0" onClick={onClose} aria-label="Close panel">
          <X size={16} />
        </button>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-5">{children}</div>
      {footer && <div className="flex flex-wrap items-center justify-end gap-2 border-t border-line px-5 py-3.5">{footer}</div>}
    </Overlay>
  );
}

export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  body,
  confirmLabel = "Confirm",
  danger = false,
  busy = false,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  body: string;
  confirmLabel?: string;
  danger?: boolean;
  busy?: boolean;
}) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      footer={
        <>
          <button className="btn btn-ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button className={clsx("btn", danger ? "btn-danger" : "btn-primary")} onClick={onConfirm} disabled={busy}>
            {busy && <Loader2 size={13} className="animate-spin" />}
            {confirmLabel}
          </button>
        </>
      }
    >
      <p className="text-[12px] leading-relaxed text-mist">{body}</p>
    </Modal>
  );
}

/* ------------------------------------------------------------------ */
/* Toasts                                                              */
/* ------------------------------------------------------------------ */

type Toast = { id: number; tone: "success" | "error" | "info"; message: string };
const ToastContext = createContext<{ push: (tone: Toast["tone"], message: string) => void }>({ push: () => {} });

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((tone: Toast["tone"], message: string) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev.slice(-3), { id, tone, message }]);
    setTimeout(() => setToasts((prev) => prev.filter((toast) => toast.id !== id)), 4800);
  }, []);
  const value = useMemo(() => ({ push }), [push]);
  return (
    <ToastContext.Provider value={value}>
      {children}
      {createPortal(
        <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[min(360px,calc(100vw-32px))] flex-col gap-2" aria-live="polite">
          <AnimatePresence>
            {toasts.map((toast) => (
              <motion.div
                key={toast.id}
                initial={{ opacity: 0, y: 12, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 6, scale: 0.98 }}
                transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
                className={clsx(
                  "pointer-events-auto flex items-start gap-2.5 rounded-lg border px-3.5 py-3 text-[11.5px] leading-relaxed shadow-lift backdrop-blur-md",
                  toast.tone === "error"
                    ? "border-crit/30 bg-crit/10 text-crit"
                    : toast.tone === "success"
                      ? "border-low/30 bg-surface/95 text-crystal"
                      : "border-ion/25 bg-surface/95 text-crystal",
                )}
              >
                {toast.tone === "error" ? (
                  <XCircle size={15} className="mt-0.5 shrink-0 text-crit" />
                ) : toast.tone === "success" ? (
                  <CheckCircle2 size={15} className="mt-0.5 shrink-0 text-low" />
                ) : (
                  <Info size={15} className="mt-0.5 shrink-0 text-ion" />
                )}
                <span>{toast.message}</span>
                <button className="ml-auto text-dim hover:text-ink" onClick={() => setToasts((prev) => prev.filter((t) => t.id !== toast.id))} aria-label="Dismiss notification">
                  <X size={12} />
                </button>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>,
        document.body,
      )}
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}

/* ------------------------------------------------------------------ */
/* Access control                                                      */
/* ------------------------------------------------------------------ */

export function ReadOnlyHint({ role }: { role: string }) {
  if (role !== "viewer") return null;
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md border border-veil/10 bg-veil/[0.03] px-2 py-1 font-mono text-[9px] uppercase tracking-[0.1em] text-dim">
      <ShieldAlert size={11} /> Read-only access
    </span>
  );
}

export function InlineLink({ children, onClick }: { children: ReactNode; onClick?: () => void }) {
  return (
    <button onClick={onClick} className="inline-flex items-center gap-1 text-ion hover:text-crystal">
      {children} <ArrowRight size={11} />
    </button>
  );
}
