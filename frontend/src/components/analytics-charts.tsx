import { useEffect, useMemo, useRef, useState } from "react";
import clsx from "clsx";
import { heatInk, palette, tone } from "../lib/theme";

/* ------------------------------------------------------------------ */
/* Shared helpers                                                      */
/* ------------------------------------------------------------------ */

const GRID = "var(--chart-grid)";
const AXIS = "var(--chart-axis)";
const MONO = "JetBrains Mono, monospace";

/** A fixed viewBox letterboxes the plot and shrinks its type whenever the card is wider
    than the reference ratio, so charts measure their own box and draw one-to-one. */
export function useChartBox(fallbackW: number, fallbackH: number) {
  const ref = useRef<HTMLDivElement | null>(null);
  const [box, setBox] = useState({ w: fallbackW, h: fallbackH });
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const measure = () => {
      const rect = el.getBoundingClientRect();
      const w = Math.round(rect.width);
      const h = Math.round(rect.height);
      if (w < 200 || h < 40) return;
      setBox((prev) => (Math.abs(prev.w - w) <= 1 && Math.abs(prev.h - h) <= 1 ? prev : { w, h }));
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);
  return [ref, box] as const;
}

export const RISK_HEX: Record<string, string> = {
  get Critical() {
    return palette().crit;
  },
  get High() {
    return palette().high;
  },
  get Medium() {
    return palette().med;
  },
  get Low() {
    return palette().low;
  },
};

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}

function short(value: string, length: number) {
  return value.length > length ? `${value.slice(0, length - 1)}…` : value;
}

/** Corner tags are drawn inside the plot, so they carry a plate instead of losing to a dense cluster. */
function QuadrantTag({ text, x, y, anchor, color }: { text: string; x: number; y: number; anchor: "start" | "end"; color: string }) {
  if (!text) return null;
  const label = text.toUpperCase();
  const width = label.length * 5.6 + 10;
  const left = anchor === "end" ? x - width : x;
  return (
    <g pointerEvents="none">
      <rect x={left} y={y - 8.5} width={width} height={12} rx="2.5" fill="var(--tooltip)" fillOpacity="0.92" stroke="var(--line)" />
      <text x={anchor === "end" ? x - 5 : x + 5} y={y} textAnchor={anchor} fill={color} fontSize="7.5" fontFamily={MONO} letterSpacing="1">
        {label}
      </text>
    </g>
  );
}

function withAlpha(color: string, alpha: number) {
  const hex = color.replace("#", "");
  if (hex.length === 3) {
    const [r, g, b] = hex.split("").map((char) => parseInt(char + char, 16));
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }
  if (hex.length === 6) {
    const r = parseInt(hex.slice(0, 2), 16);
    const g = parseInt(hex.slice(2, 4), 16);
    const b = parseInt(hex.slice(4, 6), 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }
  return color;
}

function niceTicks(min: number, max: number, count = 4) {
  if (max === min) return [min];
  const step = (max - min) / count;
  return Array.from({ length: count + 1 }, (_, index) => min + step * index);
}

/* ------------------------------------------------------------------ */
/* Treemap                                                             */
/* ------------------------------------------------------------------ */

export interface TreemapItem {
  name: string;
  value: number;
  color?: string;
  detail?: string;
  meta?: string;
}

interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

function binaryTreemap(items: TreemapItem[], rect: Rect, out: Array<Rect & { item: TreemapItem }>) {
  if (!items.length) return;
  if (items.length === 1) {
    out.push({ ...rect, item: items[0] });
    return;
  }
  const total = items.reduce((sum, item) => sum + item.value, 0) || 1;
  let running = 0;
  let split = 1;
  for (let i = 0; i < items.length - 1; i += 1) {
    running += items[i].value;
    if (running / total >= 0.5) {
      split = i + 1;
      break;
    }
  }
  const first = items.slice(0, split);
  const second = items.slice(split);
  const firstTotal = first.reduce((sum, item) => sum + item.value, 0);
  const ratio = firstTotal / total;
  if (rect.w >= rect.h) {
    const w = rect.w * ratio;
    binaryTreemap(first, { ...rect, w }, out);
    binaryTreemap(second, { x: rect.x + w, y: rect.y, w: rect.w - w, h: rect.h }, out);
  } else {
    const h = rect.h * ratio;
    binaryTreemap(first, { ...rect, h }, out);
    binaryTreemap(second, { x: rect.x, y: rect.y + h, w: rect.w, h: rect.h - h }, out);
  }
}

export function Treemap({
  items,
  height = 260,
  onSelect,
  emptyLabel = "No records to weight.",
}: {
  items: TreemapItem[];
  height?: number;
  onSelect?: (item: TreemapItem) => void;
  emptyLabel?: string;
}) {
  const [hover, setHover] = useState<string | null>(null);
  /* "none" used to stretch a 640-unit layout into any card, which pulled tile labels
     sideways by up to 21%. Tiles now fill the box they are actually in. */
  const [boxRef, box] = useChartBox(640, height);
  const W = box.w;
  const H = box.h;
  const rects = useMemo(() => {
    const sorted = [...items].filter((item) => item.value > 0).sort((a, b) => b.value - a.value);
    const out: Array<Rect & { item: TreemapItem }> = [];
    binaryTreemap(sorted, { x: 0, y: 0, w: W, h: H }, out);
    return out;
  }, [items, W, H]);

  if (!items.length || !rects.length) {
    return <div className="py-14 text-center text-[11px] text-dim">{emptyLabel}</div>;
  }

  return (
    <div ref={boxRef} style={{ height }} className="w-full">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full" role="img" aria-label="Weighted treemap">
        <defs>
          {rects.map((rect, index) => {
            const hue = tone(rect.item.color || palette().pulse);
            const active = hover === rect.item.name;
            return (
              <linearGradient key={`grad-${index}`} id={`treemap-${index}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={hue} stopOpacity={active ? 0.26 : 0.15} />
                <stop offset="58%" stopColor={withAlpha(hue, 0.055)} />
                <stop offset="100%" stopColor="var(--chart-surface)" stopOpacity="0.92" />
              </linearGradient>
            );
          })}
        </defs>
        {rects.map((rect, index) => {
          const item = rect.item;
          const color = tone(item.color || palette().pulse);
          const active = hover === item.name;
          const showLabel = rect.w > 76 && rect.h > 34;
          return (
            <g
              key={`${item.name}-${index}`}
              onMouseEnter={() => setHover(item.name)}
              onMouseLeave={() => setHover(null)}
              onClick={() => onSelect?.(item)}
              className={onSelect ? "cursor-pointer" : undefined}
              opacity={hover && !active ? 0.55 : 1}
            >
              <rect
                x={rect.x + 1}
                y={rect.y + 1}
                width={Math.max(0, rect.w - 2)}
                height={Math.max(0, rect.h - 2)}
                rx="3"
                fill={`url(#treemap-${index})`}
                stroke={withAlpha(color, active ? 0.85 : 0.4)}
                strokeWidth="0.8"
              />
              <rect
                x={rect.x + 1}
                y={rect.y + 1}
                width={Math.max(0, rect.w - 2)}
                height="1.6"
                fill={color}
                opacity={active ? 0.95 : 0.72}
              />
              {showLabel && (
                <text x={rect.x + 7} y={rect.y + 16} fill="var(--chart-plot-ink)" fontSize="9.5" fontFamily={MONO}>
                  {short(item.name, Math.max(4, Math.floor((rect.w - 14) / 5.9)))}
                </text>
              )}
              {showLabel && (
                <text x={rect.x + 7} y={rect.y + 28} fill="var(--chart-plot-mist)" fontSize="8" fontFamily={MONO}>
                  {item.meta || item.value}
                </text>
              )}
              <title>{`${item.name}: ${item.detail || item.value}`}</title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Scatter plot                                                        */
/* ------------------------------------------------------------------ */

export interface ScatterPoint {
  id?: string | number;
  group?: string | number;
  x: number;
  y: number;
  size?: number;
  color?: string;
  label?: string;
  detail?: string;
  lines?: string[];
}

export function ScatterPlot({
  points,
  height = 300,
  xLabel,
  yLabel,
  xMax,
  yMax,
  xMin = 0,
  yMin = 0,
  quadrants,
  showIdentity = false,
  emptyLabel = "No plotted records.",
  selected,
  onSelect,
  onHoverChange,
  dim,
  hint,
}: {
  points: ScatterPoint[];
  height?: number;
  xLabel: string;
  yLabel: string;
  xMax?: number;
  yMax?: number;
  xMin?: number;
  yMin?: number;
  quadrants?: [string, string, string, string];
  showIdentity?: boolean;
  emptyLabel?: string;
  selected?: string | number | null;
  onSelect?: (point: ScatterPoint, index: number) => void;
  onHoverChange?: (point: ScatterPoint | null) => void;
  dim?: (point: ScatterPoint) => boolean;
  hint?: string;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const [boxRef, box] = useChartBox(640, height);
  const W = box.w;
  const H = box.h;
  const pad = { left: 46, right: 16, top: 18, bottom: 40 };
  const maxX = xMax ?? Math.max(1, ...points.map((point) => point.x));
  const maxY = yMax ?? Math.max(1, ...points.map((point) => point.y));
  const px = (value: number) => pad.left + (clamp(value, xMin, maxX) - xMin) / (maxX - xMin || 1) * (W - pad.left - pad.right);
  const py = (value: number) => H - pad.bottom - (clamp(value, yMin, maxY) - yMin) / (maxY - yMin || 1) * (H - pad.top - pad.bottom);

  if (!points.length) {
    return <div className="py-14 text-center text-[11px] text-dim">{emptyLabel}</div>;
  }

  const isSelected = (point: ScatterPoint) => selected != null && point.id === selected;
  // Dimmed points paint first so the focused record always sits on top of the field.
  const order = points.map((_, index) => index).sort((a, b) => Number(Boolean(dim?.(points[a]))) - Number(Boolean(dim?.(points[b]))));
  const activePoint = hover != null ? points[hover] : null;
  const tipLines = (point: ScatterPoint) => (point.lines?.length ? point.lines : [`${xLabel} ${point.x} · ${yLabel} ${point.y}`]);
  const tipWidth = 208;

  const setActive = (index: number | null) => {
    setHover(index);
    onHoverChange?.(index == null ? null : points[index]);
  };

  return (
    <div ref={boxRef} style={{ height }} className="w-full">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" className="h-full w-full" role="img" aria-label={`${yLabel} by ${xLabel}`}>
        {quadrants && (
          <>
            <rect x={pad.left} y={pad.top} width={(W - pad.left - pad.right) / 2} height={(H - pad.top - pad.bottom) / 2} fill="var(--veil)" fillOpacity="0.02" />
            <rect x={W / 2 + (pad.left - pad.right) / 2} y={H / 2 + (pad.top - pad.bottom) / 2} width={(W - pad.left - pad.right) / 2} height={(H - pad.top - pad.bottom) / 2} fill="var(--ion)" fillOpacity="0.05" />
          </>
        )}
        {niceTicks(yMin, maxY, 4).map((tick) => (
          <g key={`y${tick}`}>
            <line x1={pad.left} x2={W - pad.right} y1={py(tick)} y2={py(tick)} stroke={GRID} strokeWidth="0.7" />
            <text x={pad.left - 8} y={py(tick) + 3} textAnchor="end" fill={AXIS} fontSize="8" fontFamily={MONO}>
              {Math.abs(tick) >= 100 ? Math.round(tick) : tick.toFixed(1).replace(/\.0$/, "")}
            </text>
          </g>
        ))}
        {niceTicks(xMin, maxX, 4).map((tick) => (
          <g key={`x${tick}`}>
            <line x1={px(tick)} x2={px(tick)} y1={pad.top} y2={H - pad.bottom} stroke={GRID} strokeWidth="0.7" />
            <text x={px(tick)} y={H - pad.bottom + 14} textAnchor="middle" fill={AXIS} fontSize="8" fontFamily={MONO}>
              {Math.abs(tick) >= 100 ? Math.round(tick) : tick.toFixed(1).replace(/\.0$/, "")}
            </text>
          </g>
        ))}
        {showIdentity && <line x1={px(xMin)} y1={py(yMin)} x2={px(maxX)} y2={py(maxY)} stroke="var(--violet)" strokeOpacity="0.45" strokeDasharray="3 3" strokeWidth="1" />}
        <text x={(W + pad.left - pad.right) / 2} y={H - 8} textAnchor="middle" fill={AXIS} fontSize="8.5" fontFamily={MONO} letterSpacing="1.4">
          {xLabel.toUpperCase()}
        </text>
        <text x={12} y={pad.top + (H - pad.top - pad.bottom) / 2} textAnchor="middle" fill={AXIS} fontSize="8.5" fontFamily={MONO} letterSpacing="1.4" transform={`rotate(-90 12 ${pad.top + (H - pad.top - pad.bottom) / 2})`}>
          {yLabel.toUpperCase()}
        </text>
        {order.map((index) => {
          const point = points[index];
          const active = hover === index;
          const picked = isSelected(point);
          const faded = Boolean(dim?.(point));
          const radius = clamp(point.size ?? 4, 2.5, 12);
          const colour = tone(point.color || palette().pulse);
          const action = onSelect ? "Press Enter to inspect this record." : "";
          return (
            <g
              key={`${point.label || "point"}-${index}`}
              onMouseEnter={() => setActive(index)}
              onMouseLeave={() => setActive(null)}
              onFocus={() => setActive(index)}
              onBlur={() => setActive(null)}
              onClick={() => onSelect?.(point, index)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelect?.(point, index);
                }
              }}
              tabIndex={onSelect ? 0 : undefined}
              role={onSelect ? "button" : undefined}
              aria-label={`${point.label || "record"}. ${tipLines(point).join(". ")}${action}`}
              className={clsx("outline-none", onSelect && "cursor-pointer")}
              style={{ opacity: faded ? 0.18 : 1, transition: "opacity 160ms ease" }}
            >
              {picked && (
                <circle cx={px(point.x)} cy={py(point.y)} r={radius + 5} fill={colour} fillOpacity="0.12" stroke={colour} strokeOpacity="0.9" strokeWidth="1.2" className="transition-all duration-150" />
              )}
              <circle
                cx={px(point.x)}
                cy={py(point.y)}
                r={radius + (active ? 3 : 0)}
                fill={colour}
                fillOpacity={picked ? 1 : active ? 0.95 : 0.55}
                stroke={colour}
                strokeOpacity={picked || active ? 1 : 0.6}
                strokeWidth={picked ? 1.6 : 0.8}
                className="transition-all duration-150"
                style={{ filter: active || picked ? "drop-shadow(0 0 6px rgba(100,216,255,0.55))" : undefined }}
              />
              <title>{`${point.label || "record"} · ${xLabel} ${point.x} · ${yLabel} ${point.y}${point.detail ? ` · ${point.detail}` : ""}`}</title>
            </g>
          );
        })}
        {/* Tags paint above the field so a corner bubble cannot bury the quadrant name. */}
        {quadrants && (
          <>
            <QuadrantTag text={quadrants[0]} x={W - pad.right - 6} y={pad.top + 12} anchor="end" color="var(--ion)" />
            <QuadrantTag text={quadrants[3]} x={pad.left + 6} y={H - pad.bottom - 6} anchor="start" color="var(--chart-axis)" />
          </>
        )}
        {activePoint && (
          <g pointerEvents="none">
            <rect
              x={clamp(px(activePoint.x) + 12, pad.left, W - tipWidth - pad.right)}
              y={clamp(py(activePoint.y) - 16 - tipLines(activePoint).length * 10, pad.top, H - pad.bottom - 20 - tipLines(activePoint).length * 10)}
              width={tipWidth}
              height={20 + tipLines(activePoint).length * 10}
              rx="4"
              fill="var(--tooltip)" fillOpacity="0.96"
              stroke="var(--line-strong)"
            />
            <text
              x={clamp(px(activePoint.x) + 20, pad.left + 8, W - tipWidth - pad.right + 8)}
              y={clamp(py(activePoint.y) - 16 - tipLines(activePoint).length * 10, pad.top, H - pad.bottom - 20 - tipLines(activePoint).length * 10) + 13}
              fill="var(--chart-plot-ink)" fontSize="8.5" fontFamily={MONO}
            >
              {short(activePoint.label || "record", 30)}
            </text>
            {tipLines(activePoint).map((line, lineIndex) => (
              <text
                key={line}
                x={clamp(px(activePoint.x) + 20, pad.left + 8, W - tipWidth - pad.right + 8)}
                y={clamp(py(activePoint.y) - 16 - tipLines(activePoint).length * 10, pad.top, H - pad.bottom - 20 - tipLines(activePoint).length * 10) + 24 + lineIndex * 10}
                fill="var(--chart-plot-mist)" fontSize="7.5" fontFamily={MONO}
              >
                {short(line, 40)}
              </text>
            ))}
          </g>
        )}
        {hint && (
          <text x={W - pad.right} y={pad.top - 6} textAnchor="end" fill="var(--chart-axis)" fontSize="7" fontFamily={MONO} letterSpacing="1">
            {hint.toUpperCase()}
          </text>
        )}
      </svg>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Radar                                                               */
/* ------------------------------------------------------------------ */

export interface RadarAxis {
  label: string;
  value: number;
}

export function RadarChart({
  axes,
  compare,
  height = 300,
  primaryLabel = "Current",
  compareLabel = "Previous",
  color = palette().ion,
  compareColor = palette().violet,
}: {
  axes: RadarAxis[];
  compare?: RadarAxis[];
  height?: number;
  primaryLabel?: string;
  compareLabel?: string;
  color?: string;
  compareColor?: string;
}) {
  /* A square viewBox inside a wide card letterboxed the web to 91% and left dead
     margins, so the plot is drawn against the space it actually has. */
  const [boxRef, box] = useChartBox(320, height);
  const span = Math.min(box.w, box.h);
  const center = span / 2;
  const radius = span * 0.34;
  if (axes.length < 3) {
    return <div className="py-14 text-center text-[11px] text-dim">At least three categories are required for a radar view.</div>;
  }
  const max = Math.max(1, ...axes.map((axis) => axis.value), ...(compare || []).map((axis) => axis.value));
  const angle = (index: number) => (Math.PI * 2 * index) / axes.length - Math.PI / 2;
  const point = (index: number, value: number) => {
    const r = (value / max) * radius;
    return [center + Math.cos(angle(index)) * r, center + Math.sin(angle(index)) * r] as const;
  };
  const path = (series: RadarAxis[]) =>
    series.map((axis, index) => `${index === 0 ? "M" : "L"} ${point(index, axis.value).join(" ")}`).join(" ") + " Z";

  return (
    <div ref={boxRef} style={{ height }} className="w-full">
      <svg viewBox={`0 0 ${box.w} ${box.h}`} className="h-full w-full" role="img" aria-label="Category radar comparison">
        <g transform={`translate(${(box.w - span) / 2}, ${(box.h - span) / 2})`}>
        {[0.25, 0.5, 0.75, 1].map((ring) => (
          <polygon
            key={ring}
            points={axes.map((_, index) => point(index, max * ring).join(",")).join(" ")}
            fill="none"
            stroke={GRID}
            strokeWidth="0.7"
          />
        ))}
        {axes.map((axis, index) => {
          const [x, y] = point(index, max);
          return <line key={axis.label} x1={center} y1={center} x2={x} y2={y} stroke={GRID} strokeWidth="0.6" />;
        })}
        {compare && <path d={path(compare)} fill={compareColor} fillOpacity="0.08" stroke={compareColor} strokeOpacity="0.55" strokeWidth="1" strokeDasharray="3 3" />}
        <path d={path(axes)} fill={color} fillOpacity="0.13" stroke={color} strokeWidth="1.4" />
        {axes.map((axis, index) => {
          const [x, y] = point(index, max * 1.16);
          const anchor = Math.abs(x - center) < 18 ? "middle" : x > center ? "start" : "end";
          return (
            <text key={`label-${axis.label}`} x={x} y={y} textAnchor={anchor} dominantBaseline="middle" fill="var(--mist)" fontSize="7.6" fontFamily={MONO}>
              {short(axis.label, 18).toUpperCase()}
            </text>
          );
        })}
        {axes.map((axis, index) => {
          const [x, y] = point(index, axis.value);
          return <circle key={`dot-${axis.label}`} cx={x} cy={y} r="2.6" fill={color} />;
        })}
        </g>
      </svg>
      <div className="mt-1 flex items-center justify-center gap-4 font-mono text-[8px] uppercase tracking-[0.12em] text-dim">
        <span className="inline-flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} /> {primaryLabel}</span>
        {compare && <span className="inline-flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full" style={{ background: compareColor }} /> {compareLabel}</span>}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Waterfall                                                           */
/* ------------------------------------------------------------------ */

export interface WaterfallItem {
  label: string;
  shortLabel?: string;
  value: number;
  color?: string;
  note?: string;
}

export function Waterfall({
  items,
  total,
  height = 260,
  unit = "pts",
  max,
  onSelect,
  selected,
}: {
  items: WaterfallItem[];
  total: number;
  height?: number;
  unit?: string;
  max?: number;
  onSelect?: (item: WaterfallItem, index: number) => void;
  selected?: number | null;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const [boxRef, box] = useChartBox(640, height);
  if (!items.length) return <div className="py-14 text-center text-[11px] text-dim">No factor contributions recorded.</div>;
  const W = box.w;
  const H = box.h;
  const pad = { left: 34, right: 14, top: 22, bottom: 58 };
  const top = max ?? Math.max(total, ...items.reduce<number[]>((acc, item) => {
    const previous = acc[acc.length - 1] || 0;
    acc.push(previous + item.value);
    return acc;
  }, [0]));
  const py = (value: number) => H - pad.bottom - (value / (top || 1)) * (H - pad.top - pad.bottom);
  const slot = (W - pad.left - pad.right) / (items.length + 1);
  let running = 0;
  const bars = items.map((item, index) => {
    const start = running;
    running += item.value;
    return { ...item, start, end: running, x: pad.left + slot * (index + 0.16), width: slot * 0.68 };
  });
  const activeBar = hover != null ? bars[hover] : null;

  return (
    <div ref={boxRef} style={{ height }} className="w-full">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" className="h-full w-full" role="img" aria-label="Risk contribution waterfall">
        {niceTicks(0, top, 4).map((tick) => (
          <g key={tick}>
            <line x1={pad.left} x2={W - pad.right} y1={py(tick)} y2={py(tick)} stroke={GRID} strokeWidth="0.6" />
            <text x={pad.left - 6} y={py(tick) + 3} textAnchor="end" fill={AXIS} fontSize="7.5" fontFamily={MONO}>{Math.round(tick)}</text>
          </g>
        ))}
        {bars.map((bar, index) => {
          const colour = tone(bar.color || palette().pulse);
          const isHover = hover === index;
          const isPicked = selected === index;
          return (
            <g
              key={bar.label}
              onMouseEnter={() => setHover(index)}
              onMouseLeave={() => setHover(null)}
              onFocus={() => setHover(index)}
              onBlur={() => setHover(null)}
              onClick={() => onSelect?.(bar, index)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelect?.(bar, index);
                }
              }}
              tabIndex={onSelect ? 0 : undefined}
              role={onSelect ? "button" : undefined}
              aria-label={`${bar.label}: ${bar.value.toFixed(1)} ${unit}${bar.note ? `. ${bar.note}` : ""}`}
              className={clsx("outline-none", onSelect && "cursor-pointer")}
              style={{ opacity: isHover || isPicked || hover == null ? 1 : 0.55, transition: "opacity 150ms ease" }}
            >
              <rect
                x={bar.x}
                y={py(bar.end)}
                width={bar.width}
                height={Math.max(1, py(bar.start) - py(bar.end))}
                fill={colour}
                fillOpacity={isHover || isPicked ? 0.55 : 0.32}
                stroke={colour}
                strokeOpacity={isHover || isPicked ? 1 : 0.75}
                strokeWidth={isHover || isPicked ? 1.4 : 0.8}
                rx="1.5"
              />
              <rect x={bar.x} y={py(bar.end)} width={bar.width} height="2" fill={colour} />
              <text x={bar.x + bar.width / 2} y={py(bar.end) - 5} textAnchor="middle" fill="var(--chart-plot-ink)" fontSize="8" fontFamily={MONO}>
                +{bar.value.toFixed(1)}
              </text>
              <text
                x={bar.x + bar.width / 2}
                y={H - pad.bottom + 11}
                textAnchor="end"
                transform={`rotate(-38 ${bar.x + bar.width / 2} ${H - pad.bottom + 11})`}
                fill={isHover || isPicked ? "var(--chart-plot-ink)" : "var(--chart-axis)"}
                fontSize="7.6"
                fontFamily={MONO}
              >
                {short(bar.shortLabel || bar.label, 22).toUpperCase()}
              </text>
              {index < bars.length - 1 && (
                <line x1={bar.x + bar.width} x2={bars[index + 1].x} y1={py(bar.end)} y2={py(bar.end)} stroke="var(--line-strong)" strokeDasharray="2 2" strokeWidth="0.7" />
              )}
            </g>
          );
        })}
        <rect
          x={pad.left + slot * (items.length + 0.16)}
          y={py(total)}
          width={slot * 0.68}
          height={Math.max(1, py(0) - py(total))}
          fill="var(--ion)" fillOpacity="0.14"
          stroke="var(--ion)"
          strokeWidth="1"
          rx="1.5"
        />
        <text x={pad.left + slot * (items.length + 0.5)} y={py(total) - 6} textAnchor="middle" fill="var(--ion)" fontSize="9" fontFamily={MONO}>
          {total.toFixed(1)}
        </text>
        <text x={pad.left + slot * (items.length + 0.5)} y={H - pad.bottom + 11} textAnchor="middle" fill="var(--mist)" fontSize="7.4" fontFamily={MONO}>TOTAL</text>
        <text x={pad.left} y={pad.top - 9} fill={AXIS} fontSize="7.5" fontFamily={MONO} letterSpacing="1">CONTRIBUTION · {unit.toUpperCase()}</text>
        {activeBar && (
          <g pointerEvents="none">
            <rect x={pad.left} y={4} width={W - pad.left - pad.right} height={14} rx="3" fill="var(--tooltip)" fillOpacity="0.96" stroke="var(--line-strong)" />
            <text x={pad.left + 6} y={14} fill="var(--chart-plot-ink)" fontSize="7.6" fontFamily={MONO}>
              {short(activeBar.label, 62)} · +{activeBar.value.toFixed(1)} {unit}
              {activeBar.note ? ` · ${short(activeBar.note, 52)}` : ""}
            </text>
          </g>
        )}
      </svg>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Priority matrix                                                     */
/* ------------------------------------------------------------------ */

export function PriorityMatrix({
  rows,
  cols,
  values,
  onSelect,
  height = 220,
  selected,
  unit = "assessments",
}: {
  rows: string[];
  cols: string[];
  values: number[][];
  onSelect?: (row: string, col: string) => void;
  height?: number;
  selected?: { row: number; col: number } | null;
  unit?: string;
}) {
  const max = Math.max(1, ...values.flat());
  return (
    <div className="overflow-x-auto" style={{ minHeight: height }}>
      <div className="min-w-[340px]">
        <div className="mb-1 grid gap-1" style={{ gridTemplateColumns: `64px repeat(${cols.length}, minmax(0, 1fr))` }}>
          <span />
          {cols.map((col) => (
            <span key={col} className="truncate text-center font-mono text-[7.5px] uppercase tracking-[0.08em] text-dim">{col}</span>
          ))}
        </div>
        {rows.map((row, rowIndex) => (
          <div key={row} className="mb-1 grid items-stretch gap-1" style={{ gridTemplateColumns: `64px repeat(${cols.length}, minmax(0, 1fr))` }}>
            <span className="flex items-center font-mono text-[8px] uppercase tracking-[0.08em] text-mist">{row}</span>
            {cols.map((col, colIndex) => {
              const value = values[rowIndex]?.[colIndex] ?? 0;
              const intensity = value ? 0.14 + (value / max) * 0.72 : 0;
              const isSelected = selected?.row === rowIndex && selected?.col === colIndex;
              return (
                <button
                  key={col}
                  type="button"
                  onClick={() => onSelect?.(row, col)}
                  aria-pressed={isSelected}
                  aria-label={`${row} and ${col}: ${value} ${unit}${onSelect ? ". Select to filter the charts and table to this combination." : ""}`}
                  className={clsx(
                    "relative grid place-items-center rounded-[3px] border font-mono text-[9px] tabular-nums transition-all duration-150 outline-none",
                    isSelected ? "border-ion ring-2 ring-ion/40" : "border-veil/[0.04]",
                    onSelect && "hover:scale-[1.04] hover:border-ion/60 focus-visible:border-ion focus-visible:ring-2 focus-visible:ring-ion/40",
                  )}
                  style={{
                    height: 34,
                    background: value ? `rgb(var(--ion-rgb) / ${isSelected ? Math.min(0.95, intensity + 0.2) : intensity})` : "rgb(var(--veil-rgb) / 0.03)",
                    color: value ? heatInk(isSelected ? Math.min(0.95, intensity + 0.2) : intensity) : "var(--mist)",
                  }}
                  title={`${row} · ${col}: ${value} ${unit}${onSelect ? " — click to filter" : ""}`}
                >
                  {value || "·"}
                </button>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Stacked mini timeline                                               */
/* ------------------------------------------------------------------ */

export function DailyBars({
  data,
  height = 120,
  color = palette().pulse,
  emptyLabel = "No events in this window.",
}: {
  data: Array<{ name: string; value: number; color?: string }>;
  height?: number;
  color?: string;
  emptyLabel?: string;
}) {
  if (!data.length) return <div className="py-10 text-center text-[10.5px] text-dim">{emptyLabel}</div>;
  const max = Math.max(1, ...data.map((entry) => entry.value));
  return (
    <div className="w-full" style={{ height }}>
      <div className="flex h-[calc(100%-16px)] items-end gap-[3px]">
        {data.map((entry) => {
          const hue = tone(entry.color || color);
          const empty = entry.value <= 0;
          return (
            <div key={entry.name} className="group relative flex h-full flex-1 items-end justify-center" title={`${entry.name}: ${entry.value}`}>
              <div
                className="relative w-full max-w-[64px] overflow-hidden rounded-t-[3px] transition-[filter,box-shadow] duration-200 group-hover:brightness-125"
                style={{
                  height: empty ? 3 : `${Math.max(2, (entry.value / max) * 100)}%`,
                  background: empty
                    ? "rgb(var(--line-rgb) / 0.16)"
                    : `linear-gradient(180deg, ${withAlpha(hue, 0.95)} 0%, ${withAlpha(hue, 0.55)} 42%, ${withAlpha(hue, 0.14)} 100%)`,
                  boxShadow: empty ? "none" : `inset 0 1px 0 ${withAlpha(hue, 0.9)}, 0 0 16px -7px ${hue}`,
                }}
              />
            </div>
          );
        })}
      </div>
      <div className="mt-1 flex justify-between font-mono text-[7.5px] uppercase tracking-[0.06em] text-dim">
        <span>{data[0]?.name}</span>
        <span>peak {max}</span>
        <span>{data[data.length - 1]?.name}</span>
      </div>
    </div>
  );
}
