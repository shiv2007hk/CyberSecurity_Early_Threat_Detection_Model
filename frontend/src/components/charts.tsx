import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import clsx from "clsx";
import landmask from "./visuals/landmask.json";
import { categoryColors, fmtNumber, riskColor, titleCase } from "../lib/format";
import { heatInk, palette, tone } from "../lib/theme";

export const CHART_GRID = "var(--chart-grid)";
export const AXIS_TICK = { fill: "var(--chart-axis)", fontSize: 9, fontFamily: "JetBrains Mono, monospace" };

function axisTick(value: any) {
  if (typeof value !== "string") return value;
  return value.replace(/^w\/c\s+/, "").replace(/\s+20\d{2}$/, "");
}

export function ChartTip({ active, payload, label, suffix = "" }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="min-w-[150px] rounded-lg border border-line-strong bg-tooltip/95 px-3 py-2.5 shadow-lift backdrop-blur">
      {label !== undefined && <div className="mb-1.5 font-mono text-[9px] uppercase tracking-[0.12em] text-dim">{label}</div>}
      <div className="space-y-1">
        {payload.map((entry: any, index: number) => (
          <div key={`${entry.name}-${index}`} className="flex items-center justify-between gap-4 text-[11px]">
            <span className="flex items-center gap-1.5 text-mist">
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: tone(entry.color) || entry.fill || "var(--ion)" }} />
              {entry.name}
            </span>
            <span className="tnum font-mono text-[10.5px] text-ink">
              {typeof entry.value === "number" ? entry.value.toLocaleString("en-GB", { maximumFractionDigits: 2 }) : entry.value}
              {suffix}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ChartLegend({ items, className }: { items: Array<{ name: string; value?: string | number; color: string }>; className?: string }) {
  return (
    <div className={clsx("flex flex-wrap items-center gap-x-4 gap-y-1.5", className)}>
      {items.map((item) => (
        <span key={item.name} className="inline-flex items-center gap-1.5 text-[10px] text-mist">
          <span className="h-1.5 w-1.5 rounded-sm" style={{ background: tone(item.color) }} />
          {item.name}
          {item.value !== undefined && <span className="tnum font-mono text-[9.5px] text-dim">{item.value}</span>}
        </span>
      ))}
    </div>
  );
}

export function TrendArea({
  data,
  xKey = "name",
  series,
  height = 250,
  stacked = false,
  ySuffix = "",
}: {
  data: any[];
  xKey?: string;
  series: Array<{ key: string; name: string; color: string; dashed?: boolean }>;
  height?: number;
  stacked?: boolean;
  ySuffix?: string;
}) {
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 10, left: -18, bottom: 0 }}>
          <defs>
            {series.map((item) => (
              <linearGradient key={item.key} id={`grad-${item.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={tone(item.color)} stopOpacity={0.24} />
                <stop offset="88%" stopColor={tone(item.color)} stopOpacity={0.01} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid stroke={CHART_GRID} vertical={false} />
          <XAxis dataKey={xKey} tick={AXIS_TICK} tickFormatter={axisTick} tickLine={false} axisLine={{ stroke: CHART_GRID }} interval="preserveStartEnd" minTickGap={26} />
          <YAxis tick={AXIS_TICK} tickLine={false} axisLine={false} allowDecimals={false} width={46} />
          <Tooltip content={<ChartTip suffix={ySuffix} />} cursor={{ stroke: "var(--ion)", strokeOpacity: 0.35, strokeWidth: 1 }} />
          {series.map((item) => (
            <Area
              key={item.key}
              type="monotone"
              dataKey={item.key}
              name={item.name}
              stroke={tone(item.color)}
              strokeWidth={1.6}
              fill={`url(#grad-${item.key})`}
              stackId={stacked ? "stack" : undefined}
              dot={false}
              activeDot={{ r: 2.5, fill: tone(item.color), stroke: "var(--chart-surface)", strokeWidth: 1.5 }}
              isAnimationActive
              animationDuration={700}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function TrendLine({
  data,
  xKey = "name",
  series,
  height = 220,
}: {
  data: any[];
  xKey?: string;
  series: Array<{ key: string; name: string; color: string; dashed?: boolean }>;
  height?: number;
}) {
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 8, right: 10, left: -18, bottom: 0 }}>
          <CartesianGrid stroke={CHART_GRID} vertical={false} />
          <XAxis dataKey={xKey} tick={AXIS_TICK} tickFormatter={axisTick} tickLine={false} axisLine={{ stroke: CHART_GRID }} interval="preserveStartEnd" minTickGap={30} />
          <YAxis tick={AXIS_TICK} tickLine={false} axisLine={false} width={44} />
          <Tooltip content={<ChartTip />} />
          {series.map((item) => (
            <Line
              key={item.key}
              type="monotone"
              dataKey={item.key}
              name={item.name}
              stroke={tone(item.color)}
              strokeWidth={1.7}
              strokeDasharray={item.dashed ? "4 5" : undefined}
              dot={false}
              activeDot={{ r: 2.5, fill: tone(item.color) }}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

export function BarsChart({
  data,
  xKey = "name",
  series,
  height = 240,
  stacked = false,
  layout = "vertical",
}: {
  data: any[];
  xKey?: string;
  series: Array<{ key: string; name: string; color: string }>;
  height?: number;
  stacked?: boolean;
  layout?: "vertical" | "horizontal";
}) {
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout={layout} margin={{ top: 8, right: 12, left: layout === "vertical" ? 2 : -16, bottom: 0 }} barCategoryGap={layout === "vertical" ? "28%" : "22%"}>
          <CartesianGrid stroke={CHART_GRID} vertical={layout === "horizontal"} horizontal={layout === "vertical"} />
          {layout === "vertical" ? (
            <>
              <XAxis dataKey={xKey} tick={AXIS_TICK} tickLine={false} axisLine={{ stroke: CHART_GRID }} interval={0} />
              <YAxis tick={AXIS_TICK} tickLine={false} axisLine={false} width={40} allowDecimals={false} />
            </>
          ) : (
            <>
              <XAxis type="number" tick={AXIS_TICK} tickLine={false} axisLine={false} allowDecimals={false} />
              <YAxis type="category" dataKey={xKey} tick={AXIS_TICK} tickLine={false} axisLine={{ stroke: CHART_GRID }} width={128} interval={0} />
            </>
          )}
          <Tooltip content={<ChartTip />} cursor={{ fill: "var(--pulse)", fillOpacity: 0.07 }} />
          {series.map((item) => (
            <Bar key={item.key} dataKey={item.key} name={item.name} stackId={stacked ? "stack" : undefined} fill={tone(item.color)} radius={[2, 2, 0, 0]} maxBarSize={28} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function DistributionDonut({
  data,
  height = 200,
  centerLabel = "records",
  centerValue,
  colors,
  legend = true,
}: {
  data: Array<{ name: string; value: number }>;
  height?: number;
  centerLabel?: string;
  centerValue?: number;
  colors?: string[];
  legend?: boolean;
}) {
  const seriesColors = colors ?? categoryColors();
  const total = data.reduce((acc, item) => acc + (item.value || 0), 0);
  return (
    <div className="flex flex-wrap items-center gap-4">
      <div className="relative mx-auto shrink-0" style={{ width: height, height }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius="66%"
              outerRadius="92%"
              paddingAngle={1.5}
              stroke="var(--chart-surface)"
              strokeWidth={2}
            >
              {data.map((entry, index) => (
                <Cell key={entry.name} fill={tone(seriesColors[index % seriesColors.length])} />
              ))}
            </Pie>
            <Tooltip content={<ChartTip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="tnum font-display text-[23px] font-semibold leading-none text-ink">{fmtNumber(centerValue ?? total)}</span>
          <span className="mt-1 font-mono text-[8px] uppercase tracking-[0.16em] text-dim">{centerLabel}</span>
        </div>
      </div>
      {legend && (
        <div className="min-w-[130px] flex-1 space-y-1.5">
          {data.map((item, index) => (
            <div key={item.name} className="flex items-center justify-between gap-3 text-[10.5px]">
              <span className="flex min-w-0 items-center gap-1.5 text-mist">
                <span className="h-1.5 w-1.5 shrink-0 rounded-sm" style={{ background: tone(seriesColors[index % seriesColors.length]) }} />
                <span className="truncate">{item.name}</span>
              </span>
              <span className="tnum font-mono text-[9.5px] text-dim">{item.value}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function HBarList({
  data,
  labelKey = "name",
  valueKey = "value",
  color = palette().pulse,
  suffix = "",
  max: maxProp,
}: {
  data: Array<Record<string, any>>;
  labelKey?: string;
  valueKey?: string;
  color?: string;
  suffix?: string;
  max?: number;
}) {
  const max = maxProp || Math.max(1, ...data.map((item) => Number(item[valueKey]) || 0));
  return (
    <div className="space-y-2">
      {data.map((item, index) => {
        const value = Number(item[valueKey]) || 0;
        const rawTone = Array.isArray(item.color) ? item.color[0] : color;
        const barTone = tone(String(rawTone ?? color));
        return (
          <div key={`${item[labelKey]}-${index}`} className="group">
            <div className="mb-1 flex items-baseline justify-between gap-3">
              <span className="truncate text-[10.5px] text-ink">{titleCase(String(item[labelKey]))}</span>
              <span className="tnum shrink-0 font-mono text-[9.5px] text-dim">
                {fmtNumber(value)}
                {suffix}
              </span>
            </div>
            <div className="h-[3px] w-full overflow-hidden rounded-full bg-veil/[0.05]">
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{ width: `${Math.max(2, (value / max) * 100)}%`, background: barTone, opacity: 0.92 }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function Heatmap({
  rows,
  cols,
  data,
  height = 160,
  rowLabel = "severity",
}: {
  rows: string[];
  cols?: string[];
  data: Array<{ [key: string]: any; values: number[] }>;
  height?: number;
  rowLabel?: string;
}) {
  if (!rows.length || !data.length) return <div className="py-8 text-center text-[11px] text-dim">No matrix data in this range.</div>;
  const inferredCols = cols || data[0].values.map((_: number, index: number) => String(index + 1));
  const max = Math.max(1, ...data.flatMap((row) => row.values));
  return (
    <div className="overflow-x-auto">
      <div className="min-w-[340px]">
        <div className="mb-1 grid" style={{ gridTemplateColumns: `52px repeat(${inferredCols.length}, minmax(0, 1fr))` }}>
          <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{rowLabel}</span>
          {inferredCols.map((col) => (
            <span key={col} className="text-center font-mono text-[8px] text-dim">{col}</span>
          ))}
        </div>
        {data.map((row) => (
          <div key={row[rowLabel]} className="mb-1 grid items-center gap-1" style={{ gridTemplateColumns: `52px repeat(${inferredCols.length}, minmax(0, 1fr))` }}>
            <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-mist">{row[rowLabel]}</span>
            {row.values.map((value: number, colIndex: number) => {
              const intensity = value === 0 ? 0 : 0.12 + (value / max) * 0.82;
              return (
                <div
                  key={colIndex}
                  className="grid place-items-center rounded-[3px] border border-veil/[0.03] font-mono text-[9px] tabular-nums"
                  style={{
                    height: Math.max(22, (height - 22) / data.length),
                    background: value === 0 ? "rgb(var(--veil-rgb) / 0.03)" : `rgb(var(--ion-rgb) / ${intensity})`,
                    color: value === 0 ? "var(--mist)" : heatInk(intensity),
                  }}
                  title={`${row[rowLabel]} · ${inferredCols[colIndex]}: ${value}`}
                >
                  {value || "·"}
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Signal map                                                          */
/* ------------------------------------------------------------------ */

const COLS = 72;
const ROWS = 36;
const LAT_TOP = 78;
const LAT_BOTTOM = -56;

function project(lat: number, lon: number): [number, number] {
  const x = ((lon + 180) / 360) * COLS;
  const y = ((LAT_TOP - lat) / (LAT_TOP - LAT_BOTTOM)) * ROWS;
  return [x, y];
}

function mixHex(from: string, to: string, t: number) {
  const parse = (hex: string) => [1, 3, 5].map((index) => parseInt(hex.slice(index, index + 2), 16));
  const a = parse(from);
  const b = parse(to);
  return `#${a.map((value, index) => Math.round(value + (b[index] - value) * t).toString(16).padStart(2, "0")).join("")}`;
}

const GRATICULE_LONS = [-180, -150, -120, -90, -60, -30, 0, 30, 60, 90, 120, 150, 180];
const GRATICULE_LATS = [-30, 0, 30, 60];

export function SignalMap({
  points,
  height = 300,
  className,
  selected,
  onSelect,
  labels = false,
  markerScale = 1,
  pulse = true,
  mode = "markers",
  interactive = false,
}: {
  points: Array<{ country?: string; code?: string; count: number; lat: number; lon: number }>;
  height?: number | string;
  className?: string;
  selected?: string | null;
  onSelect?: (code: string) => void;
  labels?: boolean;
  markerScale?: number;
  pulse?: boolean;
  mode?: "markers" | "density";
  interactive?: boolean;
}) {
  const max = Math.max(1, ...points.map((p) => p.count));
  const [hovered, setHovered] = useState<string | null>(null);
  const [cursor, setCursor] = useState<{ x: number; y: number; w: number; h: number } | null>(null);
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });
  const shellRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<{ sx: number; sy: number; ox: number; oy: number } | null>(null);
  const [dragging, setDragging] = useState(false);
  const W = COLS * 2;
  const H = ROWS * 2;
  const clampView = (k: number, x: number, y: number) => ({
    k,
    x: Math.max(W - W * k, Math.min(0, x)),
    y: Math.max(H - H * k, Math.min(0, y)),
  });
  const pxPerUnit = () => {
    const rect = shellRef.current?.getBoundingClientRect();
    if (!rect) return 1;
    return Math.max(0.0001, Math.min(rect.width / W, rect.height / H));
  };
  const zoomAt = (factor: number, clientX?: number, clientY?: number) => {
    const rect = shellRef.current?.getBoundingClientRect();
    setView((current) => {
      const k = Math.max(1, Math.min(7, current.k * factor));
      if (Math.abs(k - current.k) < 0.0001) return current;
      if (!rect) return { k, x: current.x, y: current.y };
      const scale = Math.max(0.0001, Math.min(rect.width / W, rect.height / H));
      const offsetX = (rect.width - W * scale) / 2;
      const offsetY = (rect.height - H * scale) / 2;
      const ux = ((clientX ?? rect.left + rect.width / 2) - rect.left - offsetX) / scale;
      const uy = ((clientY ?? rect.top + rect.height / 2) - rect.top - offsetY) / scale;
      const anchorX = ux === W / 2 ? current.x : ux;
      const anchorY = uy === H / 2 ? current.y : uy;
      return clampView(k, anchorX - ((anchorX - current.x) * k) / current.k, anchorY - ((anchorY - current.y) * k) / current.k);
    });
  };
  useEffect(() => {
    const el = shellRef.current;
    if (!el || !interactive) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      zoomAt(Math.exp(-event.deltaY * 0.0016), event.clientX, event.clientY);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [interactive]);
  const resetView = () => setView({ k: 1, x: 0, y: 0 });
  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!interactive || view.k <= 1) return;
    if ((event.target as Element).closest("[data-marker]")) return;
    dragRef.current = { sx: event.clientX, sy: event.clientY, ox: view.x, oy: view.y };
    setDragging(true);
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!dragRef.current) return;
    const scale = pxPerUnit();
    const dx = (event.clientX - dragRef.current.sx) / scale;
    const dy = (event.clientY - dragRef.current.sy) / scale;
    setView((current) => clampView(current.k, dragRef.current!.ox + dx, dragRef.current!.oy + dy));
  };
  const endDrag = () => {
    dragRef.current = null;
    setDragging(false);
  };
  const cells = useMemo(() => {
    const list: Array<[number, number]> = [];
    (landmask as string[]).forEach((row, y) => {
      for (let x = 0; x < row.length; x++) if (row[x] === "#") list.push([x + 0.5, y + 0.5]);
    });
    return list;
  }, []);
  const landDots = useMemo(
    () => cells.map(([x, y], index) => <rect key={index} x={x * 2} y={y * 2} width="1.06" height="1.06" rx="0.3" fill="rgb(var(--ink-rgb) / 0.3)" />),
    [cells],
  );
  const hoverPoint = points.find((point) => `${point.code}-${point.country}` === hovered) || null;

  return (
    <div
      ref={shellRef}
      className={clsx(
        "relative w-full overflow-hidden bg-[radial-gradient(120%_100%_at_50%_0%,var(--chart-map-light)_0%,var(--chart-map-mid)_55%,var(--chart-map-deep)_100%)]",
        view.k > 1 && (dragging ? "cursor-grabbing" : "cursor-grab"),
        className,
      )}
      style={{ height, touchAction: view.k > 1 ? "none" : "pan-y" }}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      onDoubleClick={resetView}
      onMouseMove={(event) => {
        const rect = event.currentTarget.getBoundingClientRect();
        setCursor({ x: event.clientX - rect.left, y: event.clientY - rect.top, w: rect.width, h: rect.height });
      }}
      onMouseLeave={() => {
        setHovered(null);
        setCursor(null);
        endDrag();
      }}
    >
      <svg
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="xMidYMid meet"
        className="relative h-full w-full"
        role="img"
        aria-label="Estimated geographic distribution of indicator metadata"
      >
        <defs>
          <linearGradient id="mapOcean" x1="0" y1="0" x2="0.4" y2="1">
            <stop offset="0%" stopColor="var(--chart-map-light)" />
            <stop offset="52%" stopColor="var(--chart-map-mid)" />
            <stop offset="100%" stopColor="var(--chart-map-deep)" />
          </linearGradient>
          <radialGradient id="mapShelf" cx="50%" cy="40%" r="60%">
            <stop offset="0%" stopColor="var(--pulse)" stopOpacity="0.16" />
            <stop offset="60%" stopColor="var(--pulse)" stopOpacity="0.05" />
            <stop offset="100%" stopColor="var(--pulse)" stopOpacity="0" />
          </radialGradient>
          <radialGradient id="mapPoint">
            <stop offset="0%" stopColor="var(--crystal)" stopOpacity="0.85" />
            <stop offset="45%" stopColor="var(--pulse)" stopOpacity="0.4" />
            <stop offset="100%" stopColor="var(--pulse)" stopOpacity="0" />
          </radialGradient>
          <radialGradient id="mapVignette" cx="50%" cy="48%" r="72%">
            <stop offset="62%" stopColor="var(--chart-map-deep)" stopOpacity="0" />
            <stop offset="100%" stopColor="var(--chart-map-deep)" stopOpacity="0.55" />
          </radialGradient>
          <linearGradient id="mapLine" x1="0" x2="1">
            <stop stopColor="var(--pulse)" stopOpacity="0.14" />
            <stop offset="0.5" stopColor="var(--ion)" stopOpacity="0.4" />
            <stop offset="1" stopColor="var(--violet)" stopOpacity="0.16" />
          </linearGradient>
        </defs>

        <rect width={W} height={H} fill="url(#mapOcean)" />
        <rect width={W} height={H} fill="url(#mapShelf)" />

        <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`} style={{ transition: dragging ? "none" : "transform 180ms cubic-bezier(0.16,1,0.3,1)" }}>
        {GRATICULE_LONS.map((lon) => {
          const [x] = project(0, lon);
          return (
            <line key={`lon-${lon}`} x1={x * 2} x2={x * 2} y1="0" y2={H} stroke="var(--chart-grid)" strokeWidth="0.28" />
          );
        })}
        {GRATICULE_LATS.map((lat) => {
          const [, y] = project(lat, 0);
          const equator = lat === 0;
          return (
            <line
              key={`lat-${lat}`}
              x1="0"
              x2={W}
              y1={y * 2}
              y2={y * 2}
              stroke={equator ? "var(--ion)" : "var(--chart-grid)"}
              strokeOpacity={equator ? 0.22 : 1}
              strokeWidth={equator ? "0.34" : "0.28"}
              strokeDasharray={equator ? undefined : "2 3"}
            />
          );
        })}
        <text x="2.4" y={project(0, 0)[1] * 2 - 1.4} fill="var(--chart-axis)" fontSize="1.7" fontFamily="JetBrains Mono, monospace" letterSpacing="0.14">EQUATOR</text>

        {landDots}

        {points.map((point) => {
          const [x, y] = project(point.lat, point.lon);
          const intensity = Math.min(1, point.count / max);
          const radius = (1.9 + intensity * 5.4) * markerScale;
          const hue = mixHex(palette().pulse, palette().crystal, intensity);
          const isSelected = selected && selected === point.code;
          const isHovered = hovered === `${point.code}-${point.country}`;
          const active = isSelected || isHovered;
          const cx = x * 2;
          const cy = y * 2;

          if (mode === "density") {
            return (
              <g
                key={`${point.code}-${point.country}`}
                data-marker=""
                transform={`translate(${cx}, ${cy})`}
                className={onSelect ? "cursor-pointer" : undefined}
                onMouseEnter={() => setHovered(`${point.code}-${point.country}`)}
                onMouseLeave={() => setHovered(null)}
                onClick={() => onSelect?.(point.code || "")}
                role={onSelect ? "button" : undefined}
                tabIndex={onSelect ? 0 : undefined}
                aria-label={`${point.country || "Unknown"}: ${fmtNumber(point.count)} geolocated indicator${point.count === 1 ? "" : "s"}`}
                onKeyDown={(event) => {
                  if (!onSelect) return;
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelect(point.code || "");
                  }
                }}
              >
                <title>{`${point.country || "Unknown"} · ${fmtNumber(point.count)} indicator location${point.count === 1 ? "" : "s"}`}</title>
                <circle r={radius * 3.4} fill="url(#mapPoint)" opacity={0.5 + intensity * 0.35} />
                <circle r={radius * 0.42} fill="var(--crystal)" opacity="0.9" />
                {isSelected && <circle r={radius * 0.9} fill="none" stroke="var(--ink)" strokeWidth="0.4" strokeDasharray="1.2 1.2" />}
                {active && (
                  <text x={radius * 0.9} y={-radius * 0.5} fill="var(--chart-plot-ink)" fontSize="1.8" fontFamily="JetBrains Mono, monospace" letterSpacing="0.08" pointerEvents="none">
                    {point.code || point.country?.slice(0, 2).toUpperCase()}
                  </text>
                )}
              </g>
            );
          }

          return (
            <g
              key={`${point.code}-${point.country}`}
              data-marker=""
              transform={`translate(${cx}, ${cy})`}
              className={onSelect ? "cursor-pointer" : undefined}
              onMouseEnter={() => setHovered(`${point.code}-${point.country}`)}
              onMouseLeave={() => setHovered(null)}
              onClick={() => onSelect?.(point.code || "")}
              role={onSelect ? "button" : undefined}
              tabIndex={onSelect ? 0 : undefined}
              aria-label={`${point.country || "Unknown"}: ${fmtNumber(point.count)} geolocated indicator${point.count === 1 ? "" : "s"}`}
              onKeyDown={(event) => {
                if (!onSelect) return;
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelect(point.code || "");
                }
              }}
            >
              <title>{`${point.country || "Unknown"} · ${fmtNumber(point.count)} indicator location${point.count === 1 ? "" : "s"}`}</title>
              <circle r={radius * 2.9} fill="url(#mapPoint)" opacity={active ? 0.78 : 0.4 + intensity * 0.2} />
              {intensity > 0.55 && <circle r={radius * 1.5} fill="none" stroke={hue} strokeWidth="0.25" opacity="0.32" />}
              {pulse && (
                <circle r={radius * 0.6} fill="none" stroke={hue} strokeWidth="0.32" opacity="0.75">
                  <animate attributeName="r" values={`${radius * 0.6};${radius * 2.4}`} dur="3.4s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.62;0" dur="3.4s" repeatCount="indefinite" />
                </circle>
              )}
              <circle r={radius * 0.62} fill={hue} stroke="var(--chart-plot-ink)" strokeOpacity="0.85" strokeWidth={active ? "0.42" : "0.22"} />
              {isSelected && (
                <>
                  <line x1={-radius * 2.2} x2={radius * 2.2} y1="0" y2="0" stroke="var(--chart-plot-ink)" strokeOpacity="0.45" strokeWidth="0.2" />
                  <line x1="0" x2="0" y1={-radius * 2.2} y2={radius * 2.2} stroke="var(--chart-plot-ink)" strokeOpacity="0.45" strokeWidth="0.2" />
                  <circle r={radius * 1.4} fill="none" stroke="var(--ink)" strokeWidth="0.42" strokeDasharray="1.4 1.4">
                    <animate attributeName="r" values={`${radius * 1.25};${radius * 1.55}`} dur="2.6s" repeatCount="indefinite" />
                  </circle>
                </>
              )}
              {(labels || active) && (
                <g pointerEvents="none">
                  <text
                    x={radius * 1.15 + 1.2}
                    y={-radius * 0.85}
                    fill={active ? "var(--chart-plot-ink)" : "var(--mist)"}
                    fontSize={active ? "2.2" : "1.75"}
                    fontFamily="JetBrains Mono, monospace"
                    letterSpacing="0.07"
                  >
                    {point.code || point.country?.slice(0, 2).toUpperCase()}
                  </text>
                  {active && (
                    <text
                      x={radius * 1.15 + 1.2}
                      y={-radius * 0.85 + 2.7}
                      fill="var(--mist)"
                      fontSize="1.6"
                      fontFamily="JetBrains Mono, monospace"
                      letterSpacing="0.05"
                    >
                      {fmtNumber(point.count)}
                    </text>
                  )}
                </g>
              )}
            </g>
          );
        })}
        </g>

        <rect width={W} height={H} fill="url(#mapVignette)" pointerEvents="none" />
        <text x="2.4" y={H - 3.2} fill="var(--chart-axis)" fontSize="1.55" fontFamily="JetBrains Mono, monospace" letterSpacing="0.16">
          SOURCE-SUPPLIED LOCATION ESTIMATES · NOT ATTRIBUTION
        </text>
      </svg>

      {interactive && (
        <div
          className="absolute bottom-2.5 right-2.5 z-20 flex items-center gap-1 rounded-lg border border-line-strong bg-sunken/80 p-0.5 shadow-lift backdrop-blur-md"
          onPointerDown={(event) => event.stopPropagation()}
        >
          <button
            type="button"
            onClick={() => zoomAt(1 / 1.4)}
            aria-label="Zoom out"
            className="grid h-6 w-6 place-items-center rounded-md text-[13px] leading-none text-mist transition-colors hover:bg-ion/10 hover:text-ion"
          >
            −
          </button>
          <button
            type="button"
            onClick={resetView}
            aria-label="Reset map view"
            className="tnum h-6 min-w-[40px] rounded-md px-1 font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim transition-colors hover:bg-ion/10 hover:text-ion"
          >
            {view.k.toFixed(1)}×
          </button>
          <button
            type="button"
            onClick={() => zoomAt(1.4)}
            aria-label="Zoom in"
            className="grid h-6 w-6 place-items-center rounded-md text-[13px] leading-none text-mist transition-colors hover:bg-ion/10 hover:text-ion"
          >
            +
          </button>
        </div>
      )}

      {hoverPoint && cursor && mode === "markers" && (
        <div
          className="pointer-events-none absolute z-20 w-[176px] rounded-lg border border-line-strong bg-sunken/95 px-2.5 py-2 shadow-lift backdrop-blur-md"
          style={{
            left: Math.max(8, Math.min(cursor.x + 14, cursor.w - 184)),
            top: Math.max(8, Math.min(cursor.y - 54, cursor.h - 62)),
          }}
        >
          <div className="flex items-center justify-between gap-2">
            <span className="truncate text-[11px] font-medium text-ink">{hoverPoint.country || "Unknown"}</span>
            <span className="shrink-0 font-mono text-[8px] uppercase tracking-[0.1em] text-ion">{hoverPoint.code}</span>
          </div>
          <div className="mt-0.5 font-mono text-[9px] uppercase tracking-[0.08em] text-dim">
            {fmtNumber(hoverPoint.count)} location{hoverPoint.count === 1 ? "" : "s"} · source metadata
          </div>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Correlation graph                                                   */
/* ------------------------------------------------------------------ */

interface GraphNode {
  id: string;
  ref?: string;
  name: string;
  severity?: string;
  risk?: number;
  degree?: number;
  category?: string;
  technology?: string;
  [key: string]: any;
}

interface GraphEdge {
  source: string;
  target: string;
  score: number;
  reasons?: Array<{ label: string; weight?: number }>;
}

const graphCache = new WeakMap<object, Map<string, { x: number; y: number }>>();

const GRAPH_W = 1000;
const GRAPH_H = 620;

export function CorrelationGraph({
  nodes,
  edges,
  height = 560,
  onSelect,
  selectedId,
  maxNodes = 140,
  labels = false,
  hideIsolated = false,
  query = "",
  path = [],
  className,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  height?: number | string;
  onSelect?: (node: GraphNode) => void;
  selectedId?: string | null;
  maxNodes?: number;
  labels?: boolean;
  hideIsolated?: boolean;
  query?: string;
  path?: string[];
  className?: string;
}) {
  const visible = useMemo(() => {
    const sorted = [...nodes].sort((a, b) => (b.degree || 0) - (a.degree || 0));
    return sorted.slice(0, maxNodes);
  }, [nodes, maxNodes]);

  const visibleIds = useMemo(() => new Set(visible.map((node) => node.ref || node.id)), [visible]);

  const layout = useMemo(() => {
    const cached = graphCache.get(nodes);
    if (cached) return cached;
    const positions = new Map<string, { x: number; y: number }>();
    const keys = visible.map((node) => node.ref || node.id);
    keys.forEach((key, index) => {
      const golden = index * 2.399963;
      const radius = 90 + Math.sqrt(index + 1) * 52;
      positions.set(key, {
        x: GRAPH_W / 2 + Math.cos(golden) * radius * 1.32,
        y: GRAPH_H / 2 + Math.sin(golden) * radius * 0.82,
      });
    });
    const links = edges.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target));
    for (let iteration = 0; iteration < 170; iteration++) {
      const keysArr = [...positions.keys()];
      for (let i = 0; i < keysArr.length; i++) {
        for (let j = i + 1; j < keysArr.length; j++) {
          const a = positions.get(keysArr[i])!;
          const b = positions.get(keysArr[j])!;
          let dx = b.x - a.x;
          let dy = b.y - a.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = 1500 / (dist * dist);
          dx = (dx / dist) * force;
          dy = (dy / dist) * force;
          a.x -= dx;
          a.y -= dy;
          b.x += dx;
          b.y += dy;
          if (dist < 30) {
            const push = (30 - dist) * 0.12;
            const nx = (b.x - a.x) / (Math.abs(b.x - a.x) + Math.abs(b.y - a.y) + 0.001);
            const ny = (b.y - a.y) / (Math.abs(b.x - a.x) + Math.abs(b.y - a.y) + 0.001);
            a.x -= nx * push;
            a.y -= ny * push;
            b.x += nx * push;
            b.y += ny * push;
          }
        }
      }
      links.forEach((edge) => {
        const a = positions.get(edge.source);
        const b = positions.get(edge.target);
        if (!a || !b) return;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const ideal = 132;
        const force = (dist - ideal) * 0.016 * (0.4 + (edge.score || 0.5));
        a.x += (dx / dist) * force;
        a.y += (dy / dist) * force;
        b.x -= (dx / dist) * force;
        b.y -= (dy / dist) * force;
      });
      positions.forEach((pos) => {
        pos.x += (GRAPH_W / 2 - pos.x) * 0.0032;
        pos.y += (GRAPH_H / 2 - pos.y) * 0.0038;
        pos.x = Math.max(42, Math.min(GRAPH_W - 42, pos.x));
        pos.y = Math.max(34, Math.min(GRAPH_H - 34, pos.y));
      });
    }
    graphCache.set(nodes, positions);
    return positions;
  }, [nodes, edges, visible, visibleIds]);

  const links = useMemo(
    () => edges.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target)),
    [edges, visibleIds],
  );

  const adjacency = useMemo(() => {
    const map = new Map<string, Set<string>>();
    links.forEach((edge) => {
      if (!map.has(edge.source)) map.set(edge.source, new Set());
      if (!map.has(edge.target)) map.set(edge.target, new Set());
      map.get(edge.source)!.add(edge.target);
      map.get(edge.target)!.add(edge.source);
    });
    return map;
  }, [links]);

  const matching = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return null;
    const set = new Set<string>();
    visible.forEach((node) => {
      const key = node.ref || node.id;
      const haystack = `${node.ref || ""} ${node.name || ""} ${node.category || ""} ${node.technology || ""}`.toLowerCase();
      if (haystack.includes(needle)) set.add(key);
    });
    return set;
  }, [query, visible]);

  const pathPairs = useMemo(() => {
    const set = new Set<string>();
    for (let index = 0; index < path.length - 1; index++) {
      set.add(`${path[index]}>${path[index + 1]}`);
      set.add(`${path[index + 1]}>${path[index]}`);
    }
    return set;
  }, [path]);
  const pathSet = useMemo(() => new Set(path), [path]);

  const [hovered, setHovered] = useState<string | null>(null);
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });
  const shellRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<{ sx: number; sy: number; ox: number; oy: number } | null>(null);
  const [dragging, setDragging] = useState(false);

  const clampView = (k: number, x: number, y: number) => ({
    k,
    x: Math.max(GRAPH_W - GRAPH_W * k, Math.min(0, x)),
    y: Math.max(GRAPH_H - GRAPH_H * k, Math.min(0, y)),
  });
  const scaleFor = () => {
    const rect = shellRef.current?.getBoundingClientRect();
    if (!rect) return 1;
    return Math.max(0.0001, Math.min(rect.width / GRAPH_W, rect.height / GRAPH_H));
  };
  const zoomAt = (factor: number, clientX?: number, clientY?: number) => {
    const rect = shellRef.current?.getBoundingClientRect();
    setView((current) => {
      const k = Math.max(1, Math.min(6, current.k * factor));
      if (Math.abs(k - current.k) < 0.0001) return current;
      if (!rect) return { k, x: current.x, y: current.y };
      const scale = Math.max(0.0001, Math.min(rect.width / GRAPH_W, rect.height / GRAPH_H));
      const offsetX = (rect.width - GRAPH_W * scale) / 2;
      const offsetY = (rect.height - GRAPH_H * scale) / 2;
      const hasPointer = clientX != null && clientY != null;
      const ux = hasPointer ? ((clientX as number) - rect.left - offsetX) / scale : GRAPH_W / 2;
      const uy = hasPointer ? ((clientY as number) - rect.top - offsetY) / scale : GRAPH_H / 2;
      return clampView(k, ux - ((ux - current.x) * k) / current.k, uy - ((uy - current.y) * k) / current.k);
    });
  };
  useEffect(() => {
    const el = shellRef.current;
    if (!el) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      zoomAt(Math.exp(-event.deltaY * 0.0016), event.clientX, event.clientY);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);
  const resetView = () => setView({ k: 1, x: 0, y: 0 });
  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (view.k <= 1) return;
    if ((event.target as Element).closest("[data-graph-node]")) return;
    dragRef.current = { sx: event.clientX, sy: event.clientY, ox: view.x, oy: view.y };
    setDragging(true);
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!dragRef.current) return;
    const scale = scaleFor();
    const dx = (event.clientX - dragRef.current.sx) / scale;
    const dy = (event.clientY - dragRef.current.sy) / scale;
    setView((current) => clampView(current.k, dragRef.current!.ox + dx, dragRef.current!.oy + dy));
  };
  const endDrag = () => {
    dragRef.current = null;
    setDragging(false);
  };

  if (!nodes.length) return <div className="py-16 text-center text-[11px] text-dim">No correlated clusters in this range.</div>;

  const activeId = hovered || selectedId || null;
  const activeNeighbors = activeId ? adjacency.get(activeId) : undefined;

  return (
    <div
      ref={shellRef}
      className={clsx(
        "relative w-full overflow-hidden bg-[radial-gradient(120%_100%_at_50%_0%,var(--chart-map-light)_0%,var(--chart-map-mid)_58%,var(--chart-map-deep)_100%)]",
        view.k > 1 && (dragging ? "cursor-grabbing" : "cursor-grab"),
        className,
      )}
      style={{ height, touchAction: view.k > 1 ? "none" : "pan-y" }}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      onDoubleClick={resetView}
      onMouseLeave={endDrag}
    >
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_45%,rgb(var(--pulse-rgb)/0.14),transparent_62%)]" aria-hidden="true" />
      <svg
        viewBox={`0 0 ${GRAPH_W} ${GRAPH_H}`}
        preserveAspectRatio="xMidYMid meet"
        className="relative h-full w-full"
        role="img"
        aria-label="Threat correlation network"
      >
        <defs>
          <radialGradient id="graphCore" cx="50%" cy="50%">
            <stop offset="0%" stopColor="var(--chart-map-light)" stopOpacity="0.9" />
            <stop offset="70%" stopColor="var(--chart-map-mid)" stopOpacity="0.4" />
            <stop offset="100%" stopColor="var(--chart-map-deep)" stopOpacity="0" />
          </radialGradient>
          <filter id="graphGlow" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <pattern id="graphDots" width="28" height="28" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="0.7" fill="rgb(var(--ink-rgb) / 0.14)" />
          </pattern>
        </defs>
        <rect width={GRAPH_W} height={GRAPH_H} fill="url(#graphDots)" />
        <circle cx={GRAPH_W / 2} cy={GRAPH_H / 2} r={GRAPH_H * 0.62} fill="url(#graphCore)" />

        <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`} style={{ transition: dragging ? "none" : "transform 180ms cubic-bezier(0.16,1,0.3,1)" }}>
          <g opacity="0.45">
            {[120, 220, 320, 420].map((radius, index) => (
              <circle
                key={radius}
                cx={GRAPH_W / 2}
                cy={GRAPH_H / 2}
                r={radius}
                fill="none"
                stroke="var(--chart-grid)"
                strokeWidth="0.6"
                strokeDasharray={index % 2 ? "2 8" : undefined}
              />
            ))}
          </g>

          {links.map((edge, index) => {
            const a = layout.get(edge.source);
            const b = layout.get(edge.target);
            if (!a || !b) return null;
            const inPath = pathPairs.has(`${edge.source}>${edge.target}`);
            const touchesActive = activeId === edge.source || activeId === edge.target;
            const dim = (activeId && !touchesActive) || (matching && !matching.has(edge.source) && !matching.has(edge.target));
            const midX = (a.x + b.x) / 2 + (b.y - a.y) * 0.1;
            const midY = (a.y + b.y) / 2 - (b.x - a.x) * 0.1;
            return (
              <path
                key={`${edge.source}-${edge.target}-${index}`}
                d={`M ${a.x} ${a.y} Q ${midX} ${midY} ${b.x} ${b.y}`}
                fill="none"
                className={inPath && !dragging ? "edge-flow" : undefined}
                stroke={
                  inPath
                    ? "rgb(var(--crystal-rgb) / 0.9)"
                    : touchesActive
                      ? "rgb(var(--ion-rgb) / 0.6)"
                      : "rgb(var(--dim-rgb) / 0.34)"
                }
                strokeWidth={inPath ? 1.7 : touchesActive ? 1.15 : 0.55}
                opacity={dim ? 0.16 : 1}
                style={{ transition: "opacity 220ms ease, stroke-width 220ms ease" }}
              />
            );
          })}

          {visible.map((node) => {
            const key = node.ref || node.id;
            const pos = layout.get(key);
            if (!pos) return null;
            const degree = node.degree || 0;
            if (hideIsolated && degree === 0) return null;
            const size = 3 + Math.min(8, degree * 0.78);
            const color = riskColor(node.risk);
            const isSelected = selectedId === key;
            const isHovered = hovered === key;
            const isPath = pathSet.has(key);
            const related = !activeId || activeId === key || activeNeighbors?.has(key);
            const pathRelated = !pathSet.size || isPath;
            const matchDim = matching ? !matching.has(key) : false;
            const dim = !related || !pathRelated || matchDim;
            const showLabel = labels || isSelected || isHovered || isPath || degree >= 9;
            return (
              <g
                key={key}
                data-graph-node=""
                transform={`translate(${pos.x}, ${pos.y})`}
                className={onSelect ? "cursor-pointer" : undefined}
                onMouseEnter={() => setHovered(key)}
                onMouseLeave={() => setHovered(null)}
                onClick={() => onSelect?.(node)}
                role={onSelect ? "button" : undefined}
                tabIndex={onSelect ? 0 : undefined}
                aria-label={`${node.ref || node.name}: risk ${Math.round(Number(node.risk) || 0)}, ${degree} connection${degree === 1 ? "" : "s"}`}
                onKeyDown={(event) => {
                  if (!onSelect) return;
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelect(node);
                  }
                }}
                opacity={dim ? 0.24 : 1}
                style={{ transition: "opacity 240ms ease" }}
              >
                <title>{`${node.ref || node.name} · ${node.category || "record"} · ${degree} connection(s)`}</title>
                <circle r={size * 3} fill={color} opacity={isSelected || isHovered || isPath ? 0.16 : 0.06} />
                <circle r={size + 6.5} fill="none" stroke={color} strokeWidth="0.5" opacity={isSelected ? 0.9 : 0.35} strokeDasharray={isSelected ? undefined : "1.6 2.4"} />
                <circle
                  r={size}
                  fill={color}
                  opacity={isSelected || isHovered ? 1 : 0.86}
                  filter={isSelected || isPath ? "url(#graphGlow)" : undefined}
                />
                <circle r={size * 0.4} fill="var(--chart-node-core)" opacity={0.85} />
                {isSelected && (
                  <circle r={size + 11} fill="none" stroke="var(--crystal)" strokeWidth="0.8" strokeDasharray="2 3" opacity="0.85">
                    <animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="9s" repeatCount="indefinite" />
                  </circle>
                )}
                {showLabel && (
                  <g pointerEvents="none">
                    <text x={size + 8} y={2.5} fill={isSelected || isHovered || isPath ? "var(--chart-plot-ink)" : "rgb(var(--mist-rgb) / 0.9)"} fontSize={isSelected ? "10" : "8.6"} fontFamily="JetBrains Mono, monospace" letterSpacing="0.02">
                      {(node.ref || node.name).slice(0, 26)}
                    </text>
                    {(isSelected || isHovered) && (
                      <text x={size + 8} y={13} fill="var(--chart-axis)" fontSize="7.4" fontFamily="JetBrains Mono, monospace">
                        risk {Math.round(Number(node.risk) || 0)} · {degree} link{degree === 1 ? "" : "s"}
                      </text>
                    )}
                  </g>
                )}
              </g>
            );
          })}
        </g>
      </svg>

      <div className="pointer-events-none absolute bottom-3 left-3 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">
        <span className="hidden sm:inline">nodes {fmtNumber(nodes.length)}</span>
        <span className="hidden sm:inline">edges {fmtNumber(edges.length)}</span>
        {nodes.length > maxNodes && <span className="text-violet">top {maxNodes} by degree</span>}
        {matching && <span className="text-ion">{matching.size} match{matching.size === 1 ? "" : "es"}</span>}
      </div>

      <div
        className="absolute bottom-3 right-3 z-10 flex items-center gap-1 rounded-lg border border-line-strong bg-sunken/80 p-0.5 shadow-lift backdrop-blur-md"
        onPointerDown={(event) => event.stopPropagation()}
      >
        <button
          type="button"
          onClick={() => zoomAt(1 / 1.35)}
          aria-label="Zoom out"
          className="grid h-6 w-6 place-items-center rounded-md text-[13px] leading-none text-mist transition-colors hover:bg-ion/10 hover:text-ion"
        >
          −
        </button>
        <button
          type="button"
          onClick={resetView}
          aria-label="Fit graph to screen"
          className="tnum h-6 min-w-[42px] rounded-md px-1 font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim transition-colors hover:bg-ion/10 hover:text-ion"
        >
          {view.k > 1 ? `${view.k.toFixed(1)}×` : "fit"}
        </button>
        <button
          type="button"
          onClick={() => zoomAt(1.35)}
          aria-label="Zoom in"
          className="grid h-6 w-6 place-items-center rounded-md text-[13px] leading-none text-mist transition-colors hover:bg-ion/10 hover:text-ion"
        >
          +
        </button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Sparkline                                                           */
/* ------------------------------------------------------------------ */

export function Sparkline({ values, color = palette().ion, width = 94, height = 24 }: { values: number[]; color?: string; width?: number; height?: number }) {
  if (!values.length) return null;
  const max = Math.max(1, ...values);
  const points = values.map((value, index) => `${(index / Math.max(1, values.length - 1)) * width},${height - (value / max) * (height - 3) - 1.5}`).join(" ");
  return (
    <svg width={width} height={height} className="overflow-visible" aria-hidden="true">
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.2" strokeLinejoin="round" strokeLinecap="round" opacity="0.8" />
    </svg>
  );
}
