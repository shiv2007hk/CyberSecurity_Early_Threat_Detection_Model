import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  CircleSlash,
  DatabaseZap,
  Globe2,
  RefreshCw,
  ServerCog,
  ShieldCheck,
  Signal,
  TriangleAlert,
  Waves,
} from "lucide-react";
import clsx from "clsx";
import { api, qs } from "../../lib/api";
import { fmtDate, fmtNumber, relTime, titleCase } from "../../lib/format";
import { tone as themeTone } from "../../lib/theme";
import {
  EmptyState,
  ErrorState,
  InlineNotice,
  LoadingBlock,
  PageHeader,
  Panel,
  PanelHead,
  RangeTabs,
  StatusBadge,
} from "../../components/ui";
import { ChartLegend, HBarList, SignalMap, TrendArea } from "../../components/charts";
import { RadarChart, useChartBox } from "../../components/analytics-charts";
import { FilterSelect, MiniBar, SectionLabel } from "./shared";

const TONES: Record<string, string> = {
  ion: "#64d8ff",
  pulse: "#49b8ff",
  violet: "#9a8cff",
  crit: "#ff4d5e",
  high: "#ff963d",
  low: "#42c98a",
  dim: "#6f8aa4",
};

function StatBlock({
  label,
  value,
  detail,
  tone = "ion",
  children,
}: {
  label: string;
  value: string | number;
  detail?: string;
  tone?: keyof typeof TONES;
  children?: React.ReactNode;
}) {
  const swatch = themeTone(TONES[tone]);
  return (
    <div className="stat-tile group min-w-0 px-4 py-4">
      <span
        className="pointer-events-none absolute inset-x-4 top-0 h-px opacity-80"
        style={{ background: `linear-gradient(90deg, transparent, ${swatch}, transparent)` }}
        aria-hidden="true"
      />
      <div className="flex items-start gap-1.5 text-[11px] font-medium leading-[1.4] tracking-[-0.005em] text-mist">
        <span className="mt-[5px] h-1 w-1 shrink-0 rounded-full" style={{ background: swatch }} />
        <span className="min-w-0">{label}</span>
      </div>
      <div className="tnum mt-2.5 font-display text-[32px] font-semibold leading-none tracking-[-0.025em] text-ink">{value}</div>
      <div className="mt-2 flex min-w-0 items-center justify-between gap-3">
        {detail && <span className="truncate text-[10.5px] text-dim">{detail}</span>}
        {children}
      </div>
      <span
        className="pointer-events-none absolute -bottom-12 right-0 h-24 w-24 rounded-full opacity-[0.12] blur-2xl transition-opacity duration-300 group-hover:opacity-[0.22]"
        style={{ background: swatch }}
        aria-hidden="true"
      />
    </div>
  );
}

function ControlChart({
  data,
  selected,
  onSelect,
}: {
  data: Array<{ name: string; observed: number; baseline: number; z: number; flagged: boolean }>;
  selected: string | null;
  onSelect: (name: string) => void;
}) {
  const [boxRef, box] = useChartBox(700, 292);
  if (!data.length) return <div className="py-14 text-center text-[11px] text-dim">No activity buckets in this window.</div>;
  /* Authored at 700 units but drawn into a ~616px card, which shrank every label by 12%. */
  const W = box.w;
  const H = Math.max(170, Math.round(W * 0.417));
  const pad = { left: 40, right: 14, top: 22, bottom: 38 };
  const max = Math.max(1, ...data.map((entry) => Math.max(entry.observed, entry.baseline)));
  const deviations = data
    .filter((entry) => Math.abs(entry.z) > 0.05 && entry.observed !== entry.baseline)
    .map((entry) => Math.abs(entry.observed - entry.baseline) / Math.abs(entry.z))
    .sort((a, b) => a - b);
  const sigma = Math.max(1, deviations.length ? deviations[Math.floor(deviations.length / 2)] : 1);
  const mean = data[0].baseline;
  const threshold = mean + 2 * sigma;
  const ceiling = Math.max(max, threshold) * 1.14;
  const py = (value: number) => H - pad.bottom - (value / ceiling) * (H - pad.top - pad.bottom);
  const slot = (W - pad.left - pad.right) / data.length;
  const labelEvery = Math.max(1, Math.ceil(data.length / 7));

  return (
    <div ref={boxRef} style={{ height: H }} className="w-full">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full" role="img" aria-label="Threat activity against a two-sigma baseline">
        {[0, 0.25, 0.5, 0.75, 1].map((fraction) => {
          const value = ceiling * fraction;
          return (
            <g key={fraction}>
              <line x1={pad.left} x2={W - pad.right} y1={py(value)} y2={py(value)} stroke="var(--chart-grid)" strokeWidth="0.7" />
              <text x={pad.left - 7} y={py(value) + 3} textAnchor="end" fill="var(--chart-axis)" fontSize="7.5" fontFamily="JetBrains Mono, monospace">
                {Math.round(value)}
              </text>
            </g>
          );
        })}
        <rect
          x={pad.left}
          y={py(threshold)}
          width={W - pad.left - pad.right}
          height={Math.max(0, py(mean) - py(threshold))}
          fill="rgb(var(--high-rgb) / 0.05)"
        />
        <line x1={pad.left} x2={W - pad.right} y1={py(mean)} y2={py(mean)} stroke="rgb(var(--pulse-rgb) / 0.6)" strokeWidth="0.9" strokeDasharray="4 4" />
        <line x1={pad.left} x2={W - pad.right} y1={py(threshold)} y2={py(threshold)} stroke="rgb(var(--high-rgb) / 0.65)" strokeWidth="0.9" strokeDasharray="2 4" />
        {data.map((entry, index) => {
          const x = pad.left + slot * index;
          const barW = Math.max(2, slot * 0.56);
          const isSelected = selected === entry.name;
          const color = themeTone(entry.flagged ? (entry.z >= 3 ? TONES.crit : TONES.high) : TONES.pulse);
          return (
            <g key={`${entry.name}-${index}`} onClick={() => onSelect(entry.name)} className="cursor-pointer">
              <rect x={x} y={pad.top} width={slot} height={H - pad.top - pad.bottom} fill="transparent" />
              <rect
                x={x + (slot - barW) / 2}
                y={py(entry.observed)}
                width={barW}
                height={Math.max(1, py(0) - py(entry.observed))}
                rx="1.5"
                fill={color}
                fillOpacity={entry.flagged ? 0.82 : isSelected ? 0.7 : 0.34}
                stroke={isSelected ? "var(--ink)" : color}
                strokeOpacity={isSelected ? 0.9 : 0.55}
                strokeWidth={isSelected ? 1 : 0.6}
              />
              {entry.flagged && (
                <circle cx={x + slot / 2} cy={py(entry.observed) - 5} r="2.4" fill={color}>
                  <title>{`${entry.name}: ${entry.observed} records · z ${entry.z} above the ${entry.baseline} baseline`}</title>
                </circle>
              )}
              {index % labelEvery === 0 && (
                <text x={x + slot / 2} y={H - pad.bottom + 14} textAnchor="middle" fill="var(--chart-axis)" fontSize="7.2" fontFamily="JetBrains Mono, monospace">
                  {entry.name}
                </text>
              )}
            </g>
          );
        })}
        {/* Painted after the bars so a flagged interval cannot bury the threshold value. */}
        {(() => {
          const label = `2σ THRESHOLD ${threshold.toFixed(1)}`;
          const labelW = label.length * 5.2 + 10;
          const y = Math.max(pad.top + 3, py(threshold) - 5);
          return (
            <g pointerEvents="none">
              <rect x={W - pad.right - labelW} y={y - 8.5} width={labelW} height={11.5} rx="2" fill="var(--tooltip)" fillOpacity="0.92" stroke="var(--line)" />
              <text x={W - pad.right - 5} y={y} textAnchor="end" fill="rgb(var(--high-rgb))" fontSize="7" fontFamily="JetBrains Mono, monospace" letterSpacing="1">
                {label}
              </text>
            </g>
          );
        })()}
      </svg>
      <ChartLegend
        className="mt-1 px-1"
        items={[
          { name: "Observed records", color: TONES.pulse },
          { name: "Baseline mean", color: "#49b8ff" },
          { name: "Flagged interval", color: TONES.high },
        ]}
      />
    </div>
  );
}

export default function Monitoring() {
  const [range, setRange] = useState("30d");
  const [category, setCategory] = useState("all");
  const [selectedBucket, setSelectedBucket] = useState<string | null>(null);
  const [selectedGeo, setSelectedGeo] = useState<string | null>(null);

  const analyticsQuery = useQuery({
    queryKey: ["monitoring", range, category],
    queryFn: () =>
      api<any>(
        `/analytics${qs({ range, category: category === "all" ? undefined : category })}`,
      ),
  });
  const facetsQuery = useQuery({
    queryKey: ["monitoring-facets", range],
    queryFn: () => api<any>(`/threats${qs({ size: 1, range })}`),
    staleTime: 60_000,
  });
  const alertsQuery = useQuery({
    queryKey: ["alert-summary"],
    queryFn: () => api<any>("/alerts/summary"),
    staleTime: 30_000,
  });
  const logsQuery = useQuery({
    queryKey: ["monitoring-ingestion"],
    queryFn: () => api<any>("/sources/logs?size=100"),
    staleTime: 60_000,
  });

  const data = analyticsQuery.data;
  const previousRange = useMemo(() => {
    if (!data?.range?.start || !data?.range?.end) return null;
    const start = new Date(data.range.start).getTime();
    const end = new Date(data.range.end).getTime();
    const span = Math.max(60_000, end - start);
    return { from: new Date(start - span).toISOString(), end: new Date(start).toISOString() };
  }, [data?.range?.start, data?.range?.end]);
  const previousQuery = useQuery({
    queryKey: ["monitoring-previous", previousRange?.from, previousRange?.end],
    enabled: !!previousRange,
    queryFn: () => api<any>(`/threats${qs({ size: 1, range: "custom", from: previousRange!.from, end: previousRange!.end })}`),
    staleTime: 60_000,
  });

  const anomalies = useMemo(
    () => (data?.anomaly_series || []) as Array<{ name: string; observed: number; baseline: number; z: number; flagged: boolean }>,
    [data],
  );
  const flagged = useMemo(() => anomalies.filter((entry) => entry.flagged), [anomalies]);
  const flaggedPeak = useMemo(() => Math.max(1, ...flagged.map((entry) => entry.observed)), [flagged]);
  const baseline = anomalies[0]?.baseline ?? 0;

  const categories = useMemo(
    () =>
      ((facetsQuery.data?.facets?.categories || []) as Array<{ name: string; count: number }>).map((entry) => ({
        value: entry.name,
        label: `${entry.name} (${entry.count})`,
      })),
    [facetsQuery.data],
  );
  const categoryOptions = useMemo(() => [{ value: "all", label: "All categories" }, ...categories], [categories]);

  const currentCategories = useMemo(
    () => (facetsQuery.data?.facets?.categories || []) as Array<{ name: string; count: number }>,
    [facetsQuery.data],
  );

  const previousCategories = useMemo(() => {
    const rows = (previousQuery.data?.facets?.categories || []) as Array<{ name: string; count: number }>;
    return new Map(rows.map((entry) => [entry.name, entry.count]));
  }, [previousQuery.data]);

  const radarAxes = useMemo(
    () =>
      [...currentCategories]
        .sort((a, b) => b.count - a.count)
        .slice(0, 8)
        .map((entry) => ({ label: entry.name, value: entry.count })),
    [currentCategories],
  );
  const radarCompare = useMemo(
    () => radarAxes.map((axis) => ({ label: axis.label, value: previousCategories.get(axis.label) ?? 0 })),
    [radarAxes, previousCategories],
  );

  const timeline = useMemo(() => {
    const threats = (data?.threat_series || []) as any[];
    const alerts = (data?.alert_series || []) as any[];
    const vulns = (data?.vuln_series || []) as any[];
    return threats.map((entry, index) => ({
      name: entry.name,
      threats: entry.total,
      alerts: alerts[index]?.total ?? 0,
      vulnerabilities: vulns[index]?.count ?? 0,
    }));
  }, [data]);

  const geoPoints = useMemo(
    () =>
      ((data?.geo_activity || []) as Array<{ country: string; code: string; count: number; lat: number; lon: number }>).filter(
        (entry) => typeof entry.lat === "number" && typeof entry.lon === "number",
      ),
    [data],
  );
  const geoTotal = geoPoints.reduce((sum, entry) => sum + entry.count, 0);
  const selectedPoint = geoPoints.find((entry) => entry.code === selectedGeo) || null;

  const sourceRows = (data?.source_reliability || []) as Array<{ name: string; reliability: number; status: string; items: number }>;
  const sourcesOnline = sourceRows.filter((entry) => entry.status === "operational" || entry.status === "degraded").length;

  const ingestionDays = useMemo(() => {
    const logs = (logsQuery.data?.items || []) as any[];
    const map = new Map<string, number>();
    logs.forEach((log) => {
      const date = new Date(log.started_at);
      if (Number.isNaN(date.getTime())) return;
      const key = date.toISOString().slice(0, 10);
      map.set(key, (map.get(key) ?? 0) + (log.items_new ?? 0));
    });
    return Array.from({ length: 14 }).map((_, index) => {
      const date = new Date();
      date.setDate(date.getDate() - (13 - index));
      const key = date.toISOString().slice(0, 10);
      return { name: date.toLocaleDateString("en-GB", { day: "2-digit", month: "short" }), value: map.get(key) ?? 0 };
    });
  }, [logsQuery.data]);

  const recentRuns = ((logsQuery.data?.items || []) as any[]).slice(0, 6);
  const activeAlerts = alertsQuery.data?.active ?? 0;

  const loading = analyticsQuery.isLoading;
  const failed = analyticsQuery.isError;

  return (
    <>
      <PageHeader
        kicker="Monitoring surface · two-sigma activity watch"
        title="Monitoring & anomaly detection"
        description="Interval-by-interval watch over recorded intelligence, alert generation, indicator geography and ingestion health. The anomaly test is a transparent two-sigma comparison against the preceding 14-day baseline — a statistical observation, never an attack confirmation."
        aside={
          data && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">
              <span className="inline-flex items-center gap-1.5 text-ion/85">
                <Signal size={10} /> window computed from stored records
              </span>
              <span>·</span>
              <span>{data.range?.granularity} buckets</span>
              <span>·</span>
              <span>{fmtDate(data.range?.start)} → {fmtDate(data.range?.end)}</span>
              <span>·</span>
              <span>generated {relTime(data.generated_at)}</span>
            </div>
          )
        }
        actions={
          <>
            <FilterSelect label="Category" value={category} onChange={setCategory} options={categoryOptions} className="w-[178px]" />
            <RangeTabs value={range} onChange={setRange} options={[{ value: "24h", label: "24H" }, { value: "7d", label: "7D" }, { value: "30d", label: "30D" }, { value: "90d", label: "90D" }]} />
            <button className="btn btn-ghost btn-sm" onClick={() => analyticsQuery.refetch()} disabled={analyticsQuery.isFetching} aria-label="Refresh monitoring data">
              <RefreshCw size={12} className={clsx(analyticsQuery.isFetching && "animate-spin")} /> Refresh
            </button>
          </>
        }
      />

      {loading && (
        <Panel>
          <LoadingBlock rows={6} label="Loading monitoring window" />
        </Panel>
      )}

      {failed && !loading && (
        <Panel>
          <ErrorState message={(analyticsQuery.error as Error)?.message} retry={() => analyticsQuery.refetch()} />
        </Panel>
      )}

      {data && !failed && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-5">
            <StatBlock
              label="Flagged intervals"
              value={flagged.length}
              detail={`of ${anomalies.length} buckets above +2σ`}
              tone={flagged.length ? "high" : "low"}
            >
              <span className={clsx("shrink-0 font-mono text-[8px] uppercase tracking-[0.12em]", flagged.length ? "text-high" : "text-low")}>
                {flagged.length ? "above +2σ" : "within band"}
              </span>
            </StatBlock>
            <StatBlock label="Baseline mean" value={baseline.toFixed(1)} detail="records per interval · prior 14 days" tone="pulse" />
            <StatBlock
              label="Records observed"
              value={fmtNumber(data.kpis?.new_threats ?? 0)}
              detail={`${data.kpis?.new_vulnerabilities ?? 0} vulnerabilities · ${data.kpis?.new_alerts ?? 0} alerts`}
              tone="ion"
            />
            <StatBlock
              label="Active alerts"
              value={fmtNumber(activeAlerts)}
              detail={`${alertsQuery.data?.critical ?? 0} critical in the open queue`}
              tone={alertsQuery.data?.critical ? "crit" : "violet"}
            />
            <StatBlock
              label="Indicator geography"
              value={fmtNumber(geoTotal)}
              detail={`${geoPoints.length} estimated locations · metadata only`}
              tone="violet"
            />
          </div>

          <div className="grid gap-4 xl:grid-cols-12">
            <Panel ticks className="xl:col-span-7">
              <PanelHead
                title="Activity against baseline"
                kicker="Observed records per interval"
                right={<span className="chip">{flagged.length} flagged</span>}
              />
              <div className="px-4 pb-4 pt-2">
                <ControlChart
                  data={anomalies}
                  selected={selectedBucket}
                  onSelect={(name) => setSelectedBucket((current) => (current === name ? null : name))}
                />
                <p className="mt-2 border-t border-line/70 pt-2.5 text-[10px] leading-relaxed text-dim">
                  Baseline is the preceding 14-day daily mean. The threshold sits two standard deviations above it.
                  Sigma is estimated from the API&apos;s returned z-scores so the band stays reproducible from the same records.
                </p>
              </div>
            </Panel>

            <Panel className="xl:col-span-5">
              <PanelHead
                title="Flagged intervals"
                kicker="Two-sigma exceedances"
                right={<span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{anomalies.length} buckets</span>}
              />
              <div className="max-h-[352px] overflow-y-auto px-3 pb-3">
                {!flagged.length && (
                  <EmptyState
                    icon={<Waves size={18} />}
                    title="No interval crossed the threshold"
                    detail="Every bucket stayed within two standard deviations of the stored baseline for this window."
                  />
                )}
                <div className="space-y-1.5">
                  {flagged
                    .slice()
                    .sort((a, b) => b.z - a.z)
                    .map((entry) => {
                      const active = selectedBucket === entry.name;
                      return (
                        <button
                          key={entry.name}
                          onClick={() => setSelectedBucket((current) => (current === entry.name ? null : entry.name))}
                          className={clsx(
                            "w-full rounded-lg border px-3 py-2.5 text-left transition-colors",
                            active ? "border-ion/45 bg-ion/[0.07]" : "border-line bg-shade/20 hover:border-line-strong",
                          )}
                        >
                          <div className="flex items-center justify-between gap-3">
                            <span className="truncate font-mono text-[9.5px] uppercase tracking-[0.08em] text-mist">{entry.name}</span>
                            <span
                              className={clsx(
                                "tnum shrink-0 rounded-[4px] border px-1.5 py-0.5 font-mono text-[9px]",
                                entry.z >= 3 ? "border-crit/35 bg-crit/8 text-crit" : "border-high/35 bg-high/8 text-high",
                              )}
                            >
                              z {entry.z.toFixed(2)}
                            </span>
                          </div>
                          <div className="mt-2 flex items-center gap-2">
                            <span className="tnum font-display text-[18px] font-semibold leading-none text-ink">{entry.observed}</span>
                            <span className="text-[9.5px] text-dim">records</span>
                            <span className="ml-auto font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">
                              +{Math.max(0, entry.observed - entry.baseline).toFixed(0)} over baseline
                            </span>
                          </div>
                          <div className="mt-2">
                            <MiniBar value={(entry.observed / flaggedPeak) * 100} color={entry.z >= 3 ? "#ff4d5e" : "#ff963d"} />
                          </div>
                        </button>
                      );
                    })}
                </div>
                {flagged.length > 0 && (
                  <p className="mt-3 px-1 text-[9.5px] leading-relaxed text-dim">
                    Select an interval to highlight it on the control chart. A flag means volume exceeded the stored baseline, not that an intrusion occurred.
                  </p>
                )}
              </div>
            </Panel>
          </div>

          <div className="grid gap-4 xl:grid-cols-12">
            <Panel className="xl:col-span-4">
              <PanelHead
                title="Category profile"
                kicker="Current window vs preceding window"
                right={<span className="chip">{radarAxes.length} categories</span>}
              />
              <div className="px-4 pb-4 pt-2">
                <RadarChart
                  axes={radarAxes}
                  compare={radarCompare}
                  height={292}
                  primaryLabel="Current window"
                  compareLabel="Previous window"
                  color="#64d8ff"
                  compareColor="#9a8cff"
                />
                <p className="mt-1 text-[10px] leading-relaxed text-dim">
                  Comparison uses threat categories recorded in the immediately preceding window of equal length. Empty axes mean the category produced no records in that earlier window.
                </p>
              </div>
            </Panel>

            <Panel className="xl:col-span-8">
              <PanelHead
                title="Event timeline"
                kicker="Threat, vulnerability and alert volume by interval"
                right={<span className="chip">{data.range?.granularity}</span>}
              />
              <div className="px-3 pb-4 pt-2">
                <TrendArea
                  data={timeline}
                  height={276}
                  series={[
                    { key: "threats", name: "Threat records", color: "#64d8ff" },
                    { key: "alerts", name: "Alerts generated", color: "#ff963d" },
                    { key: "vulnerabilities", name: "Vulnerabilities", color: "#9a8cff" },
                  ]}
                />
                <div className="mt-2 flex flex-wrap items-center justify-between gap-2 px-1">
                  <ChartLegend
                    items={[
                      { name: "Threats", color: "#64d8ff" },
                      { name: "Alerts", color: "#ff963d" },
                      { name: "Vulnerabilities", color: "#9a8cff" },
                    ]}
                  />
                  <Link to="/app/analytics" className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-ion hover:text-crystal">
                    Full analytics →
                  </Link>
                </div>
              </div>
            </Panel>
          </div>

          <div className="grid gap-4 xl:grid-cols-12">
            <Panel ticks className="xl:col-span-8">
              <PanelHead
                title="Global indicator geography"
                kicker="Estimated location attached to indicator metadata"
                right={<span className="chip">{geoPoints.length} locations</span>}
              />
              <div className="px-3 pb-3 pt-1">
                {geoPoints.length ? (
                  <SignalMap points={geoPoints} height={318} selected={selectedGeo} onSelect={(code) => setSelectedGeo((current) => (current === code ? null : code))} />
                ) : (
                  <EmptyState
                    icon={<Globe2 size={18} />}
                    title="No located indicators in this filter"
                    detail="Indicator records in this window carry no geographic metadata, or the current category filter excludes them."
                  />
                )}
                <div className="mt-1 flex flex-wrap items-center justify-between gap-2 border-t border-line/70 px-1 pt-2.5">
                  <p className="max-w-[70ch] text-[10px] leading-relaxed text-dim">{data.geo_note}</p>
                  {selectedPoint && (
                    <button className="btn btn-quiet btn-sm" onClick={() => setSelectedGeo(null)}>
                      Clear selection
                    </button>
                  )}
                </div>
              </div>
            </Panel>

            <div className="space-y-4 xl:col-span-4">
              <Panel>
                <PanelHead title={selectedPoint ? selectedPoint.country : "Location readout"} kicker={selectedPoint ? "Selected map point" : "Top observed locations"} />
                <div className="px-4 pb-4 pt-1">
                  {selectedPoint ? (
                    <div className="space-y-3">
                      <div className="flex items-end justify-between gap-3">
                        <span className="tnum font-display text-[34px] font-semibold leading-none text-ink">{selectedPoint.count}</span>
                        <span className="font-mono text-[9px] uppercase tracking-[0.1em] text-dim">
                          {geoTotal ? ((selectedPoint.count / geoTotal) * 100).toFixed(1) : "0"}% of located indicators
                        </span>
                      </div>
                      <MiniBar value={geoTotal ? (selectedPoint.count / geoTotal) * 100 : 0} color="#9a8cff" />
                      <div className="rounded-lg border border-violet/20 bg-violet/[0.05] px-3 py-2.5 text-[10.5px] leading-relaxed text-violet">
                        Location metadata does not identify a person, organisation or state actor. Coordinates are rounded estimates supplied with the indicator record.
                      </div>
                    </div>
                  ) : (
                    <HBarList data={geoPoints.slice(0, 7).map((entry) => ({ name: entry.country, value: entry.count }))} color="#9a8cff" />
                  )}
                </div>
              </Panel>

              <Panel>
                <PanelHead title="Alert posture" kicker="Open queue" right={<Link to="/app/alerts" className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-ion">Open →</Link>} />
                <div className="grid grid-cols-3 gap-2 px-4 pb-4 pt-1">
                  {[
                    { label: "Active", value: activeAlerts, tone: "text-ink" },
                    { label: "Critical", value: alertsQuery.data?.critical ?? 0, tone: "text-crit" },
                    { label: "Unassigned", value: alertsQuery.data?.unassigned ?? 0, tone: "text-med" },
                  ].map((entry) => (
                    <div key={entry.label} className="rounded-lg border border-line bg-shade/20 px-2.5 py-2">
                      <div className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">{entry.label}</div>
                      <div className={clsx("tnum mt-1 font-display text-[18px] font-semibold", entry.tone)}>{entry.value}</div>
                    </div>
                  ))}
                </div>
              </Panel>
            </div>
          </div>

          <div className="grid gap-4 xl:grid-cols-12">
            <Panel className="xl:col-span-5">
              <PanelHead
                title="Source health matrix"
                kicker="Reliability, status and recorded volume"
                right={<span className="chip">{sourcesOnline}/{sourceRows.length} reachable</span>}
              />
              <div className="overflow-x-auto px-3 pb-3">
                {!sourceRows.length ? (
                  <EmptyState icon={<DatabaseZap size={18} />} title="No sources registered" detail="Add a connector in Sources & ingestion to begin collecting records." />
                ) : (
                  <table className="table-shell min-w-[380px]">
                    <thead>
                      <tr>
                        <th>Source</th>
                        <th>Status</th>
                        <th>Reliability</th>
                        <th className="text-right">Items</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sourceRows.map((source) => (
                        <tr key={source.name}>
                          <td className="max-w-[150px] truncate text-[11px] text-ink">{source.name}</td>
                          <td><StatusBadge status={source.status} /></td>
                          <td>
                            <div className="flex items-center gap-2">
                              <MiniBar value={source.reliability * 100} color={source.reliability >= 0.8 ? "#42c98a" : source.reliability >= 0.6 ? "#ffd166" : "#ff963d"} />
                              <span className="tnum font-mono text-[9px] text-dim">{(source.reliability * 100).toFixed(0)}%</span>
                            </div>
                          </td>
                          <td className="tnum text-right font-mono text-[10px] text-mist">{fmtNumber(source.items)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                <div className="mt-2 flex items-center justify-between px-1">
                  <span className="text-[9.5px] text-dim">Reliability is the stored source score, not measured accuracy.</span>
                  <Link to="/app/sources" className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-ion">Manage →</Link>
                </div>
              </div>
            </Panel>

            <Panel className="xl:col-span-7">
              <PanelHead
                title="Ingestion activity"
                kicker="New records accepted per day · last 14 days"
                right={<span className="chip">{fmtNumber(ingestionDays.reduce((sum, day) => sum + day.value, 0))} new</span>}
              />
              <div className="px-4 pb-4 pt-2">
                <div className="flex h-[108px] items-end gap-[3px]" role="img" aria-label="New records accepted per day over the last fourteen days">
                  {ingestionDays.map((day) => {
                    const max = Math.max(1, ...ingestionDays.map((entry) => entry.value));
                    return (
                      <div key={day.name} className="group flex h-full flex-1 items-end" title={`${day.name}: ${day.value} new records`}>
                        <div
                          className="w-full rounded-t-[2px] bg-pulse/70 transition-opacity group-hover:bg-ion"
                          style={{ height: `${Math.max(2, (day.value / max) * 100)}%` }}
                        />
                      </div>
                    );
                  })}
                </div>
                <div className="mt-1 flex justify-between font-mono text-[7.5px] uppercase tracking-[0.06em] text-dim">
                  <span>{ingestionDays[0]?.name}</span>
                  <span>{ingestionDays[ingestionDays.length - 1]?.name}</span>
                </div>
                <div className="mt-3 space-y-1.5">
                  {recentRuns.map((log) => (
                    <div key={`${log.source_key}-${log.started_at}`} className="flex items-center gap-2 rounded-md border border-line bg-shade/20 px-2.5 py-1.5">
                      <span className={clsx("h-1.5 w-1.5 shrink-0 rounded-full", log.status === "success" || log.status === "ok" ? "bg-low" : log.status === "error" || log.status === "failed" ? "bg-crit" : "bg-med")} />
                      <span className="min-w-0 flex-1 truncate font-mono text-[9px] uppercase tracking-[0.06em] text-mist">{log.source_key}</span>
                      <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">{titleCase(log.mode)}</span>
                      <span className="tnum font-mono text-[9px] text-ink">+{log.items_new ?? 0}</span>
                      <span className="hidden font-mono text-[8.5px] text-dim sm:block">{relTime(log.started_at)}</span>
                    </div>
                  ))}
                  {!recentRuns.length && <p className="text-[10.5px] text-dim">No ingestion runs recorded yet.</p>}
                </div>
              </div>
            </Panel>
          </div>

          <div className="grid gap-4 xl:grid-cols-12">
            <Panel className="xl:col-span-7 border-ion/15">
              <PanelHead title="Surface boundaries" kicker="What this deployment can and cannot observe" />
              <div className="grid gap-3 px-4 pb-4 pt-1 sm:grid-cols-2">
                <div className="rounded-lg border border-low/20 bg-low/[0.04] px-3.5 py-3">
                  <div className="mb-2 flex items-center gap-1.5 font-mono text-[8.5px] uppercase tracking-[0.14em] text-low">
                    <ShieldCheck size={11} /> Instrumented here
                  </div>
                  <ul className="space-y-1.5 text-[10.5px] leading-relaxed text-mist">
                    <li>Intelligence record velocity per interval</li>
                    <li>Deterministic alert-rule output and workflow state</li>
                    <li>Source status, reliability and ingestion runs</li>
                    <li>Indicator location metadata supplied with records</li>
                  </ul>
                </div>
                <div className="rounded-lg border border-line bg-veil/[0.02] px-3.5 py-3">
                  <div className="mb-2 flex items-center gap-1.5 font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">
                    <CircleSlash size={11} /> Not connected
                  </div>
                  <ul className="space-y-1.5 text-[10.5px] leading-relaxed text-mist">
                    <li>Network packet capture or flow records</li>
                    <li>Endpoint / EDR process telemetry</li>
                    <li>Authentication and sign-in logs</li>
                    <li>DNS, proxy or firewall event streams</li>
                  </ul>
                </div>
              </div>
              <div className="px-4 pb-4">
                <InlineNotice tone="violet" title="No telemetry substitution">
                  Panels on this page never fill gaps with randomised values. Where a telemetry source is absent, the surface states
                  it plainly instead of charting invented logins, packets or requests. Traffic-rate panels live in Advanced analytics,
                  which labels platform activity rather than claiming live network capture.
                </InlineNotice>
              </div>
            </Panel>

            <Panel className="xl:col-span-5">
              <PanelHead title="Next moves" kicker="Operator escalation" right={<ServerCog size={14} className="text-dim" />} />
              <div className="space-y-2 px-4 pb-4 pt-1">
                {[
                  {
                    icon: <TriangleAlert size={14} />,
                    title: "Review flagged intervals",
                    detail: `${flagged.length} bucket(s) exceeded +2σ. Open the alert centre to confirm whether a rule produced corroborating evidence.`,
                    to: "/app/alerts",
                    label: "Open alert centre",
                  },
                  {
                    icon: <Activity size={14} />,
                    title: "Compare category movement",
                    detail: "Cross-check the radar against Advanced analytics before reprioritising collection.",
                    to: "/app/analytics",
                    label: "Open analytics",
                  },
                  {
                    icon: <DatabaseZap size={14} />,
                    title: "Audit ingestion health",
                    detail: `${sourceRows.length - sourcesOnline} source(s) are not currently operational. A failed connector run stores no replacement data.`,
                    to: "/app/sources",
                    label: "Open sources",
                  },
                ].map((action) => (
                  <Link
                    key={action.title}
                    to={action.to}
                    className="group flex items-start gap-3 rounded-lg border border-line bg-shade/20 px-3 py-2.5 transition-colors hover:border-ion/35 hover:bg-ion/[0.03]"
                  >
                    <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-md border border-line bg-veil/[0.03] text-ion">{action.icon}</span>
                    <span className="min-w-0">
                      <span className="block text-[11.5px] text-ink">{action.title}</span>
                      <span className="mt-0.5 block text-[10px] leading-relaxed text-dim">{action.detail}</span>
                      <span className="mt-1.5 inline-block font-mono text-[8.5px] uppercase tracking-[0.12em] text-ion/80 group-hover:text-ion">{action.label} →</span>
                    </span>
                  </Link>
                ))}
              </div>
            </Panel>
          </div>
        </div>
      )}
    </>
  );
}
