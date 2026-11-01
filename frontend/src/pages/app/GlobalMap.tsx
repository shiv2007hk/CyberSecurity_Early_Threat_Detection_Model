import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useReducedMotion } from "framer-motion";
import {
  Activity,
  ArrowUpRight,
  Database,
  Eye,
  EyeOff,
  Globe2,
  Layers3,
  MapPin,
  Maximize2,
  Minimize2,
  Radar,
  RefreshCcw,
  Search,
  ShieldCheck,
  X,
} from "lucide-react";
import clsx from "clsx";
import { api, qs, type Paginated, type Threat } from "../../lib/api";
import { categoryColors, fmtDate, fmtNumber, relTime, riskColor, titleCase } from "../../lib/format";
import {
  aggregateGeography,
  buildThreatTimeline,
  countBy,
  rangeDays,
  threatsWithGeography,
  useThreatWindow,
  type ThreatIndicator,
} from "../../lib/threat-window";
import {
  EmptyState,
  ErrorState,
  InlineNotice,
  Kpi,
  LoadingBlock,
  PageHeader,
  Panel,
  PanelHead,
  RangeTabs,
  SeverityBadge,
} from "../../components/ui";
import { DistributionDonut, HBarList } from "../../components/charts";
import { ThreatGlobe } from "../../components/visuals/ThreatGlobe";
import { DailyBars } from "../../components/analytics-charts";
import { MiniBar, ScoreChip, SectionLabel } from "./shared";

const RANGES = [
  { value: "7d", label: "7D" },
  { value: "30d", label: "30D" },
  { value: "90d", label: "90D" },
];

function MiniStat({ label, value, detail }: { label: string; value: React.ReactNode; detail?: string }) {
  return (
    <div className="rounded-md border border-line bg-shade/25 px-2.5 py-2">
      <div className="font-mono text-[7.6px] uppercase tracking-[0.12em] text-dim">{label}</div>
      <div className="tnum mt-1 font-display text-[17px] font-semibold leading-none text-ink">{value}</div>
      {detail && <div className="mt-1 truncate text-[9px] text-dim">{detail}</div>}
    </div>
  );
}

export default function GlobalMap() {
  const reduceMotion = useReducedMotion();
  const [range, setRange] = useState("90d");
  const [category, setCategory] = useState("all");
  const [country, setCountry] = useState<string | null>(null);
  const [mode, setMode] = useState<"markers" | "density">("markers");
  const [labels, setLabels] = useState(true);
  const [countryQuery, setCountryQuery] = useState("");
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    if (!expanded) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setExpanded(false);
    };
    globalThis.addEventListener("keydown", onKey);
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      globalThis.removeEventListener("keydown", onKey);
      document.body.style.overflow = previous;
    };
  }, [expanded]);

  const window = useThreatWindow(range, category);
  const facetsQuery = useQuery({
    queryKey: ["threat-map-facets", range],
    queryFn: () => api<Paginated<Threat>>(`/threats${qs({ range, size: 1 })}`),
    staleTime: 60_000,
  });

  const items = window.items;
  const geo = useMemo(() => aggregateGeography(items), [items]);
  const selected = country ? geo.find((entry) => entry.code === country) || null : null;
  const geotagged = geo.reduce((sum, entry) => sum + entry.count, 0);
  const recordsWithGeo = useMemo(
    () => new Set(geo.flatMap((entry) => entry.threats.map((threat) => threat.ref))).size,
    [geo],
  );
  const exploitedOrigins = geo.filter((entry) => entry.threats.some((threat: any) => threat.known_exploited)).length;
  const categories = (facetsQuery.data?.facets?.categories || window.facets?.categories || []).filter(
    (entry: any) => entry.count > 0,
  );
  const categoryDonut = useMemo(() => countBy(items, "category").slice(0, 8), [items]);
  const sourceBars = useMemo(() => countBy(items, "source").slice(0, 7), [items]);
  const timeline = useMemo(
    () =>
      buildThreatTimeline(items, range).map((bucket) => ({
        name: fmtDate(bucket.start),
        value: bucket.value,
      })),
    [items, range],
  );
  const bucketDays = rangeDays(range) <= 30 ? 1 : rangeDays(range) <= 90 ? 7 : rangeDays(range) <= 180 ? 14 : 30;

  const rows = useMemo(() => {
    const collected: Array<{ threat: Threat; country: string; code: string; indicator: string; type: string }> = [];
    items.forEach((threat) => {
      const seen = new Set<string>();
      (threat.indicators as ThreatIndicator[] | undefined)?.forEach((indicator) => {
        const location = indicator.geo;
        if (!location?.country || !Number.isFinite(location.lat) || !Number.isFinite(location.lon)) return;
        if (seen.has(location.country)) return;
        seen.add(location.country);
        collected.push({
          threat,
          country: location.country,
          code: location.code || location.country.slice(0, 2).toUpperCase(),
          indicator: indicator.value || "—",
          type: indicator.type || "indicator",
        });
      });
    });
    return collected
      .filter((row) => !country || row.code === country)
      .sort((a, b) => Number(b.threat.risk_score || 0) - Number(a.threat.risk_score || 0));
  }, [items, country]);

  /* Every field below is an aggregate of stored records; the globe adds no
      geography of its own and never invents a location. */
  const mapPoints = useMemo(
    () =>
      geo.map((entry) => ({
        country: entry.country,
        code: entry.code,
        count: entry.count,
        lat: entry.lat,
        lon: entry.lon,
        records: entry.threats.length,
        maxRisk: entry.maxRisk,
        classes: entry.categories.slice(0, 3).map((category) => category.name),
      })),
    [geo],
  );
  const rankingMax = Math.max(1, ...geo.map((entry) => entry.count));
  const selectedAverageRisk = selected?.threats.length
    ? selected.threats.reduce((sum, threat) => sum + Number(threat.risk_score || 0), 0) / selected.threats.length
    : 0;
  const selectedShare = selected ? Math.round((selected.count / Math.max(1, geotagged)) * 100) : 0;
  const filteredGeo = useMemo(() => {
    const needle = countryQuery.trim().toLowerCase();
    if (!needle) return geo;
    return geo.filter((entry) => `${entry.country} ${entry.code}`.toLowerCase().includes(needle));
  }, [geo, countryQuery]);
  const scannedLabel =
    window.total > items.length ? `${fmtNumber(items.length)} of ${fmtNumber(window.total)}` : fmtNumber(items.length);

  return (
    <>
      <PageHeader
        title="Global threat map"
        kicker="Geography · indicator metadata · stored records"
        description="Indicators in stored reports carry a source-supplied location estimate. This map plots those estimates, never performs its own IP geolocation, and never turns a location into an attribution claim."
        aside={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span><span className="text-ink">{geo.length}</span> origin countries</span>
            <span>·</span>
            <span><span className="text-ion">{fmtNumber(geotagged)}</span> geolocated indicators</span>
            <span>·</span>
            <span><span className="text-ink">{fmtNumber(items.length)}</span> records in view</span>
            <span>·</span>
            <span><span className="text-crit">{fmtNumber(exploitedOrigins)}</span> origins with KEV-linked reports</span>
          </div>
        }
        actions={
          <>
            <RangeTabs value={range} onChange={setRange} options={RANGES} />
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => {
                window.refetch();
                facetsQuery.refetch();
              }}
            >
              <RefreshCcw size={13} /> Refresh map
            </button>
          </>
        }
      />

      <div className="mb-4 grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Origin countries" value={fmtNumber(geo.length)} detail="With source-supplied location metadata" icon={<Globe2 size={15} />} tone="low" />
        <Kpi label="Geolocated indicators" value={fmtNumber(geotagged)} detail="Indicator records carrying a location" icon={<MapPin size={15} />} tone="ion" />
        <Kpi label="Records with geography" value={fmtNumber(recordsWithGeo)} detail={`Of ${scannedLabel} reports scanned`} icon={<Database size={15} />} tone="violet" />
        <Kpi label="KEV-linked origins" value={fmtNumber(exploitedOrigins)} detail="Countries with a known-exploited report" icon={<ShieldCheck size={15} />} tone="crit" />
      </div>

      {expanded && <div className="fixed inset-0 z-[80] bg-sunken/80 backdrop-blur-sm" onClick={() => setExpanded(false)} aria-hidden="true" />}

      <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,2.6fr)_minmax(0,1fr)]">
        <Panel
          className={clsx(
            "overflow-hidden",
            expanded && "fixed inset-2 z-[90] flex h-[calc(100dvh-1rem)] min-h-0 flex-col border-line-strong bg-surface/95 shadow-[0_40px_120px_-40px_rgba(0,0,0,0.95)]",
          )}
          ticks
        >
          <PanelHead
            className={expanded ? "hidden" : undefined}
            title="Indicator geography"
            kicker={selected ? `Focused on ${selected.country} · source-supplied metadata` : "Source-supplied location metadata · marker area scales with count"}
            right={<span className="chip">{fmtNumber(geotagged)} location{geotagged === 1 ? "" : "s"}</span>}
          />
          <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2.5">
            <div className="inline-flex rounded-lg border border-line bg-sunken/70 p-0.5" role="group" aria-label="Map rendering mode">
              {[
                { value: "markers" as const, label: "Markers", icon: <MapPin size={11} /> },
                { value: "density" as const, label: "Density", icon: <Radar size={11} /> },
              ].map((option) => (
                <button
                  key={option.value}
                  type="button"
                  aria-pressed={mode === option.value}
                  onClick={() => setMode(option.value)}
                  className={clsx(
                    "inline-flex h-[25px] items-center gap-1.5 rounded-md px-2.5 font-mono text-[8.5px] uppercase tracking-[0.1em] transition-colors",
                    mode === option.value ? "bg-ion/15 text-ion shadow-[inset_0_0_0_1px_rgba(100,216,255,0.24)]" : "text-dim hover:text-mist",
                  )}
                >
                  {option.icon}
                  {option.label}
                </button>
              ))}
            </div>
            <button
              type="button"
              aria-pressed={labels}
              onClick={() => setLabels((value) => !value)}
              className={clsx(
                "btn btn-sm btn-ghost h-[31px] gap-1.5 px-2.5 font-mono text-[8.5px] uppercase tracking-[0.1em]",
                labels && "border-ion/30 text-ion",
              )}
            >
              {labels ? <Eye size={12} /> : <EyeOff size={12} />}
              Labels
            </button>
            <label className="relative ml-auto flex h-[31px] items-center">
              <Search size={12} className="pointer-events-none absolute left-2.5 text-dim" />
              <input
                value={countryQuery}
                onChange={(event) => setCountryQuery(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key !== "Enter") return;
                  const hit = filteredGeo[0];
                  if (hit) setCountry(hit.code);
                }}
                placeholder="Find country"
                aria-label="Search countries in the origin ranking"
                className="field h-[31px] w-[132px] rounded-lg pl-7 pr-2 text-[11px] sm:w-[150px]"
              />
            </label>
            <button
              type="button"
              onClick={() => setExpanded((value) => !value)}
              className="btn btn-sm btn-ghost h-[31px] gap-1.5 px-2.5"
              aria-label={expanded ? "Exit full-screen map" : "Expand map to full screen"}
            >
              {expanded ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
              <span className="hidden sm:inline">{expanded ? "Exit" : "Expand"}</span>
            </button>
            <span className="hidden font-mono text-[8px] uppercase tracking-[0.12em] text-dim xl:block">
              {mode === "markers" ? "Count-scaled markers" : "Count-weighted density"}
            </span>
          </div>
          {categories.length > 0 && !expanded && (
            <div className="flex flex-wrap items-center gap-1.5 border-b border-line px-3 py-2">
              <span className="shrink-0 pr-1 font-mono text-[7.5px] uppercase tracking-[0.16em] text-dim">Class</span>
              <button
                type="button"
                onClick={() => {
                  setCategory("all");
                  setCountry(null);
                }}
                className={clsx(
                  "chip shrink-0 transition-colors",
                  category === "all" ? "border-ion/45 bg-ion/10 text-ion" : "hover:border-line-strong hover:text-mist",
                )}
              >
                All
              </button>
              {categories.map((entry: any) => (
                <button
                  key={entry.name}
                  type="button"
                  onClick={() => {
                    setCategory(entry.name);
                    setCountry(null);
                  }}
                  className={clsx(
                    "chip shrink-0 transition-colors",
                    category === entry.name ? "border-ion/45 bg-ion/10 text-ion" : "hover:border-line-strong hover:text-mist",
                  )}
                >
                  {entry.name}
                  <span className="ml-0.5 text-dim">{entry.count}</span>
                </button>
              ))}
            </div>
          )}
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-line bg-surface/40 px-3 py-2">
            {selected ? (
              <>
                <span className="inline-flex items-center gap-1.5 font-mono text-[8px] uppercase tracking-[0.14em] text-ion">
                  <span className="h-1.5 w-1.5 rounded-full bg-ion shadow-[0_0_6px_rgba(100,216,255,0.7)]" />
                  {selected.code}
                </span>
                <span className="text-[11.5px] font-medium text-ink">{selected.country}</span>
                <span className="font-mono text-[9px] text-dim">
                  {fmtNumber(selected.count)} indicator{selected.count === 1 ? "" : "s"} · {selectedShare}% of mapped · avg risk{" "}
                  <span style={{ color: riskColor(selectedAverageRisk) }}>{selectedAverageRisk.toFixed(1)}</span>
                </span>
                <button
                  type="button"
                  onClick={() => setCountry(null)}
                  className="ml-auto inline-flex items-center gap-1 font-mono text-[8px] uppercase tracking-[0.12em] text-dim transition-colors hover:text-ink"
                >
                  <X size={11} /> Clear
                </button>
              </>
            ) : (
              <>
                <span className="h-1.5 w-1.5 rounded-full bg-ion/50" />
                <span className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">
                  Select a marker or a ranking row to focus a country
                </span>
              </>
            )}
          </div>
          {window.isError ? (
            <div className="p-4">
              <ErrorState compact message={(window.error as any)?.message} retry={() => window.refetch()} />
            </div>
          ) : window.isLoading ? (
            <div className="p-4">
              <LoadingBlock rows={8} label="Loading indicator geography" />
            </div>
          ) : mapPoints.length ? (
            <div className={clsx("relative", expanded && "min-h-0 flex-1")}>
              <ThreatGlobe
                points={mapPoints}
                height={expanded ? "100%" : 500}
                selected={country}
                onSelect={(code) => setCountry((current) => (current === code ? null : code || null))}
                labels={labels}
                mode={mode}
                pulse={!reduceMotion && mode === "markers"}
                reducedMotion={!!reduceMotion}
                className={expanded ? "absolute inset-0" : undefined}
              />

              {expanded && (
                <div className="pointer-events-none absolute right-3 top-3 hidden w-[236px] sm:block xl:hidden">
                  <div className="glass-plate px-3 py-2.5">
                    {selected ? (
                      <>
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-[8px] uppercase tracking-[0.14em] text-ion">{selected.code}</span>
                          <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">focused</span>
                        </div>
                        <div className="mt-0.5 truncate text-[12px] font-medium text-ink">{selected.country}</div>
                        <div className="mt-2 grid grid-cols-3 gap-2">
                          <div>
                            <div className="font-mono text-[7px] uppercase tracking-[0.1em] text-dim">locations</div>
                            <div className="tnum mt-0.5 font-display text-[16px] font-semibold leading-none text-ink">{fmtNumber(selected.count)}</div>
                          </div>
                          <div>
                            <div className="font-mono text-[7px] uppercase tracking-[0.1em] text-dim">records</div>
                            <div className="tnum mt-0.5 font-display text-[16px] font-semibold leading-none text-ink">{fmtNumber(selected.threats.length)}</div>
                          </div>
                          <div>
                            <div className="font-mono text-[7px] uppercase tracking-[0.1em] text-dim">avg risk</div>
                            <div className="tnum mt-0.5 font-display text-[16px] font-semibold leading-none" style={{ color: riskColor(selectedAverageRisk) }}>{selectedAverageRisk.toFixed(1)}</div>
                          </div>
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="font-mono text-[8px] uppercase tracking-[0.14em] text-dim">Geolocated indicators</div>
                        <div className="tnum mt-1 font-display text-[22px] font-semibold leading-none text-ink">{fmtNumber(geotagged)}</div>
                        <div className="mt-1 font-mono text-[7.5px] uppercase tracking-[0.1em] text-dim">
                          {fmtNumber(geo.length)} countries · {fmtNumber(recordsWithGeo)} records
                        </div>
                        <div className="mt-2 border-t border-line pt-1.5 text-[9.5px] leading-relaxed text-dim">Select a marker to focus a country.</div>
                      </>
                    )}
                  </div>
                </div>
              )}

              <div className="pointer-events-none absolute left-3 top-3 hidden md:block">
                <div className="rounded-lg border border-line-strong bg-sunken/80 px-3 py-2 shadow-lift backdrop-blur-md">
                  <div className="font-mono text-[7.5px] uppercase tracking-[0.18em] text-dim">Geolocated indicators</div>
                  <div className="tnum mt-1 font-display text-[24px] font-semibold leading-none text-ink">{fmtNumber(geotagged)}</div>
                  <div className="mt-1 font-mono text-[7.5px] uppercase tracking-[0.12em] text-dim">
                    {fmtNumber(geo.length)} countries · {fmtNumber(recordsWithGeo)} records
                  </div>
                </div>
              </div>

              <div className="pointer-events-none absolute inset-x-0 bottom-0 bg-gradient-to-t from-sunken/95 via-sunken/45 to-transparent px-3 pb-2.5 pt-10">
                <div className="flex flex-wrap items-end justify-between gap-2 pr-[116px]">
                  <div className="pointer-events-auto flex flex-wrap items-center gap-x-3 gap-y-1.5">
                    <span className="inline-flex items-center gap-1.5 font-mono text-[7.5px] uppercase tracking-[0.12em] text-dim">
                      <span className="h-1.5 w-1.5 rounded-full bg-ion shadow-[0_0_6px_rgba(100,216,255,0.7)]" />
                      Marker size = recorded count
                    </span>
                    <span className="hidden items-center gap-1.5 font-mono text-[7.5px] uppercase tracking-[0.12em] text-dim sm:inline-flex">
                      <span className="h-2.5 w-2.5 rounded-full border border-ion/40 bg-ion/10" />
                      Pulse = busiest or critical-band location · presence, not activity
                    </span>
                    <span className="hidden items-center gap-1.5 font-mono text-[7.5px] uppercase tracking-[0.12em] text-dim lg:inline-flex">
                      <span className="h-px w-5 bg-[linear-gradient(90deg,rgb(var(--pulse-rgb)/0.1),rgb(var(--pulse-rgb)),rgb(var(--pulse-rgb)/0.1))]" />
                      Arcs join recorded locations · not attack paths
                    </span>
                    <span className="hidden items-center gap-1.5 font-mono text-[7.5px] uppercase tracking-[0.12em] text-dim xl:inline-flex">
                      <span>1</span>
                      <span className="h-[3px] w-14 rounded-full bg-[linear-gradient(90deg,rgb(var(--pulse-rgb)),rgb(var(--crystal-rgb)))]" />
                      <span>{fmtNumber(rankingMax)}</span>
                      <span>locations / marker</span>
                    </span>
                  </div>
                  <span className="font-mono text-[7.5px] uppercase tracking-[0.12em] text-dim">
                    {country ? `${country} selected · click the marker again to clear` : "Source-supplied location estimates · not attribution"}
                  </span>
                </div>
              </div>

              {expanded && (
                <aside className="absolute inset-y-0 right-0 z-10 hidden w-[300px] flex-col border-l border-line bg-surface/92 backdrop-blur-md xl:flex">
                  <div className="flex items-center justify-between gap-2 border-b border-line px-3.5 py-2.5">
                    <span className="font-mono text-[8px] uppercase tracking-[0.14em] text-dim">Country intelligence</span>
                    {selected && (
                      <button
                        type="button"
                        onClick={() => setCountry(null)}
                        className="inline-flex items-center gap-1 font-mono text-[8px] uppercase tracking-[0.12em] text-dim hover:text-ink"
                      >
                        <X size={10} /> Clear
                      </button>
                    )}
                  </div>
                  {selected ? (
                    <div className="min-h-0 flex-1 overflow-y-auto px-3.5 py-3">
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <div className="font-mono text-[8px] uppercase tracking-[0.12em] text-ion">{selected.code}</div>
                          <div className="mt-0.5 truncate text-[13px] font-semibold text-ink">{selected.country}</div>
                        </div>
                        <span className="chip">{selectedShare}%</span>
                      </div>
                      <div className="mt-2.5 grid grid-cols-2 gap-2">
                        <MiniStat label="Indicators" value={fmtNumber(selected.count)} detail="With this location" />
                        <MiniStat label="Records" value={fmtNumber(selected.threats.length)} detail="Distinct reports" />
                        <MiniStat label="Avg risk" value={selectedAverageRisk.toFixed(1)} />
                        <MiniStat label="Peak risk" value={fmtNumber(selected.maxRisk)} />
                      </div>
                      <div className="mt-3">
                        <SectionLabel>Classes</SectionLabel>
                        <div className="flex flex-wrap gap-1">
                          {selected.categories.slice(0, 4).map((entry) => (
                            <span key={entry.name} className="chip">{entry.name} <span className="ml-1 text-dim">{entry.count}</span></span>
                          ))}
                        </div>
                      </div>
                      <div className="mt-2.5">
                        <SectionLabel>Sources</SectionLabel>
                        <div className="flex flex-wrap gap-1">
                          {selected.sources.slice(0, 3).map((entry) => (
                            <span key={entry.name} className="chip">{entry.name} <span className="ml-1 text-dim">{entry.count}</span></span>
                          ))}
                        </div>
                      </div>
                      <div className="mt-3 border-t border-line pt-2">
                        <SectionLabel right={<span className="chip">{selected.threats.length}</span>}>Top records</SectionLabel>
                        <div className="divide-y divide-veil/[0.05]">
                          {selected.threats.slice(0, 4).map((threat) => (
                            <Link
                              key={threat.id}
                              to={`/app/threats?focus=${encodeURIComponent(threat.ref)}`}
                              className="flex items-start justify-between gap-2 py-1.5 hover:bg-veil/[0.03]"
                            >
                              <div className="min-w-0">
                                <div className="flex items-center gap-1">
                                  <span className="truncate font-mono text-[8px] text-info">{threat.ref}</span>
                                </div>
                                <div className="mt-0.5 truncate text-[10px] text-mist">{threat.name}</div>
                                <div className="mt-0.5 font-mono text-[7.5px] uppercase tracking-[0.06em] text-dim">{threat.category} · {relTime(threat.published_at)}</div>
                              </div>
                              <ScoreChip score={threat.risk_score} />
                            </Link>
                          ))}
                        </div>
                      </div>
                      <p className="mt-3 border-t border-line pt-2 font-mono text-[7.5px] uppercase leading-relaxed tracking-[0.08em] text-dim">
                        Location metadata is not attribution
                      </p>
                    </div>
                  ) : (
                    <div className="px-3.5 py-6 text-[10.5px] leading-relaxed text-dim">
                      Click a marker to inspect its recorded classes, sources and highest-risk reports. Location data comes from
                      the source record; the platform does not geolocate addresses itself.
                    </div>
                  )}
                </aside>
              )}
            </div>
          ) : (
            <EmptyState
              title="No geolocated indicator metadata in this window"
              detail="Reports in this range carry no location metadata, or the selected class has none. The platform does not geolocate IP addresses itself to fill the map."
              icon={<Globe2 size={19} />}
              action={category !== "all" ? <button className="btn btn-ghost btn-sm" onClick={() => setCategory("all")}>Clear class filter</button> : undefined}
            />
          )}
          <div className={clsx("flex flex-wrap items-center justify-between gap-2 border-t border-line px-4 py-2.5 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim", expanded && "hidden")}>
            <span>{fmtNumber(geotagged)} indicator location(s) · {fmtNumber(rows.length)} evidence row(s){country ? ` · ${country}` : ""}</span>
            <span>{country ? `${country} selected` : "no country selected"}</span>
          </div>
        </Panel>

        <div className="grid content-start gap-4">
          <Panel className="overflow-hidden">
            <PanelHead
              title={selected ? selected.country : "Origin ranking"}
              kicker={selected ? `${selected.code} · source-supplied location metadata` : "Share of geolocated indicators"}
              right={
                selected ? (
                  <button className="btn btn-quiet btn-sm" onClick={() => setCountry(null)}>Clear</button>
                ) : (
                  <span className="chip">{filteredGeo.length}/{geo.length} countries</span>
                )
              }
            />
            {selected ? (
              <div className="p-3.5">
                <div className="grid grid-cols-2 gap-2">
                  <MiniStat label="Indicators" value={fmtNumber(selected.count)} detail="With this location" />
                  <MiniStat label="Records" value={fmtNumber(selected.threats.length)} detail="Distinct reports" />
                  <MiniStat label="Avg risk" value={selectedAverageRisk.toFixed(1)} detail="Composite score" />
                  <MiniStat label="Peak risk" value={fmtNumber(selected.maxRisk)} detail="Highest record" />
                </div>

                <div className="mt-3 border-t border-line pt-2.5">
                  <SectionLabel>Classes</SectionLabel>
                  <div className="flex flex-wrap gap-1.5">
                    {selected.categories.slice(0, 6).map((entry) => (
                      <span key={entry.name} className="chip">
                        {entry.name} <span className="ml-1 text-dim">{entry.count}</span>
                      </span>
                    ))}
                  </div>
                </div>
                <div className="mt-2.5">
                  <SectionLabel>Sources</SectionLabel>
                  <div className="flex flex-wrap gap-1.5">
                    {selected.sources.slice(0, 5).map((entry) => (
                      <span key={entry.name} className="chip">
                        {entry.name} <span className="ml-1 text-dim">{entry.count}</span>
                      </span>
                    ))}
                  </div>
                </div>

                <div className="mt-3 border-t border-line pt-2.5">
                  <SectionLabel right={<span className="chip">{selected.threats.length}</span>}>Top records</SectionLabel>
                  <div className="divide-y divide-veil/[0.05]">
                    {selected.threats.slice(0, 3).map((threat) => (
                      <Link
                        key={threat.id}
                        to={`/app/threats?focus=${encodeURIComponent(threat.ref)}`}
                        className="flex items-start justify-between gap-2 py-2 transition-colors hover:bg-veil/[0.025]"
                      >
                        <div className="min-w-0">
                          <div className="flex min-w-0 items-center gap-1.5">
                            <span className="truncate text-[10.5px] text-ink">{threat.name}</span>
                          </div>
                          <div className="mt-0.5 truncate font-mono text-[7.5px] uppercase tracking-[0.06em] text-dim">
                            {threat.category} · {relTime(threat.published_at)}
                          </div>
                        </div>
                        <span className="shrink-0"><ScoreChip score={threat.risk_score} /></span>
                      </Link>
                    ))}
                  </div>
                </div>
                <p className="mt-2.5 border-t border-line pt-2 font-mono text-[7.5px] uppercase leading-relaxed tracking-[0.1em] text-dim">
                  Location metadata is not attribution
                </p>
              </div>
            ) : filteredGeo.length ? (
              <div className="max-h-[420px] divide-y divide-veil/[0.04] overflow-y-auto">
                {filteredGeo.map((entry, index) => {
                  const active = country === entry.code;
                  const share = Math.round((entry.count / Math.max(1, geotagged)) * 100);
                  return (
                    <button
                      key={entry.code}
                      type="button"
                      onClick={() => setCountry((current) => (current === entry.code ? null : entry.code))}
                      className={clsx(
                        "group flex w-full items-center gap-2.5 px-3 py-2.5 text-left transition-colors",
                        active ? "bg-ion/[0.07]" : "hover:bg-veil/[0.03]",
                      )}
                    >
                      <span className={clsx("w-4 shrink-0 font-mono text-[8px]", active ? "text-ion" : "text-dim")}>
                        {String(index + 1).padStart(2, "0")}
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="flex items-baseline justify-between gap-2">
                          <span className="flex min-w-0 items-baseline gap-1.5">
                            <span className="font-mono text-[8px] uppercase tracking-[0.08em] text-dim">{entry.code}</span>
                            <span className={clsx("truncate text-[10.5px]", active ? "text-ink" : "text-ink")}>{entry.country}</span>
                          </span>
                          <span className="tnum shrink-0 font-mono text-[9px] text-dim">{entry.count} · {share}%</span>
                        </span>
                        <span className="mt-1.5 block">
                          <MiniBar value={entry.count} max={rankingMax} color={active ? "#64d8ff" : "#49b8ff"} />
                        </span>
                      </span>
                      <span
                        className="h-1.5 w-1.5 shrink-0 rounded-full"
                        style={{ background: riskColor(entry.maxRisk) }}
                        title={`Peak risk ${entry.maxRisk}`}
                      />
                    </button>
                  );
                })}
              </div>
            ) : (
              <div className="px-4 py-10 text-center">
                <p className="text-[10.5px] text-dim">No country or code matches “{countryQuery}”.</p>
                <button type="button" onClick={() => setCountryQuery("")} className="btn btn-ghost btn-sm mt-3">Clear search</button>
              </div>
            )}
          </Panel>

          <Panel>
            <PanelHead title="By category" kicker="Reports in the current view" right={<span className="chip">{categoryDonut.length}</span>} />
            <div className="p-4">
              {categoryDonut.length ? (
                <DistributionDonut
                  data={categoryDonut}
                  height={158}
                  centerValue={items.length}
                  centerLabel="reports"
                  colors={categoryColors()}
                />
              ) : (
                <p className="py-10 text-center text-[10.5px] text-dim">No reports in this view.</p>
              )}
              <p className="mt-3 border-t border-line pt-2.5 text-[9.5px] leading-relaxed text-dim">
                Category counts describe every report in the filter, not only the reports that carry a location.
              </p>
            </div>
          </Panel>
        </div>
      </div>

      <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
        <Panel>
          <PanelHead
            title="Publication timeline"
            kicker={`${bucketDays === 1 ? "Daily" : `${bucketDays}-day`} buckets · published date`}
            right={<Activity size={14} className="text-dim" />}
          />
          <div className="p-4">
            <DailyBars data={timeline} height={168} color="#49b8ff" emptyLabel="No publication dates in this window." />
            <p className="mt-2.5 border-t border-line pt-2.5 text-[9.5px] leading-relaxed text-dim">
              A flat or empty bucket means no report was published in that interval. It is not evidence that no activity
              occurred. {selected ? `Focused on ${selected.country}.` : "Select a country to inspect its records."}
            </p>
          </div>
        </Panel>
        <Panel>
          <PanelHead title="Source coverage" kicker="Reports contributing to this view" right={<span className="chip">{sourceBars.length}</span>} />
          <div className="p-4">
            {sourceBars.length ? (
              <HBarList data={sourceBars} color="#9a8cff" />
            ) : (
              <p className="py-8 text-center text-[10.5px] text-dim">No source attribution in this view.</p>
            )}
            <p className="mt-3 border-t border-line pt-2.5 font-mono text-[7.5px] uppercase leading-relaxed tracking-[0.1em] text-dim">
              Source attribution as recorded · no live synchronisation implied
            </p>
          </div>
        </Panel>
      </div>

      <Panel className="mb-4" ticks>
        <PanelHead
          title="Reading this map"
          kicker="What the data can and cannot support"
          right={<span className="chip text-violet">evidence limits</span>}
        />
        <div className="grid grid-cols-1 gap-3 p-4 lg:grid-cols-2">
          <InlineNotice tone="med" title="Location is not attribution">
            Marker positions come from location metadata attached to indicators by the source. An IP address estimate does
            not identify an attacker, an operator or a sponsoring state, and this map must not be read as one.
          </InlineNotice>
          <InlineNotice tone="ion" title="No live lookup, no filling in gaps">
            The console never geolocates addresses itself and never infers a point for a missing one.
            Reports without usable metadata are excluded from the map and remain visible in the evidence table only when
            they carry a location.
          </InlineNotice>
        </div>
        <div className="grid grid-cols-1 gap-px border-t border-line bg-line sm:grid-cols-3">
          {[
            { label: "Reports scanned", value: `${scannedLabel} reports`, detail: window.total > items.length ? "200-record ceiling applies" : "Full selected window" },
            { label: "With geography", value: `${recordsWithGeo} records`, detail: `${geotagged} indicator locations` },
            { label: "Known exploited", value: `${items.filter((t: any) => t.known_exploited).length} records`, detail: "Reports linked to a KEV entry" },
          ].map((entry) => (
            <div key={entry.label} className="bg-surface px-4 py-3">
              <div className="font-mono text-[8px] uppercase tracking-[0.14em] text-dim">{entry.label}</div>
              <div className="mt-1 text-[12px] text-ink">{entry.value}</div>
              <div className="mt-0.5 text-[9.5px] text-dim">{entry.detail}</div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel>
        <PanelHead
          title="Geolocated evidence"
          kicker="Stored indicators with location metadata, highest risk first"
          right={<span className="chip">{rows.length} row(s)</span>}
        />
        {window.isError ? (
          <ErrorState message={(window.error as any)?.message} retry={() => window.refetch()} />
        ) : rows.length ? (
          <>
            <div className="overflow-x-auto">
              <table className="table-shell">
                <thead>
                  <tr>
                    <th>Origin</th>
                    <th>Indicator</th>
                    <th className="hidden sm:table-cell">Class</th>
                    <th>Risk</th>
                    <th className="hidden md:table-cell">Severity</th>
                    <th className="hidden lg:table-cell">Source</th>
                    <th className="hidden lg:table-cell">Published</th>
                    <th aria-label="Open record" />
                  </tr>
                </thead>
                <tbody>
                  {rows.slice(0, 12).map((row) => (
                    <tr key={`${row.threat.id}-${row.code}`}>
                      <td>
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-[8px] uppercase tracking-[0.08em] text-ion">{row.code}</span>
                          <span className="truncate text-[10.5px] text-mist">{row.country}</span>
                        </div>
                      </td>
                      <td className="max-w-[240px]">
                        <div className="truncate font-mono text-[9.5px] text-ink">{row.indicator}</div>
                        <div className="font-mono text-[7.5px] uppercase tracking-[0.08em] text-dim">{titleCase(row.type)}</div>
                      </td>
                      <td className="hidden sm:table-cell">
                        <span className="text-[10px] text-mist">{row.threat.category}</span>
                      </td>
                      <td><ScoreChip score={row.threat.risk_score} /></td>
                      <td className="hidden md:table-cell"><SeverityBadge severity={row.threat.severity} /></td>
                      <td className="hidden lg:table-cell"><span className="text-[10px] text-mist">{row.threat.source}</span></td>
                      <td className="hidden lg:table-cell">
                        <span className="font-mono text-[9px] text-dim">{relTime(row.threat.published_at)}</span>
                      </td>
                      <td>
                        <Link
                          to={`/app/threats?focus=${encodeURIComponent(row.threat.ref)}`}
                          aria-label={`Open ${row.threat.ref}`}
                          className="inline-flex text-dim transition-colors hover:text-ion"
                        >
                          <ArrowUpRight size={13} />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-4 py-2.5 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
              <span>showing {Math.min(rows.length, 12)} of {rows.length} geolocated row(s)</span>
              <span>{threatsWithGeography(items).length} record(s) carry usable location metadata</span>
            </div>
          </>
        ) : (
          <EmptyState
            title="No geolocated evidence in this view"
            detail="No stored indicator carries usable latitude and longitude for the current filter. Nothing is inferred or substituted."
            icon={<Globe2 size={19} />}
          />
        )}
      </Panel>

      <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-3">
        {[
          { label: "Map source", value: "Stored indicator metadata", icon: <Layers3 size={13} /> },
          { label: "Lookup policy", value: "No client or server geolocation call", icon: <ShieldCheck size={13} /> },
          { label: "Attribution", value: "Not asserted from an IP location", icon: <Globe2 size={13} /> },
        ].map((entry) => (
          <div key={entry.label} className="panel-quiet flex items-center gap-2.5 px-3.5 py-2.5">
            <span className="grid h-7 w-7 place-items-center rounded-md border border-line bg-shade/25 text-dim">{entry.icon}</span>
            <div className="min-w-0">
              <div className="font-mono text-[7.8px] uppercase tracking-[0.12em] text-dim">{entry.label}</div>
              <div className="truncate text-[10.5px] text-mist">{entry.value}</div>
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
