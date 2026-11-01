import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowRight,
  BookmarkPlus,
  FlaskConical,
  Gauge,
  Info,
  RotateCcw,
  Scale,
  SlidersHorizontal,
  Trash2,
} from "lucide-react";
import clsx from "clsx";
import { api, qs } from "../../lib/api";
import { fmtDate, riskColor, titleCase } from "../../lib/format";
import { tone as themeTone } from "../../lib/theme";
import {
  EmptyState,
  ErrorState,
  InlineNotice,
  LoadingBlock,
  PageHeader,
  Panel,
  PanelHead,
} from "../../components/ui";
import { Waterfall } from "../../components/analytics-charts";
import { FilterSelect, MiniBar, SectionLabel } from "./shared";

const FACTOR_ORDER = ["severity", "exploitability", "exposure", "asset_criticality", "evidence_strength"] as const;
type FactorKey = (typeof FACTOR_ORDER)[number];

const FACTOR_TONE: Record<FactorKey, string> = {
  severity: "#ff963d",
  exploitability: "#ff4d5e",
  exposure: "#9a8cff",
  asset_criticality: "#49b8ff",
  evidence_strength: "#64d8ff",
};

const FACTOR_SHORT: Record<FactorKey, string> = {
  severity: "Severity",
  exploitability: "Exploitability",
  exposure: "Exposure",
  asset_criticality: "Criticality",
  evidence_strength: "Evidence",
};

const PRESETS: Array<{ key: string; label: string; hint: string }> = [
  { key: "recorded", label: "As recorded", hint: "API factor values" },
  { key: "internet", label: "Internet-facing", hint: "Exposure 9.5 / 10" },
  { key: "airgapped", label: "Air-gapped", hint: "Exposure 1.5 / 10" },
  { key: "tier0", label: "Tier-0 asset", hint: "Criticality 10 / 10" },
  { key: "patched", label: "Patch applied", hint: "Exploitability 0 / 10 assumption" },
];

type Thresholds = { medium: number; high: number; critical: number };
type Values = Record<FactorKey, number>;

function clamp(value: number, min = 0, max = 10) {
  return Math.max(min, Math.min(max, value));
}

function bandFor(score: number, thresholds: Thresholds) {
  if (score >= thresholds.critical) return "Critical";
  if (score >= thresholds.high) return "High";
  if (score >= thresholds.medium) return "Medium";
  return "Low";
}

function ScoreDial({ score, category, size = 158 }: { score: number; category: string; size?: number }) {
  const radius = size / 2 - 11;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - clamp(score, 0, 100) / 100);
  const color = riskColor(score);
  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90" role="img" aria-label={`${category} risk score ${score.toFixed(1)} of 100`}>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgb(var(--line-rgb) / 0.16)" strokeWidth="6" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 600ms cubic-bezier(0.16,1,0.3,1), stroke 300ms" }}
        />
        {[25, 50, 75].map((tick) => {
          const angle = (tick / 100) * Math.PI * 2;
          const inner = radius - 8;
          const outer = radius + 8;
          const cx = size / 2;
          const cy = size / 2;
          return (
            <line
              key={tick}
              x1={cx + Math.cos(angle) * inner}
              y1={cy + Math.sin(angle) * inner}
              x2={cx + Math.cos(angle) * outer}
              y2={cy + Math.sin(angle) * outer}
              stroke="rgb(var(--line-rgb) / 0.3)"
              strokeWidth="1"
            />
          );
        })}
      </svg>
      <div className="absolute text-center">
        <div className="tnum font-display text-[34px] font-semibold leading-none text-ink">{score.toFixed(1)}</div>
        <div className="mt-1.5 font-mono text-[8.5px] uppercase tracking-[0.18em]" style={{ color }}>{category}</div>
      </div>
    </div>
  );
}

function BandTrack({ score, thresholds }: { score: number; thresholds: Thresholds }) {
  const segments = [
    { width: thresholds.medium, color: themeTone("#42c98a") },
    { width: thresholds.high - thresholds.medium, color: themeTone("#ffd166") },
    { width: thresholds.critical - thresholds.high, color: themeTone("#ff963d") },
    { width: 100 - thresholds.critical, color: themeTone("#ff4d5e") },
  ];
  return (
    <div>
      <div className="relative h-[7px] w-full overflow-hidden rounded-full">
        <div className="flex h-full w-full opacity-40">
          {segments.map((segment, index) => (
            <span key={index} style={{ width: `${segment.width}%`, background: segment.color }} />
          ))}
        </div>
        <span
          className="absolute top-1/2 h-[11px] w-[3px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-ink shadow-[0_0_8px_rgb(var(--ink-rgb)/0.8)]"
          style={{ left: `${clamp(score, 0, 100)}%`, transition: "left 500ms cubic-bezier(0.16,1,0.3,1)" }}
        />
      </div>
      <div className="relative mt-1 h-3 font-mono text-[7.5px] text-dim">
        <span className="absolute -translate-x-1/2" style={{ left: `${thresholds.medium}%` }}>{thresholds.medium}</span>
        <span className="absolute -translate-x-1/2" style={{ left: `${thresholds.high}%` }}>{thresholds.high}</span>
        <span className="absolute -translate-x-1/2" style={{ left: `${thresholds.critical}%` }}>{thresholds.critical}</span>
      </div>
    </div>
  );
}

export default function Simulator() {
  const [threatRef, setThreatRef] = useState<string | null>(null);
  const [assetId, setAssetId] = useState("none");
  const [values, setValues] = useState<Values | null>(null);
  const [scenario, setScenario] = useState("recorded");
  const [pinned, setPinned] = useState<Array<{ id: number; label: string; score: number; category: string; context: string }>>([]);

  const threatsQuery = useQuery({
    queryKey: ["sim-threats"],
    queryFn: () => api<any>(`/threats${qs({ range: "365d", size: 100, sort_by: "risk_score", order: "desc" })}`),
    staleTime: 120_000,
  });
  const assetsQuery = useQuery({
    queryKey: ["sim-assets"],
    queryFn: () => api<any>(`/assets${qs({ size: 100 })}`),
    staleTime: 120_000,
  });
  const configQuery = useQuery({
    queryKey: ["risk-config"],
    queryFn: () => api<any>("/risk/config"),
    staleTime: 120_000,
  });

  const threatItems = (threatsQuery.data?.items || []) as any[];
  const activeRef = threatRef || threatItems[0]?.ref || "";
  const detailQuery = useQuery({
    queryKey: ["sim-detail", activeRef],
    enabled: !!activeRef,
    queryFn: () => api<any>(`/threats/${activeRef}`),
    staleTime: 60_000,
  });

  const assetItems = (assetsQuery.data?.items || []) as any[];
  const asset = assetItems.find((item) => String(item.id) === assetId) || null;
  const detail = detailQuery.data;
  const breakdown = detail?.risk_breakdown;
  const weights: Record<FactorKey, number> = configQuery.data?.weights || {
    severity: 0.25,
    exploitability: 0.2,
    exposure: 0.2,
    asset_criticality: 0.2,
    evidence_strength: 0.15,
  };
  const thresholds: Thresholds = configQuery.data?.thresholds || { medium: 25, high: 50, critical: 75 };

  const baseValues = useMemo<Values | null>(() => {
    if (!breakdown?.components) return null;
    const next = {} as Values;
    FACTOR_ORDER.forEach((key) => {
      next[key] = Number(breakdown.components[key]?.value ?? 0);
    });
    return next;
  }, [breakdown]);

  const assetExposure = asset ? (asset.internet_facing || asset.exposure === "internet-facing" ? 9.5 : asset.exposure === "air-gapped" ? 1.5 : 5.0) : 5.0;
  const assetCriticality = asset ? clamp((asset.criticality ?? 3) * 2) : 5.0;

  const recordedValues = useMemo<Values | null>(() => {
    if (!baseValues) return null;
    return { ...baseValues, exposure: assetExposure, asset_criticality: assetCriticality };
  }, [baseValues, assetExposure, assetCriticality]);

  useEffect(() => {
    if (!recordedValues) return;
    setValues(recordedValues);
    setScenario("recorded");
    // Reset only when the selected threat or asset changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detail?.threat?.ref, assetId, recordedValues ? JSON.stringify(recordedValues) : ""]);

  const baselineScore = Number(breakdown?.risk_score ?? 0);
  const projectedScore = useMemo(() => {
    if (!values) return 0;
    const total = FACTOR_ORDER.reduce((sum, key) => sum + weights[key] * values[key], 0);
    return Math.round(Math.max(0, Math.min(100, 10 * total)) * 10) / 10;
  }, [values, weights]);
  const projectedCategory = bandFor(projectedScore, thresholds);
  const delta = Math.round((projectedScore - baselineScore) * 10) / 10;
  const scoreColor = riskColor(projectedScore);

  const contributions = useMemo(
    () =>
      FACTOR_ORDER.map((key) => ({
        key,
        label: FACTOR_SHORT[key],
        value: values?.[key] ?? 0,
        weight: weights[key],
        contribution: Math.round((values?.[key] ?? 0) * weights[key] * 10 * 10) / 10,
        baseContribution: Math.round((baseValues?.[key] ?? 0) * weights[key] * 10 * 10) / 10,
      })),
    [values, weights, baseValues],
  );

  const applyPreset = (key: string) => {
    if (!recordedValues) return;
    const next: Values = { ...recordedValues };
    if (key === "internet") next.exposure = 9.5;
    if (key === "airgapped") next.exposure = 1.5;
    if (key === "tier0") next.asset_criticality = 10;
    if (key === "patched") next.exploitability = 0;
    setValues(next);
    setScenario(key);
  };

  const updateFactor = (key: FactorKey, value: number) => {
    setValues((current) => (current ? { ...current, [key]: value } : current));
    setScenario("custom");
  };

  const pinScenario = () => {
    const presetLabel = PRESETS.find((preset) => preset.key === scenario)?.label || "Custom mix";
    setPinned((current) => [
      ...current.slice(-2),
      {
        id: Date.now(),
        label: presetLabel,
        score: projectedScore,
        category: projectedCategory,
        context: `${detail?.threat?.ref || "—"}${asset ? ` · ${asset.ref}` : " · no asset"}`,
      },
    ]);
  };

  const loading = threatsQuery.isLoading || configQuery.isLoading;
  const failed = threatsQuery.isError || configQuery.isError;

  const resetProjection = () => {
    if (recordedValues) {
      setValues(recordedValues);
      setScenario("recorded");
    }
  };

  return (
    <>
      <PageHeader
        kicker="Projection lab · session-only, never written back"
        title="What-if risk & attack simulator"
        description="Recompute the published multi-factor risk score under controlled assumptions. Factor values come from the API's own breakdown; the projection applies the configured weights and thresholds in the browser. No scenario is persisted, and none is a prediction of compromise."
        aside={
          breakdown && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">
              <span className="text-violet">{breakdown.model_version}</span>
              <span>·</span>
              <span>weights {FACTOR_ORDER.map((key) => `${FACTOR_SHORT[key].toLowerCase()} ${(weights[key] * 100).toFixed(0)}%`).join(" / ")}</span>
            </div>
          )
        }
        actions={
          <>
            <button className="btn btn-ghost btn-sm" onClick={resetProjection} disabled={!recordedValues}>
              <RotateCcw size={12} /> Reset
            </button>
            <button className="btn btn-primary btn-sm" onClick={pinScenario} disabled={!values}>
              <BookmarkPlus size={12} /> Pin scenario
            </button>
          </>
        }
      />

      {loading && (
        <Panel>
          <LoadingBlock rows={6} label="Loading simulator inputs" />
        </Panel>
      )}

      {failed && !loading && (
        <Panel>
          <ErrorState
            message={(threatsQuery.error as Error)?.message || (configQuery.error as Error)?.message}
            retry={() => {
              threatsQuery.refetch();
              configQuery.refetch();
            }}
          />
        </Panel>
      )}

      {!loading && !failed && (
        <div className="space-y-4">
          <Panel ticks>
            <PanelHead title="Scenario inputs" kicker="Record, inventory and assumption" right={<FlaskConical size={14} className="text-violet" />} />
            <div className="grid gap-3 px-4 pb-4 pt-1 lg:grid-cols-12">
              <FilterSelect
                label="Threat record"
                value={activeRef}
                onChange={(value) => setThreatRef(value)}
                options={threatItems.map((item) => ({
                  value: item.ref,
                  label: `${item.ref} · ${String(item.name).slice(0, 54)} (${Number(item.risk_score ?? 0).toFixed(0)})`,
                }))}
                className="lg:col-span-5"
              />
              <FilterSelect
                label="Linked asset"
                value={assetId}
                onChange={setAssetId}
                options={[
                  { value: "none", label: "No asset · generic profile" },
                  ...assetItems.map((item) => ({
                    value: String(item.id),
                    label: `${item.ref} · ${String(item.name).slice(0, 40)} · ${titleCase(item.exposure)}`,
                  })),
                ]}
                className="lg:col-span-4"
              />
              <div className="lg:col-span-3">
                <SectionLabel>Evidence</SectionLabel>
                <div className="flex flex-wrap gap-1.5">
                  {detail?.threat && <span className="chip">{detail.threat.cve_id || detail.threat.ref}</span>}
                  <span className="chip">{detail?.threat?.known_exploited ? "KEV evidence" : "No KEV flag"}</span>
                  <span className="chip">{detail?.threat?.epss_score != null ? `EPSS ${(Number(detail.threat.epss_score) * 100).toFixed(1)}%` : "No EPSS"}</span>
                </div>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 border-t border-line px-4 py-3">
              <span className="mr-1 font-mono text-[8px] uppercase tracking-[0.16em] text-dim">Presets</span>
              {PRESETS.map((preset) => (
                <button
                  key={preset.key}
                  onClick={() => applyPreset(preset.key)}
                  title={preset.hint}
                  className={clsx(
                    "rounded-md border px-2.5 py-1.5 font-mono text-[9px] uppercase tracking-[0.08em] transition-colors",
                    scenario === preset.key
                      ? "border-ion/50 bg-ion/[0.1] text-ion"
                      : "border-line bg-shade/20 text-mist hover:border-line-strong hover:text-ink",
                  )}
                >
                  {preset.label}
                </button>
              ))}
              {scenario === "custom" && <span className="rounded-md border border-violet/40 bg-violet/[0.08] px-2.5 py-1.5 font-mono text-[9px] uppercase tracking-[0.08em] text-violet">Custom mix</span>}
            </div>
          </Panel>

          {!detail?.threat && !detailQuery.isLoading && (
            <Panel>
              <EmptyState
                icon={<FlaskConical size={18} />}
                title="Select a threat record"
                detail="The simulator needs a recorded threat to derive its five factor values."
              />
            </Panel>
          )}

          {detail?.threat && values && (
            <>
              <div className="grid gap-4 xl:grid-cols-12">
                <Panel className="xl:col-span-5">
                  <PanelHead
                    title="Score movement"
                    kicker="Recorded baseline vs projection"
                    right={<span className="chip">{asset ? asset.ref : "no asset linked"}</span>}
                  />
                  <div className="px-4 pb-4 pt-2">
                    <div className="mb-4 min-w-0">
                      <span className="font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">Threat under test</span>
                      <div className="mt-1 truncate text-[13px] font-medium text-ink">{detail.threat.name}</div>
                      <div className="mt-0.5 font-mono text-[9px] uppercase tracking-[0.08em] text-dim">
                        {detail.threat.ref} · {detail.threat.category} · {fmtDate(detail.threat.published_at)} · {detail.threat.source}
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <div className="rounded-xl border border-line bg-shade/20 px-3 py-3">
                        <div className="flex items-center justify-between font-mono text-[8px] uppercase tracking-[0.14em] text-dim">
                          <span>Recorded</span>
                          <span>{breakdown?.risk_category}</span>
                        </div>
                        <div className="mt-2 flex justify-center">
                          <ScoreDial score={baselineScore} category={breakdown?.risk_category || bandFor(baselineScore, thresholds)} size={132} />
                        </div>
                      </div>
                      <div className="relative rounded-xl border px-3 py-3" style={{ borderColor: `${scoreColor}55`, background: `${scoreColor}0a` }}>
                        <ArrowRight size={13} className="absolute -left-[15px] top-1/2 hidden -translate-y-1/2 text-dim sm:block" />
                        <div className="flex items-center justify-between font-mono text-[8px] uppercase tracking-[0.14em] text-dim">
                          <span>Projected</span>
                          <span style={{ color: scoreColor }}>{projectedCategory}</span>
                        </div>
                        <div className="mt-2 flex justify-center">
                          <ScoreDial score={projectedScore} category={projectedCategory} size={132} />
                        </div>
                      </div>
                    </div>
                    <div className="mt-3">
                      <BandTrack score={projectedScore} thresholds={thresholds} />
                    </div>
                    <div className="mt-3 flex items-center justify-between gap-3 rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                      <span className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">Movement</span>
                      <span className="tnum font-display text-[20px] font-semibold" style={{ color: themeTone(delta > 0 ? "#ff4d5e" : delta < 0 ? "#42c98a" : "#a9c1d8") }}>
                        {delta > 0 ? "+" : ""}{delta.toFixed(1)} <span className="font-mono text-[9px] uppercase tracking-[0.1em] text-dim">pts</span>
                      </span>
                    </div>
                    {asset && (
                      <div className="mt-3 rounded-lg border border-violet/20 bg-violet/[0.05] px-3 py-2.5">
                        <div className="flex items-center justify-between gap-2 font-mono text-[8px] uppercase tracking-[0.12em] text-violet">
                          <span>{asset.ref} · {asset.category}</span>
                          <Link to={`/app/assets?focus=${asset.ref}`} className="text-ion/80 hover:text-ion">Inventory →</Link>
                        </div>
                        <p className="mt-1 text-[10px] leading-relaxed text-mist">
                          {asset.name} · exposure {titleCase(asset.exposure)} · criticality {asset.criticality}/5. These two recorded attributes drive the inventory factors below.
                        </p>
                      </div>
                    )}
                  </div>
                </Panel>

                <Panel className="xl:col-span-7">
                  <PanelHead
                    title="Factor console"
                    kicker="Normalised 0–10 · weights from risk model configuration"
                    right={<SlidersHorizontal size={14} className="text-dim" />}
                  />
                  <div className="space-y-4 px-4 pb-4 pt-2">
                    {FACTOR_ORDER.map((key) => {
                      const factor = breakdown?.factors?.find((entry: any) => entry.key === key);
                      const contribution = contributions.find((entry) => entry.key === key)!;
                      return (
                        <div key={key} className="min-w-0 rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                          <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                            <div className="min-w-0">
                              <div className="text-[11.5px] text-ink">{factor?.label || FACTOR_SHORT[key]}</div>
                              <div className="mt-0.5 truncate font-mono text-[8.5px] uppercase tracking-[0.06em] text-dim" title={factor?.note}>
                                {factor?.note || "Component supplied by the risk engine"}
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="tnum font-mono text-[11px]" style={{ color: themeTone(FACTOR_TONE[key]) }}>{values[key].toFixed(1)}</span>
                              <span className="font-mono text-[8px] uppercase tracking-[0.08em] text-dim">× {(weights[key] * 100).toFixed(0)}% = {contribution.contribution.toFixed(1)} pts</span>
                            </div>
                          </div>
                          <div className="mt-2 flex items-center gap-3">
                            <span className="w-4 shrink-0 text-right font-mono text-[8px] text-dim">0</span>
                            <input
                              type="range"
                              min={0}
                              max={10}
                              step={0.1}
                              value={values[key]}
                              onChange={(event) => updateFactor(key, Number(event.target.value))}
                              className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-veil/[0.08] accent-ion"
                              style={{ accentColor: themeTone(FACTOR_TONE[key]) }}
                              aria-label={`${FACTOR_SHORT[key]} normalised value`}
                            />
                            <span className="w-4 shrink-0 font-mono text-[8px] text-dim">10</span>
                          </div>
                        </div>
                      );
                    })}
                    <p className="text-[9.5px] leading-relaxed text-dim">
                      Moving a factor changes only this projection. Changing the model itself requires the administrator risk
                      configuration, which rescoring applies to stored records.
                    </p>
                  </div>
                </Panel>
              </div>

              <div className="grid gap-4 xl:grid-cols-12">
                <Panel ticks className="xl:col-span-7">
                  <PanelHead title="Projected contribution waterfall" kicker="Weight × normalised factor × 10" right={<span className="chip">{projectedScore.toFixed(1)} / 100</span>} />
                  <div className="px-3 pb-3 pt-2">
                    <Waterfall
                      items={contributions.map((entry) => ({
                        label: entry.label,
                        value: entry.contribution,
                        color: themeTone(FACTOR_TONE[entry.key as FactorKey]),
                        note: `${entry.value.toFixed(1)} × ${(entry.weight * 100).toFixed(0)}%`,
                      }))}
                      total={projectedScore}
                      height={286}
                    />
                  </div>
                </Panel>

                <Panel className="xl:col-span-5">
                  <PanelHead title="Delta bridge" kicker="Contribution change against the recorded record" right={<Scale size={14} className="text-dim" />} />
                  <div className="space-y-1.5 px-3 pb-4 pt-1">
                    {contributions.map((entry) => {
                      const difference = Math.round((entry.contribution - entry.baseContribution) * 10) / 10;
                      const deltaTone = themeTone(difference > 0 ? "#ff4d5e" : difference < 0 ? "#42c98a" : "#6f8aa4");
                      return (
                        <div key={entry.key} className="rounded-md border border-line bg-shade/20 px-2.5 py-2">
                          <div className="flex items-center justify-between gap-3">
                            <span className="inline-flex min-w-0 items-center gap-1.5 text-[10.5px] text-mist">
                              <span className="h-1.5 w-1.5 shrink-0 rounded-sm" style={{ background: themeTone(FACTOR_TONE[entry.key as FactorKey]) }} />
                              <span className="truncate">{entry.label}</span>
                            </span>
                            <span className="tnum shrink-0 font-mono text-[9.5px]" style={{ color: deltaTone }}>
                              {difference > 0 ? "+" : ""}{difference.toFixed(1)} pts
                            </span>
                          </div>
                          <div className="mt-1.5 flex items-center gap-2 font-mono text-[8.5px] text-dim">
                            <span>{entry.baseContribution.toFixed(1)}</span>
                            <ArrowRight size={9} />
                            <span className="text-ink">{entry.contribution.toFixed(1)}</span>
                            <span className="ml-auto uppercase tracking-[0.08em]">{((entry.value / 10) * 100).toFixed(0)}% of scale</span>
                          </div>
                        </div>
                      );
                    })}
                    <div className="rounded-lg border border-line-strong bg-ion/[0.03] px-3 py-2.5">
                      <div className="flex items-baseline justify-between">
                        <span className="font-mono text-[8px] uppercase tracking-[0.14em] text-dim">Total movement</span>
                        <span className="tnum font-display text-[20px] font-semibold" style={{ color: themeTone(delta > 0 ? "#ff4d5e" : delta < 0 ? "#42c98a" : "#a9c1d8") }}>
                          {delta > 0 ? "+" : ""}{delta.toFixed(1)}
                        </span>
                      </div>
                      <MiniBar value={projectedScore} color={scoreColor} />
                    </div>
                  </div>
                </Panel>
              </div>

              <div className="grid gap-4 xl:grid-cols-12">
                <Panel className="xl:col-span-7">
                  <PanelHead
                    title="Scenario comparison"
                    kicker="Pinned this session · not saved"
                    right={
                      pinned.length ? (
                        <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{pinned.length} / 3 pinned</span>
                      ) : undefined
                    }
                  />
                  <div className="px-4 pb-4 pt-2">
                    {!pinned.length && (
                      <div className="rounded-lg border border-dashed border-line px-4 py-8 text-center">
                        <Gauge size={20} className="mx-auto text-dim" />
                        <p className="mt-2 text-[11.5px] text-mist">Pin a projection to compare it against other assumptions.</p>
                        <p className="mt-1 text-[10px] leading-relaxed text-dim">
                          Pins stay in this browser session only. Reloading clears them, and nothing is written to the assessment record.
                        </p>
                      </div>
                    )}
                    <div className="space-y-2">
                      {pinned.map((entry) => (
                        <div key={entry.id} className="flex items-center gap-3 rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                          <div className="min-w-0 flex-1">
                            <div className="flex items-baseline justify-between gap-2">
                              <span className="truncate text-[11.5px] text-ink">{entry.label}</span>
                              <span className="tnum font-mono text-[11px]" style={{ color: riskColor(entry.score) }}>{entry.score.toFixed(1)}</span>
                            </div>
                            <div className="mt-1"><MiniBar value={entry.score} color={riskColor(entry.score)} /></div>
                            <div className="mt-1 font-mono text-[8px] uppercase tracking-[0.08em] text-dim">{entry.context} · {entry.category}</div>
                          </div>
                          <button
                            className="btn btn-quiet btn-icon btn-sm shrink-0"
                            onClick={() => setPinned((current) => current.filter((item) => item.id !== entry.id))}
                            aria-label={`Remove pinned scenario ${entry.label}`}
                          >
                            <Trash2 size={12} />
                          </button>
                        </div>
                      ))}
                      {pinned.length > 0 && (
                        <div className="flex items-center justify-between rounded-lg border border-line px-3 py-2 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
                          <span>Recorded baseline</span>
                          <span className="tnum text-[10px] text-mist">{baselineScore.toFixed(1)} / 100</span>
                        </div>
                      )}
                    </div>
                  </div>
                </Panel>

                <Panel className="xl:col-span-5">
                  <PanelHead title="Reading this projection" kicker="Limits and honest interpretation" right={<Info size={14} className="text-dim" />} />
                  <div className="space-y-3 px-4 pb-4 pt-1">
                    <ul className="space-y-2 text-[10.5px] leading-relaxed text-mist">
                      <li className="flex gap-2">
                        <span className="mt-[6px] h-1 w-1 shrink-0 rounded-full bg-ion" />
                        Factor values are read from the API&apos;s breakdown for the selected threat. Only the five sliders above change the arithmetic.
                      </li>
                      <li className="flex gap-2">
                        <span className="mt-[6px] h-1 w-1 shrink-0 rounded-full bg-violet" />
                        Selecting an asset applies its recorded exposure and criticality. Anticipated patches, isolation or network changes are assumptions typed into the model, not observations.
                      </li>
                      <li className="flex gap-2">
                        <span className="mt-[6px] h-1 w-1 shrink-0 rounded-full bg-high" />
                        A projected band is a prioritisation outcome under the configured weights. It does not estimate attack probability, dwell time or business loss.
                      </li>
                      <li className="flex gap-2">
                        <span className="mt-[6px] h-1 w-1 shrink-0 rounded-full bg-crit" />
                        No simulation triggers containment, scanning or any disruptive action. Response remains a human decision recorded in Recommendations.
                      </li>
                    </ul>
                    <InlineNotice tone="violet" title="Session-only projection">
                      To record a score against an asset, create an assessment in Risk assessment. This lab never mutates stored risk records.
                    </InlineNotice>
                    <Link to="/app/risk" className="inline-flex items-center gap-1 font-mono text-[8.5px] uppercase tracking-[0.12em] text-ion hover:text-crystal">
                      Open risk model <ArrowRight size={10} />
                    </Link>
                  </div>
                </Panel>
              </div>
            </>
          )}
        </div>
      )}
    </>
  );
}
