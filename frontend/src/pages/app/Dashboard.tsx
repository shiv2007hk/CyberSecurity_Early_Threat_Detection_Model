import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Boxes,
  Crosshair,
  DatabaseZap,
  GitFork,
  RefreshCw,
  ShieldAlert,
  Siren,
  Target,
  TriangleAlert,
} from "lucide-react";
import clsx from "clsx";
import { api } from "../../lib/api";
import { fmtDate, fmtNumber, fmtPct, relTime, riskColor, severityMeta, titleCase } from "../../lib/format";
import {
  AnimatedNumber,
  EmptyState,
  ErrorState,
  LiveDot,
  LoadingBlock,
  MetricCard,
  NeedleGauge,
  PageHeader,
  Panel,
  PanelHead,
  ProgressBar,
  RangeTabs,
  RiskMeter,
  SeverityBadge,
  StatusBadge,
  useToast,
} from "../../components/ui";
import { DistributionDonut, HBarList, SignalMap, TrendArea } from "../../components/charts";
import { useAuth } from "../../context/AuthContext";

const SEV_COLORS: Record<string, string> = {
  Critical: "#ff4d5e",
  High: "#ff963d",
  Medium: "#ffd166",
  Low: "#42c98a",
  Info: "#78b7ff",
};

function Delta({ value }: { value?: number | null }) {
  if (value === null || value === undefined) {
    return (
      <span className="trend-pill" data-tone="flat">
        no prior baseline
      </span>
    );
  }
  const rising = value >= 0;
  return (
    <span className="trend-pill" data-tone={rising ? "down" : "up"} title="Compared with the previous equal-length period">
      {rising ? <ArrowUpRight size={10} /> : <ArrowDownRight size={10} />}
      {Math.abs(value).toFixed(1)}%
    </span>
  );
}

function bandLabel(score: number) {
  return score >= 75 ? "Critical band" : score >= 50 ? "High band" : score >= 25 ? "Elevated band" : "Low band";
}

export default function Dashboard() {
  const [range, setRange] = useState("7d");
  const [geoFocus, setGeoFocus] = useState("");
  const navigate = useNavigate();
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["dashboard", range],
    queryFn: () => api<any>(`/dashboard?range=${range}`),
    refetchInterval: 90_000,
  });

  const scan = useMutation({
    mutationFn: () => api<any>("/alerts/scan", { method: "POST" }),
    onSuccess: (result) => {
      push("success", `Detection complete: ${result.alerts_created} new alert${result.alerts_created === 1 ? "" : "s"} across ${result.rules_evaluated ?? "five"} rules.`);
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["alert-summary"] });
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
    onError: (err: any) => push("error", err.message || "Detection run failed."),
  });

  const kpis = data?.kpis || {};
  const deltas = data?.deltas || {};
  const summary: string = data?.summary || "";
  const threatSeries = data?.threat_series || [];
  const sources = data?.source_status || [];
  const recentAlerts = data?.recent_alerts || [];
  const latestVulns = data?.latest_vulnerabilities || [];
  const recommendations = data?.open_recommendations || [];
  const criticalRecent = data?.critical_recent || [];
  const geo = data?.geo_activity || [];

  const totalActive = useMemo(
    () => sources.filter((source: any) => ["operational", "degraded"].includes(source.status)).length,
    [sources],
  );
  const geoRecords = useMemo(() => geo.reduce((sum: number, point: any) => sum + Number(point.count || 0), 0), [geo]);
  const riskScore = typeof kpis.avg_risk === "number" ? kpis.avg_risk : null;

  if (isError) {
    return (
      <>
        <PageHeader title="Command centre" description="The watch floor could not be assembled because the intelligence API did not respond." />
        <Panel><ErrorState message={(error as any)?.message} retry={() => refetch()} /></Panel>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Total visibility. Total control."
        description="One command surface over stored intelligence, validated exposure, explainable risk and active warning. Every figure resolves to a labelled record; nothing is generated for display alone."
        actions={
          <>
            {data && (
              <span className="hidden font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim md:inline">
                Snapshot {fmtDate(data.generated_at, true)}
              </span>
            )}
            <RangeTabs value={range} onChange={setRange} />
            {can("analyst") && (
              <button className="btn btn-primary btn-sm" onClick={() => scan.mutate()} disabled={scan.isPending}>
                <RefreshCw size={13} className={scan.isPending ? "animate-spin" : undefined} />
                {scan.isPending ? "Evaluating rules" : "Run detection"}
              </button>
            )}
          </>
        }
      />

      {data && (
        <div className="mb-3.5 grid gap-2.5 sm:grid-cols-2 xl:grid-cols-[1.34fr_repeat(4,minmax(0,1fr))]">
          <Link
            to="/app/risk"
            className="block rounded-[20px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ion/60 sm:col-span-2 xl:col-span-1"
          >
            <div className="metric-card group relative flex h-full flex-col p-4">
              <span className="metric-sheen" aria-hidden="true" />
              <div className="relative flex items-center justify-between gap-2">
                <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-mist">
                  <span className="h-1 w-1 rounded-full" style={{ background: riskScore === null ? "#8fa9c2" : riskColor(riskScore) }} />
                  Mean threat risk
                </div>
                <span className="metric-pill">{range}</span>
              </div>
              <div className="relative flex flex-1 items-end justify-between gap-1 pt-3">
                <div className="min-w-0">
                  <div className="flex items-end gap-1.5">
                    <span
                      className="tnum font-display text-[42px] font-semibold leading-[0.9] tracking-[-0.04em]"
                      style={{ color: riskScore === null ? "#8fa9c2" : riskColor(riskScore) }}
                    >
                      {riskScore === null ? "—" : <AnimatedNumber value={riskScore} />}
                    </span>
                    <span className="pb-1 font-mono text-[10px] text-dim">/ 100</span>
                  </div>
                  <div className="mt-2.5">
                    <span
                      className="metric-pill"
                      style={
                        riskScore === null
                          ? undefined
                          : { borderColor: `${riskColor(riskScore)}55`, background: `${riskColor(riskScore)}14`, color: riskColor(riskScore) }
                      }
                    >
                      {riskScore === null ? "No assessment yet" : bandLabel(riskScore)}
                    </span>
                  </div>
                  <p className="mt-2 max-w-[17ch] text-[10px] leading-relaxed text-dim">
                    Prioritisation score across {fmtNumber(kpis.total_threats)} stored threats
                  </p>
                </div>
                <NeedleGauge value={riskScore} size={128} className="mb-[-8px] hidden sm:block" />
              </div>
              <div className="metric-action">
                <span>Explain score</span>
                <ArrowRight size={12} />
              </div>
            </div>
          </Link>

          <Link to="/app/vulnerabilities" className="block h-full rounded-[20px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ion/60">
            <MetricCard
              label="Vulnerabilities"
              value={<AnimatedNumber value={kpis.new_vulnerabilities} />}
              detail={<><span className="text-mist">{fmtNumber(kpis.high_risk_vulnerabilities)}</span> high-risk on record · CVSS ≥ 7 or KEV</>}
              icon={<ShieldAlert size={15} />}
              tone="med"
              badge={<Delta value={deltas.new_vulnerabilities} />}
              footerLabel="Open CVE explorer"
              footer="Open CVE explorer"
              className="h-full"
            />
          </Link>

          <Link to="/app/threats" className="block h-full rounded-[20px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ion/60">
            <MetricCard
              label="Critical threats"
              value={<AnimatedNumber value={kpis.critical_threats} />}
              detail={<>of {fmtNumber(kpis.total_threats)} stored records · {fmtNumber(kpis.investigating)} investigating</>}
              icon={<TriangleAlert size={15} />}
              tone="crit"
              badge={<Delta value={deltas.critical_threats} />}
              footerLabel="Review threat ledger"
              footer="Review threat ledger"
              className="h-full"
            />
          </Link>

          <Link to="/app/assets" className="block h-full rounded-[20px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ion/60">
            <MetricCard
              label="High-risk assets"
              value={<><AnimatedNumber value={kpis.exposed_assets} /><span className="text-[15px] font-medium text-dim"> / {fmtNumber(kpis.total_assets)}</span></>}
              detail={<>{fmtNumber(kpis.validated_matches)} validated exposure matches across the inventory</>}
              icon={<Boxes size={15} />}
              tone="violet"
              gauge={kpis.total_assets ? (kpis.exposed_assets / kpis.total_assets) * 100 : 0}
              footerLabel="Inspect exposure"
              footer="Inspect exposure"
              className="h-full"
            />
          </Link>

          <Link to="/app/alerts" className="block h-full rounded-[20px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ion/60">
            <MetricCard
              label="Active warnings"
              value={<AnimatedNumber value={kpis.active_alerts} />}
              detail={<>{fmtNumber(kpis.new_alerts)} generated in the selected window</>}
              icon={<Siren size={15} />}
              tone="high"
              badge={
                <span className={clsx("metric-pill", kpis.critical_alerts ? "border-crit/30 bg-crit/10 text-crit" : undefined)}>
                  {fmtNumber(kpis.critical_alerts)} critical
                </span>
              }
              footerLabel="Open warning queue"
              footer="Open warning queue"
              className="h-full"
            />
          </Link>
        </div>
      )}

      <div className="grid gap-3.5 xl:grid-cols-12">
        <Panel className="xl:col-span-4" ticks>
          <PanelHead
            title="Attack origin map"
            kicker="Estimated indicator metadata"
            right={
              <select
                className="field h-8 w-[122px] px-2 text-[10.5px]"
                value={geoFocus}
                onChange={(event) => setGeoFocus(event.target.value)}
                aria-label="Highlight a country on the origin map"
              >
                <option value="">All countries</option>
                {geo.map((point: any) => (
                  <option key={point.code || point.country} value={point.code || point.country}>
                    {point.country}
                  </option>
                ))}
              </select>
            }
          />
          <div className="px-2">
            {isLoading ? (
              <LoadingBlock rows={4} />
            ) : geo.length ? (
              <SignalMap points={geo} height={224} labels selected={geoFocus || null} onSelect={(code) => setGeoFocus(code === geoFocus ? "" : code)} />
            ) : (
              <div className="py-16 text-center text-[11px] text-dim">No indicator geography is available.</div>
            )}
          </div>
          <div className="mt-1 flex items-center justify-between gap-3 border-t border-line px-4 py-2.5">
            <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
              {geo.length} locations · {fmtNumber(geoRecords)} records
            </span>
            <Link to="/app/analytics" className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-ion hover:text-crystal">
              Explore →
            </Link>
          </div>
          {geo.length > 0 && (
            <div className="border-t border-line px-4 py-2.5">
              <div className="mb-1.5 flex items-center justify-between font-mono text-[8px] uppercase tracking-[0.12em] text-dim">
                <span>Top indicator locations</span>
                <span>records</span>
              </div>
              <ul className="space-y-0.5">
                {[...geo]
                  .sort((a: any, b: any) => Number(b.count) - Number(a.count))
                  .slice(0, 3)
                  .map((point: any) => {
                    const key = point.code || point.country;
                    const active = geoFocus === key;
                    return (
                      <li key={key}>
                        <button
                          type="button"
                          onClick={() => setGeoFocus(active ? "" : key)}
                          className={clsx(
                            "flex w-full items-center justify-between gap-3 rounded-md px-1.5 py-1 text-left transition-colors hover:bg-veil/[0.04]",
                            active && "bg-veil/[0.055]",
                          )}
                        >
                          <span className="flex min-w-0 items-center gap-2">
                            <span className={clsx("h-1.5 w-1.5 shrink-0 rounded-full", active ? "bg-crystal" : "bg-ion/80")} />
                            <span className="truncate text-[10.5px] text-mist">{point.country}</span>
                          </span>
                          <span className="tnum shrink-0 font-mono text-[10px] text-dim">{fmtNumber(Number(point.count))}</span>
                        </button>
                      </li>
                    );
                  })}
              </ul>
            </div>
          )}
          <p className="border-t border-line px-4 py-2 text-[9px] leading-relaxed text-dim">
            {data?.geo_note || "Locations are estimates from indicator metadata, not verified attacker attribution."}
          </p>
        </Panel>

        <Panel className="xl:col-span-5" ticks>
          <PanelHead
            title="Threat records by volume"
            kicker={`Daily totals · ${range}`}
            right={
              <Link to="/app/analytics" className="btn btn-quiet btn-sm text-ion">
                Analytics <ArrowRight size={12} />
              </Link>
            }
          />
          <div className="px-4">
            <div className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <div className="flex flex-wrap items-end gap-x-3 gap-y-1.5">
                  <AnimatedNumber value={kpis.new_threats} className="font-display text-[34px] font-semibold leading-none tracking-[-0.035em] text-ink" />
                  <span className="pb-1"><Delta value={deltas.new_threats} /></span>
                </div>
                <div className="mt-1.5 font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">records observed in window</div>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {(data?.severity_distribution || []).slice(0, 4).map((entry: any) => (
                  <span key={entry.name} className="metric-pill">
                    <span className="h-1 w-1 rounded-full" style={{ background: SEV_COLORS[entry.name] || "#78b7ff" }} />
                    {entry.name} {fmtNumber(entry.value)}
                  </span>
                ))}
              </div>
            </div>
          </div>
          <div className="px-2 pb-1 pt-2 sm:px-3">
            {isLoading ? (
              <div className="px-3"><LoadingBlock rows={4} /></div>
            ) : (
              <TrendArea data={threatSeries} series={[{ key: "total", name: "Threat records", color: "#7fd2ff" }]} height={212} />
            )}
          </div>
          <div className="flex items-center justify-between border-t border-line px-4 py-2.5 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span>avg risk <span className="tnum ml-1 text-ink">{kpis.avg_risk ?? "—"}</span></span>
            <span>sources <span className="tnum ml-1 text-ink">{totalActive}/{sources.length}</span></span>
          </div>
        </Panel>

        <Panel className="xl:col-span-3">
          <PanelHead
            title="Security tasks"
            kicker="Open recommendations"
            right={<Link to="/app/recommendations" className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-ion hover:text-crystal">All →</Link>}
          />
          {isLoading ? (
            <LoadingBlock rows={4} />
          ) : recommendations.length ? (
            <div className="pb-1">
              {recommendations.slice(0, 5).map((rec: any) => (
                <Link key={rec.id} to={`/app/recommendations?focus=${rec.ref}`} className="task-row">
                  <span className="task-check" data-priority={rec.priority} aria-hidden="true" />
                  <span className="min-w-0 flex-1">
                    <span className="line-clamp-2 break-words text-[12.5px] leading-snug text-ink">{rec.title}</span>
                    <span className="mt-1 block font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">
                      Due {rec.due_at ? fmtDate(rec.due_at) : "not set"} · {rec.priority}
                    </span>
                  </span>
                </Link>
              ))}
            </div>
          ) : (
            <EmptyState title="No open tasks" detail="No recommendation currently awaits action." />
          )}
          <div className="flex items-center justify-between border-t border-line px-4 py-2.5 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span>{fmtNumber(kpis.open_recommendations)} open</span>
            <span>approval required</span>
          </div>
        </Panel>

        <Panel className="xl:col-span-4">
          <PanelHead
            title="Warning queue"
            kicker="Rule-generated detections"
            right={<Link to="/app/alerts" className="font-mono text-[9px] uppercase tracking-[0.12em] text-ion hover:text-crystal">All alerts →</Link>}
          />
          {isLoading ? (
            <LoadingBlock rows={4} />
          ) : recentAlerts.length ? (
            <div className="divide-y divide-veil/[0.045]">
              {recentAlerts.slice(0, 5).map((alert: any) => (
                <button
                  key={alert.id}
                  onClick={() => navigate(`/app/alerts?focus=${alert.ref}`)}
                  className="flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-veil/[0.025]"
                >
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: severityMeta(alert.severity).hex }} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[12px] text-ink">{alert.title}</span>
                    <span className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">
                      <span>{alert.ref}</span>
                      <span>·</span>
                      <span>{relTime(alert.detected_at)}</span>
                      <span>·</span>
                      <span>{titleCase(alert.status)}</span>
                    </span>
                  </span>
                  <span className="shrink-0 text-right">
                    <SeverityBadge severity={alert.severity} />
                    <span className="mt-1 block font-mono text-[9px] text-dim">risk {Number(alert.risk_score ?? 0).toFixed(0)}</span>
                  </span>
                </button>
              ))}
            </div>
          ) : (
            <EmptyState title="No warnings in this window" detail="The rule engine has not produced a detection for the selected period." action={<Link to="/app/alerts" className="btn btn-ghost btn-sm">Open alert centre</Link>} />
          )}
        </Panel>

        <Panel className="xl:col-span-4">
          <PanelHead title="New vulnerabilities" kicker="Published in range" right={<Link to="/app/vulnerabilities" className="font-mono text-[9px] uppercase tracking-[0.1em] text-ion">View all</Link>} />
          {isLoading ? (
            <LoadingBlock rows={4} />
          ) : latestVulns.length ? (
            <div className="divide-y divide-veil/[0.045]">
              {latestVulns.slice(0, 5).map((vuln: any) => (
                <Link key={vuln.id} to={`/app/vulnerabilities?focus=${vuln.cve_id}`} className="block px-4 py-2.5 transition-colors hover:bg-veil/[0.025]">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] text-ion">{vuln.cve_id}</span>
                    {vuln.known_exploited && <span className="rounded border border-high/30 bg-high/10 px-1 py-[1px] font-mono text-[7.5px] uppercase tracking-[0.1em] text-high">KEV</span>}
                    <span className="ml-auto font-mono text-[9px] text-dim">CVSS {vuln.cvss_score ?? "—"}</span>
                  </div>
                  <div className="mt-1 line-clamp-1 text-[11px] text-mist">{vuln.title}</div>
                  <div className="mt-1 flex items-center gap-1.5 font-mono text-[8px] uppercase tracking-[0.08em] text-dim">
                    <span>{vuln.source}</span><span>·</span><span>{relTime(vuln.published_at)}</span>
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <EmptyState title="No new vulnerabilities" detail="No vulnerability records were published in the selected period." />
          )}
        </Panel>

        <Panel className="xl:col-span-4" ticks>
          <PanelHead
            title="Watch posture"
            kicker="Assessed from stored evidence"
            right={<LiveDot tone={kpis.critical_alerts ? "crit" : "low"} label={kpis.critical_alerts ? "Critical active" : "Monitoring"} />}
          />
          {isLoading ? (
            <LoadingBlock rows={4} />
          ) : (
            <div className="p-4">
              <div className="flex items-center gap-4">
                <RiskMeter score={kpis.avg_risk} size={80} />
                <div className="min-w-0">
                  <div className="font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">Mean threat risk · {range}</div>
                  <div className="mt-1 font-display text-[15px] font-semibold text-ink">{bandLabel(Number(kpis.avg_risk) || 0)}</div>
                  <p className="mt-1 text-[10.5px] leading-relaxed text-dim">
                    A prioritisation score, not an attack probability. Exploitation evidence is reported separately.
                  </p>
                </div>
              </div>
              <div className="mt-4 space-y-2.5">
                {[
                  ["Known-exploited evidence", kpis.known_exploited, "#ff963d"],
                  ["Validated exposures", kpis.validated_matches, "#9a8cff"],
                  ["Critical active alerts", kpis.critical_alerts, "#64d8ff"],
                  ["Awaiting verification", kpis.needs_verification, "#5fb3e6"],
                ].map(([label, value, color]) => (
                  <div key={String(label)}>
                    <div className="mb-1 flex items-baseline justify-between">
                      <span className="text-[10.5px] text-mist">{label}</span>
                      <span className="tnum font-mono text-[9.5px] text-dim">{Math.max(0, Number(value) || 0)}</span>
                    </div>
                    <ProgressBar value={Math.min(100, (Number(value) || 0) * 2.4)} color={String(color)} height={3} />
                  </div>
                ))}
              </div>
              <div className="mt-4 rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                <div className="flex items-center gap-1.5 font-mono text-[8px] uppercase tracking-[0.14em] text-dim">
                  <Activity size={10} className="text-ion" /> Situation summary
                </div>
                <p className="mt-1.5 line-clamp-4 text-[10.5px] leading-relaxed text-mist">{summary || "No summary is available for this window."}</p>
              </div>
            </div>
          )}
        </Panel>

        <Panel className="xl:col-span-7">
          <PanelHead
            title="Critical and high-risk records"
            kicker="Ranked by explainable risk score"
            right={<Link to="/app/threats" className="btn btn-quiet btn-sm text-ion">Threat ledger <ArrowRight size={12} /></Link>}
          />
          {isLoading ? (
            <LoadingBlock rows={5} />
          ) : criticalRecent.length ? (
            <div className="overflow-x-auto">
              <table className="table-shell">
                <thead>
                  <tr>
                    <th>Record</th>
                    <th>Severity</th>
                    <th>Risk</th>
                    <th className="hidden md:table-cell">Source</th>
                    <th className="hidden sm:table-cell">Published</th>
                  </tr>
                </thead>
                <tbody>
                  {criticalRecent.slice(0, 6).map((threat: any) => (
                    <tr key={threat.id} onClick={() => navigate(`/app/threats?focus=${threat.ref}`)}>
                      <td className="max-w-[250px]">
                        <div className="flex items-center gap-2">
                          <span className="whitespace-nowrap font-mono text-[9px] text-dim">{threat.ref}</span>
                          <span className="truncate text-[12px] text-ink">{threat.name}</span>
                        </div>
                        <div className="mt-0.5 truncate font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">{threat.technology || threat.category}</div>
                      </td>
                      <td><SeverityBadge severity={threat.severity} /></td>
                      <td>
                        <span className="tnum font-mono text-[11px]" style={{ color: riskColor(threat.risk_score) }}>{Number(threat.risk_score ?? 0).toFixed(0)}</span>
                      </td>
                      <td className="hidden font-mono text-[9.5px] uppercase tracking-[0.06em] text-dim md:table-cell">{threat.source}</td>
                      <td className="hidden whitespace-nowrap text-[10px] text-dim sm:table-cell">{relTime(threat.published_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No critical records" detail="No critical or high severity records fall within the selected window." />
          )}
        </Panel>

        <Panel className="xl:col-span-5">
          <PanelHead
            title="Source state"
            kicker="Provenance and freshness"
            right={<Link to="/app/sources" className="font-mono text-[9px] uppercase tracking-[0.1em] text-ion">Manage</Link>}
          />
          {isLoading ? (
            <LoadingBlock rows={4} />
          ) : (
            <div className="divide-y divide-veil/[0.045]">
              {sources.slice(0, 6).map((source: any) => (
                <div key={source.key} className="flex items-center gap-3 px-4 py-2.5">
                  <span className={clsx("h-1.5 w-1.5 shrink-0 rounded-full", source.status === "operational" ? "bg-low" : source.status === "degraded" ? "bg-med" : source.status === "offline" ? "bg-crit" : "bg-dim")} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[11.5px] text-ink">{source.name}</div>
                    <div className="mt-0.5 font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">
                      {fmtNumber(source.items_ingested)} records · {source.last_success_at ? `synced ${relTime(source.last_success_at)}` : "never synced"}
                    </div>
                  </div>
                  <StatusBadge status={source.status} />
                </div>
              ))}
            </div>
          )}
          <div className="flex items-center justify-between border-t border-line px-4 py-2.5 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span className="flex items-center gap-1.5"><DatabaseZap size={10} className="text-violet" /> {fmtNumber(sources.length)} connectors</span>
            <span>{fmtNumber(sources.filter((s: any) => s.status === "operational").length)} operational</span>
          </div>
        </Panel>

        <Panel className="xl:col-span-6">
          <PanelHead title="Severity composition" kicker="Threat records in window" right={<TriangleAlert size={13} className="text-dim" />} />
          <div className="p-4">
            {isLoading ? (
              <LoadingBlock rows={3} />
            ) : (data?.severity_distribution || []).length ? (
              <DistributionDonut
                data={data.severity_distribution}
                colors={(data.severity_distribution || []).map((entry: any) => SEV_COLORS[entry.name] || "#78b7ff")}
                centerLabel="threats"
                height={182}
              />
            ) : (
              <div className="py-10 text-center text-[11px] text-dim">No threat records in this window.</div>
            )}
          </div>
        </Panel>

        <Panel className="xl:col-span-6">
          <PanelHead title="Affected technologies" kicker="Volume · average risk" right={<Crosshair size={13} className="text-dim" />} />
          <div className="p-4">
            {isLoading ? <LoadingBlock rows={4} /> : (data?.top_technologies || []).length ? <HBarList data={data.top_technologies} labelKey="name" valueKey="count" color="#49b8ff" /> : <div className="py-10 text-center text-[11px] text-dim">No technology attribution in this window.</div>}
          </div>
        </Panel>

        <Panel className="xl:col-span-12" as="section">
          <div className="grid gap-0 md:grid-cols-[1.4fr_1fr_1fr]">
            <div className="border-b border-line p-5 md:border-b-0 md:border-r">
              <div className="font-mono text-[8.5px] uppercase tracking-[0.16em] text-dim">Assessment coverage</div>
              <div className="mt-2 flex items-end gap-3">
                <span className="tnum font-display text-[30px] font-semibold leading-none text-ink">{fmtNumber(data?.assessment_count)}</span>
                <span className="pb-1 text-[11px] text-mist">stored explainable assessments</span>
              </div>
              <p className="mt-2 max-w-[52ch] text-[10.5px] leading-relaxed text-dim">
                Scores can be reproduced from their recorded factors. Changing model weights rescores records rather than hiding the calculation.
              </p>
              <Link to="/app/risk" className="btn btn-ghost btn-sm mt-3">Inspect the model <ArrowRight size={12} /></Link>
            </div>
            <div className="border-b border-line p-5 md:border-b-0 md:border-r">
              <div className="flex items-center gap-1.5 font-mono text-[8.5px] uppercase tracking-[0.16em] text-dim"><GitFork size={10} /> Correlated pairs</div>
              <div className="tnum mt-2 font-display text-[24px] font-semibold text-ink">{fmtNumber(data?.correlation_stats?.pairs)}</div>
              <div className="mt-1 font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">Avg similarity {Number(data?.correlation_stats?.avg_score || 0).toFixed(2)}</div>
              <Link to="/app/correlations" className="mt-3 inline-flex items-center gap-1 text-[10.5px] text-ion">Open cluster map <ArrowRight size={11} /></Link>
            </div>
            <div className="p-5">
              <div className="flex items-center gap-1.5 font-mono text-[8.5px] uppercase tracking-[0.16em] text-dim"><Target size={10} /> Coverage caveat</div>
              <p className="mt-2 text-[10.5px] leading-relaxed text-mist">
                Exposure totals describe the registered inventory only. An unmatched asset is not proof that no system is affected.
              </p>
              <div className="mt-3 flex flex-wrap gap-1.5">
                <span className="chip">Inventory scope</span>
                <span className="chip">{fmtPct(data?.kpis?.total_assets ? (data.kpis.exposed_assets / data.kpis.total_assets) * 100 : 0, 0)} exposed</span>
              </div>
            </div>
          </div>
        </Panel>
      </div>

      {isLoading && (
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <Panel><LoadingBlock rows={6} label="Loading watch floor" /></Panel>
          <Panel><LoadingBlock rows={6} label="Loading source state" /></Panel>
        </div>
      )}
    </>
  );
}
