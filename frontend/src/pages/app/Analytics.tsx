import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  Download,
  FileSpreadsheet,
  Gauge,
  Globe2,
  Layers,
  Radar,
  ScanSearch,
  ServerCog,
  ShieldAlert,
  Siren,
  TrendingUp,
  Waves,
} from "lucide-react";
import clsx from "clsx";
import { api, downloadFile, qs } from "../../lib/api";
import { fmtDate, fmtNumber, fmtPct, relTime, riskColor, titleCase } from "../../lib/format";
import {
  AnimatedNumber,
  EmptyState,
  ErrorState,
  InlineNotice,
  LoadingBlock,
  MetricCard,
  PageHeader,
  Panel,
  PanelHead,
  RangeTabs,
  SeverityBadge,
  StatusBadge,
  useToast,
} from "../../components/ui";
import {
  ChartLegend,
  DistributionDonut,
  HBarList,
  Heatmap,
  SignalMap,
  TrendArea,
  TrendLine,
} from "../../components/charts";
import { FilterSelect, MiniBar, SectionLabel } from "./shared";

const SOURCE_COLORS = ["#49b8ff", "#64d8ff", "#9a8cff", "#ffd166", "#42c98a", "#ff963d", "#78b7ff", "#ff4d5e", "#7f94ad", "#c9a6ff"];
const SEVERITY_COLORS: Record<string, string> = { Critical: "#ff4d5e", High: "#ff963d", Medium: "#ffd166", Low: "#42c98a" };

export default function Analytics() {
  const { push } = useToast();
  const [range, setRange] = useState("30d");
  const [severity, setSeverity] = useState("all");
  const [source, setSource] = useState("all");
  const [dataset, setDataset] = useState("threats");

  const query = useQuery({
    queryKey: ["analytics", range, severity, source],
    queryFn: () =>
      api<any>(
        `/analytics${qs({
          range,
          severity: severity === "all" ? undefined : severity,
          source: source === "all" ? undefined : source,
        })}`,
      ),
  });

  const data = query.data;
  const kpis = data?.kpis;

  const sourceOptions = useMemo(
    () => [
      { value: "all", label: "All sources" },
      ...((data?.source_distribution || []) as Array<{ name: string; value: number }>).map((entry) => ({
        value: entry.name,
        label: `${entry.name} (${entry.value})`,
      })),
    ],
    [data],
  );

  const sourceChart = useMemo(() => {
    if (!data?.source_series) return { rows: [] as any[], series: [] as any[] };
    const { labels, series } = data.source_series as { labels: string[]; series: Array<{ name: string; data: number[] }> };
    const trimmed = series.slice(0, 6);
    const rows = labels.map((label, index) => {
      const row: Record<string, any> = { name: label };
      trimmed.forEach((entry, entryIndex) => {
        row[`s${entryIndex}`] = entry.data[index] || 0;
      });
      return row;
    });
    return {
      rows,
      series: trimmed.map((entry, index) => ({ key: `s${index}`, name: entry.name, color: SOURCE_COLORS[index % SOURCE_COLORS.length] })),
    };
  }, [data]);

  const distribution = (data?.severity_distribution || []).map((entry: any) => ({ name: entry.name, value: entry.value }));
  const riskDistribution = (data?.risk_distribution || []).map((entry: any) => ({ name: entry.name, value: entry.value }));
  const classification = (data?.classification_distribution || []).slice(0, 7);
  const flagged = (data?.anomaly_series || []).filter((entry: any) => entry.flagged);
  const geoPoints = (data?.geo_activity || []).filter((entry: any) => typeof entry.lat === "number" && typeof entry.lon === "number");

  const exportCsv = async () => {
    try {
      await downloadFile(`/analytics/export.csv${qs({ dataset, range })}`, `cyberguard-${dataset}.csv`);
      push("success", `The ${titleCase(dataset)} dataset export downloaded.`);
    } catch (error: any) {
      push("error", error.message || "Export failed.");
    }
  };

  return (
    <>
      <PageHeader
        title="Advanced analytics"
        description="Cross-module aggregation over stored records: intake velocity, severity mix, risk movement, validated exposure and source behaviour. Every series is computed from the database on request; no figures are pre-baked."
        aside={
          data && (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
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
            <RangeTabs value={range} onChange={setRange} />
            <div className="flex items-center gap-1.5">
              <select className="field h-[32px] w-[132px] text-[10px]" value={dataset} onChange={(event) => setDataset(event.target.value)} aria-label="Export dataset">
                <option value="threats">Threats</option>
                <option value="vulnerabilities">Vulnerabilities</option>
                <option value="alerts">Alerts</option>
              </select>
              <button className="btn btn-ghost btn-sm" onClick={exportCsv}><Download size={13} /> Export CSV</button>
            </div>
          </>
        }
      />

      {query.isError ? (
        <Panel><ErrorState message={(query.error as any)?.message} retry={() => query.refetch()} /></Panel>
      ) : query.isLoading ? (
        <Panel><LoadingBlock rows={9} label="Aggregating analytics" /></Panel>
      ) : !data ? (
        <Panel><EmptyState title="No analytics returned" detail="The aggregation produced no result for this window." /></Panel>
      ) : (
        <>
          <div className="mb-4 grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
            <MetricCard label="Threats in range" value={<AnimatedNumber value={kpis.new_threats} />} detail={<DeltaPill value={data.deltas?.new_threats} />} icon={<Activity size={15} />} tone="ion" />
            <MetricCard label="Critical threats" value={<AnimatedNumber value={kpis.critical_threats} />} detail={<DeltaPill value={data.deltas?.critical_threats} />} icon={<Siren size={15} />} tone="crit" />
            <MetricCard label="High-risk CVEs" value={<AnimatedNumber value={kpis.high_risk_vulnerabilities} />} detail={`${fmtNumber(kpis.new_vulnerabilities)} published in range`} icon={<ShieldAlert size={15} />} tone="high" />
            <MetricCard label="Active alerts" value={<AnimatedNumber value={kpis.active_alerts} />} detail={`${fmtNumber(kpis.critical_alerts)} critical still active`} icon={<AlertTriangle size={15} />} tone="med" />
            <MetricCard
              label="Exposed assets"
              value={<AnimatedNumber value={kpis.exposed_assets} />}
              detail={`of ${fmtNumber(kpis.total_assets)} registered assets`}
              icon={<ServerCog size={15} />}
              tone="violet"
              gauge={kpis.total_assets ? (kpis.exposed_assets / kpis.total_assets) * 100 : 0}
            />
            <MetricCard
              label="Average risk"
              value={<AnimatedNumber value={Number(kpis.avg_risk || 0)} decimals={1} />}
              detail="Threats in the selected window"
              icon={<Gauge size={15} />}
              tone="low"
              gauge={Number(kpis.avg_risk || 0)}
            />
          </div>

          <div className="mb-4 grid gap-4 xl:grid-cols-[1.55fr_1fr]">
            <Panel>
              <PanelHead
                title="Threat intake by severity"
                kicker="Activity over time"
                right={<ChartLegend items={["Critical", "High", "Medium", "Low"].map((name) => ({ name, color: SEVERITY_COLORS[name] }))} />}
              />
              <div className="p-3 pt-1">
                <TrendArea
                  data={data.threat_series}
                  series={[
                    { key: "critical", name: "Critical", color: "#ff4d5e" },
                    { key: "high", name: "High", color: "#ff963d" },
                    { key: "medium", name: "Medium", color: "#ffd166" },
                    { key: "low", name: "Low", color: "#42c98a" },
                  ]}
                  stacked
                  height={244}
                />
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-4 py-2 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
                <span>Severity mix</span>
                <span>{fmtNumber(kpis.sources_online)} of {fmtNumber(kpis.sources_total)} sources online · last sync {kpis.last_sync ? relTime(kpis.last_sync) : "unknown"}</span>
              </div>
            </Panel>

            <Panel>
              <PanelHead title="Risk band distribution" kicker="Current records" />
              <div className="p-4">
                <DistributionDonut
                  data={riskDistribution}
                  height={176}
                  centerLabel="threats"
                  centerValue={kpis.new_threats}
                  colors={["#ff4d5e", "#ff963d", "#ffd166", "#42c98a"]}
                />
                <div className="mt-4 grid grid-cols-2 gap-2">
                  <div className="rounded-md border border-line bg-shade/20 px-3 py-2">
                    <div className="panel-kicker">Known exploited</div>
                    <div className="tnum mt-1 font-display text-[17px] text-crit">{fmtNumber(kpis.known_exploited)}</div>
                  </div>
                  <div className="rounded-md border border-line bg-shade/20 px-3 py-2">
                    <div className="panel-kicker">Validated matches</div>
                    <div className="tnum mt-1 font-display text-[17px] text-low">{fmtNumber(kpis.validated_matches)}</div>
                  </div>
                </div>
              </div>
            </Panel>
          </div>

          <div className="mb-4 grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
            <Panel>
              <PanelHead title="Vulnerability intake" kicker="Published advisories" right={<span className="font-mono text-[9px] text-dim">{fmtNumber(kpis.new_vulnerabilities)} in range</span>} />
              <div className="p-3 pt-1">
                <TrendArea
                  data={data.vuln_series}
                  series={[
                    { key: "count", name: "Advisories", color: "#49b8ff" },
                    { key: "critical", name: "Critical CVSS", color: "#ff4d5e" },
                  ]}
                  height={186}
                />
              </div>
            </Panel>
            <Panel>
              <PanelHead title="Alert volume" kicker="Detection output" right={<span className="font-mono text-[9px] text-dim">{fmtNumber(kpis.new_alerts)} in range</span>} />
              <div className="p-3 pt-1">
                <TrendArea
                  data={data.alert_series}
                  series={[
                    { key: "total", name: "Alerts", color: "#64d8ff" },
                    { key: "critical", name: "Critical", color: "#ff4d5e" },
                    { key: "high", name: "High", color: "#ff963d" },
                  ]}
                  height={186}
                />
              </div>
            </Panel>
            <Panel className="lg:col-span-2 xl:col-span-1">
              <PanelHead title="Risk movement" kicker="Average and maximum score" />
              <div className="p-3 pt-1">
                <TrendLine
                  data={data.risk_series}
                  series={[
                    { key: "avg_risk", name: "Average", color: "#64d8ff" },
                    { key: "max_risk", name: "Maximum", color: "#9a8cff", dashed: true },
                  ]}
                  height={186}
                />
              </div>
            </Panel>
          </div>

          <div className="mb-4 grid gap-4 xl:grid-cols-[1.5fr_1fr]">
            <Panel>
              <PanelHead
                title="Source contribution"
                kicker="Records per source over time"
                right={
                  <div className="flex items-center gap-2">
                    <FilterSelect
                      label=""
                      value={source}
                      onChange={setSource}
                      options={sourceOptions}
                      className="[&_.field]:h-[30px] [&_.field]:text-[10px] [&_.field-label]:hidden"
                    />
                  </div>
                }
              />
              <div className="p-3 pt-1">
                {sourceChart.rows.length ? (
                  <TrendLine data={sourceChart.rows} series={sourceChart.series} height={224} />
                ) : (
                  <div className="py-12 text-center text-[11px] text-dim">No source series in this window.</div>
                )}
              </div>
              <div className="border-t border-line px-4 py-2">
                <ChartLegend items={sourceChart.series.map((entry) => ({ name: entry.name, color: entry.color }))} />
              </div>
            </Panel>

            <Panel>
              <PanelHead title="Classification mix" kicker="AI-assisted taxonomy" />
              <div className="p-4">
                <HBarList data={classification} color="#9a8cff" />
                <div className="mt-4 border-t border-line pt-3">
                  <SectionLabel>Severity split</SectionLabel>
                  <DistributionDonut data={distribution} height={132} centerLabel="threats" centerValue={kpis.new_threats} colors={["#ff4d5e", "#ff963d", "#ffd166", "#42c98a", "#78b7ff"]} />
                </div>
              </div>
            </Panel>
          </div>

          <div className="mb-4 grid gap-4 xl:grid-cols-2">
            <Panel>
              <PanelHead title="Severity × asset criticality" kicker="Validated exposure density" right={<span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">criticality 1 → 5</span>} />
              <div className="p-4">
                <Heatmap rows={data.heatmap?.rows || []} cols={data.heatmap?.cols || []} data={data.heatmap?.data || []} height={152} />
                <p className="mt-2 text-[10px] leading-relaxed text-dim">Only matches with a satisfied product-and-version condition are counted. A hit is not proof of compromise.</p>
              </div>
            </Panel>
            <Panel>
              <PanelHead title="CVE severity × asset category" kicker="Exposure matrix" />
              <div className="p-4">
                {data.vuln_asset_matrix?.cols?.length ? (
                  <Heatmap rows={["Critical", "High", "Medium", "Low"]} cols={data.vuln_asset_matrix.cols.map((entry: string) => titleCase(entry))} data={data.vuln_asset_matrix.rows || []} height={152} />
                ) : (
                  <div className="py-12 text-center text-[11px] text-dim">No asset categories registered.</div>
                )}
              </div>
            </Panel>
          </div>

          <div className="mb-4 grid gap-4 xl:grid-cols-[1.4fr_1fr]">
            <Panel>
              <PanelHead
                title="Two-sigma activity baseline"
                kicker="Daily observation vs trailing mean"
                right={
                  flagged.length ? (
                    <span className="chip border-crit/30 text-crit">{flagged.length} flagged interval(s)</span>
                  ) : (
                    <span className="chip text-low">Within baseline</span>
                  )
                }
              />
              <div className="p-3 pt-1">
                <TrendLine
                  data={data.anomaly_series || []}
                  series={[
                    { key: "observed", name: "Observed", color: "#64d8ff" },
                    { key: "baseline", name: "Baseline", color: "#64798f", dashed: true },
                  ]}
                  height={196}
                />
              </div>
              <div className="border-t border-line px-4 py-2.5">
                {flagged.length ? (
                  <div className="flex flex-wrap gap-1.5">
                    {flagged.slice(0, 10).map((entry: any) => (
                      <span key={entry.name} className="chip border-crit/25 text-crit">
                        {entry.name} · z {entry.z} · {entry.observed} observed
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">No interval exceeded the two-sigma threshold.</p>
                )}
              </div>
            </Panel>

            <Panel>
              <PanelHead title="Resolution time" kicker="Resolved alerts only" />
              <div className="p-4">
                <div className="space-y-3">
                  {(data.resolution_time || []).map((entry: any) => {
                    const max = Math.max(1, ...(data.resolution_time || []).map((row: any) => row.avg_hours || 0));
                    return (
                      <div key={entry.severity}>
                        <div className="mb-1 flex items-center justify-between gap-2">
                          <span className="flex items-center gap-2 text-[10.5px] text-mist">
                            <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEVERITY_COLORS[entry.severity] }} />
                            {entry.severity}
                          </span>
                          <span className="tnum font-mono text-[9.5px] text-dim">{entry.resolved} resolved · {entry.avg_hours}h avg</span>
                        </div>
                        <MiniBar value={entry.avg_hours} max={max} color={SEVERITY_COLORS[entry.severity]} />
                      </div>
                    );
                  })}
                </div>
                <InlineNotice tone="ion" className="mt-4">
                  Durations use stored detection and resolution timestamps. They describe handling in this dataset, not response guarantees.
                </InlineNotice>
              </div>
            </Panel>
          </div>

          <div className="mb-4 grid gap-4 xl:grid-cols-[1.3fr_1fr]">
            <Panel>
              <PanelHead title="Most referenced technologies" kicker="Across threat and vulnerability text" />
              <div className="p-4">
                <HBarList data={(data.top_technologies || []).slice(0, 9)} color="#64d8ff" />
              </div>
            </Panel>
            <Panel>
              <PanelHead title="Common indicators" kicker="Extracted entities" />
              <div className="p-4">
                {(data.common_indicators || []).length ? (
                  <div className="space-y-2">
                    {(data.common_indicators || []).slice(0, 10).map((entry: any) => (
                      <div key={`${entry.type}-${entry.value}`} className="flex items-center justify-between gap-3 rounded-md border border-line bg-shade/20 px-2.5 py-2">
                        <div className="min-w-0">
                          <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-violet">{entry.type}</span>
                          <div className="truncate font-mono text-[10px] text-ink">{entry.value}</div>
                        </div>
                        <span className="tnum shrink-0 font-mono text-[10px] text-dim">{entry.count}×</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="py-8 text-center text-[11px] text-dim">No indicators extracted in this window.</p>
                )}
              </div>
            </Panel>
          </div>

          <div className="mb-4 grid gap-4 xl:grid-cols-[1.45fr_1fr]">
            <Panel>
              <PanelHead title="Top vulnerabilities" kicker="Highest priority in range" right={<Link to="/app/vulnerabilities" className="text-[10px] text-ion hover:text-crystal">Open module</Link>} />
              <div className="table-shell overflow-x-auto border-0">
                <table className="w-full">
                  <thead>
                    <tr>
                      <th>CVE</th>
                      <th>Advisory</th>
                      <th className="text-right">CVSS</th>
                      <th className="text-right">EPSS</th>
                      <th>KEV</th>
                      <th>Published</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(data.top_vulnerabilities || []).map((entry: any) => (
                      <tr key={entry.id}>
                        <td><Link to={`/app/vulnerabilities?focus=${entry.cve_id}`} className="font-mono text-[10px] text-ion hover:text-crystal">{entry.cve_id}</Link></td>
                        <td className="max-w-[320px]"><span className="block truncate text-[11px] text-ink">{entry.title}</span></td>
                        <td className="tnum text-right font-mono text-[10.5px]" style={{ color: riskColor((entry.cvss || 0) * 10) }}>{entry.cvss?.toFixed?.(1) ?? entry.cvss}</td>
                        <td className="tnum text-right font-mono text-[10.5px] text-mist">{entry.epss != null ? fmtPct(entry.epss) : "—"}</td>
                        <td>{entry.known_exploited ? <span className="chip border-crit/30 text-crit">KEV</span> : <span className="text-dim">—</span>}</td>
                        <td className="font-mono text-[9.5px] text-dim">{fmtDate(entry.published_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>

            <Panel>
              <PanelHead title="Top assets by risk" kicker="Ranked from validated exposure" right={<Link to="/app/assets" className="text-[10px] text-ion hover:text-crystal">Open inventory</Link>} />
              <div className="divide-y divide-veil/[0.05]">
                {(data.top_assets || []).slice(0, 7).map((asset: any) => (
                  <div key={asset.id} className="flex items-center gap-3 px-4 py-2.5">
                    <span className="tnum grid h-8 w-9 shrink-0 place-items-center rounded-md border border-line bg-shade/30 font-mono text-[10px]" style={{ color: riskColor(asset.risk_score) }}>
                      {Math.round(asset.risk_score || 0)}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-[11px] text-ink">{asset.name}</div>
                      <div className="truncate font-mono text-[8.5px] text-dim">{asset.ref} · {titleCase(asset.category)} · crit {asset.criticality}/5</div>
                    </div>
                    <div className="shrink-0 text-right">
                      {asset.validated_vulnerabilities > 0 ? (
                        <span className="chip text-med">{asset.validated_vulnerabilities} validated</span>
                      ) : (
                        <span className="chip text-dim">none validated</span>
                      )}
                      {asset.known_exploited > 0 && <div className="mt-1 font-mono text-[8px] uppercase tracking-[0.1em] text-crit">KEV linked</div>}
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
          </div>

          <div className="mb-4 grid gap-4 xl:grid-cols-[1fr_1fr]">
            <Panel>
              <PanelHead title="Indicator geography" kicker="Estimates from indicator metadata" right={<Globe2 size={14} className="text-dim" />} />
              <div className="px-2 pt-2">
                {geoPoints.length ? (
                  <SignalMap points={geoPoints} height={244} />
                ) : (
                  <div className="py-16 text-center text-[11px] text-dim">No geolocatable indicators in this window.</div>
                )}
              </div>
              <div className="border-t border-line px-4 py-2.5 text-[10px] leading-relaxed text-dim">{data.geo_note}</div>
            </Panel>

            <Panel>
              <PanelHead title="Source reliability" kicker="Configuration and observed volume" right={<Radar size={14} className="text-dim" />} />
              <div className="table-shell overflow-x-auto border-0">
                <table className="w-full">
                  <thead>
                    <tr>
                      <th>Source</th>
                      <th>Status</th>
                      <th className="text-right">Reliability</th>
                      <th className="text-right">Items</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(data.source_reliability || []).map((entry: any) => (
                      <tr key={entry.name}>
                        <td className="text-[11px] text-ink">{entry.name}</td>
                        <td><StatusBadge status={entry.status} /></td>
                        <td className="text-right">
                          <span className="inline-flex items-center gap-2">
                            <span className="w-16"><MiniBar value={entry.reliability || 0} color="#64d8ff" /></span>
                            <span className="tnum font-mono text-[9.5px] text-dim">{Math.round(entry.reliability || 0)}%</span>
                          </span>
                        </td>
                        <td className="tnum text-right font-mono text-[10px] text-mist">{fmtNumber(entry.items)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          </div>

          <div className="mb-4 grid gap-4 xl:grid-cols-[1.35fr_1fr]">
            <Panel>
              <PanelHead
                title="Recent ingestion runs"
                kicker="Connector execution log"
                right={<Link to="/app/sources" className="text-[10px] text-ion hover:text-crystal">Manage sources</Link>}
              />
              <div className="divide-y divide-veil/[0.05]">
                {(data.ingestion_recent || []).length ? (
                  (data.ingestion_recent || []).map((entry: any, index: number) => (
                    <div key={`${entry.source}-${index}`} className="flex items-start gap-3 px-4 py-2.5">
                      <span className="mt-1"><StatusBadge status={entry.status === "success" ? "resolved" : entry.status === "failed" ? "dismissed" : entry.status} /></span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[9px] uppercase tracking-[0.1em] text-mist">{entry.source}</span>
                          <span className="chip text-dim">{entry.mode}</span>
                          <span className="tnum font-mono text-[9px] text-dim">+{entry.items_new}</span>
                        </div>
                        <div className="mt-0.5 truncate text-[10.5px] text-dim">{entry.message}</div>
                      </div>
                      <span className="shrink-0 font-mono text-[8.5px] text-dim">{relTime(entry.started_at)}</span>
                    </div>
                  ))
                ) : (
                  <div className="py-10 text-center text-[11px] text-dim">No ingestion runs recorded.</div>
                )}
              </div>
            </Panel>

            <Panel ticks>
              <PanelHead title="Aggregate reading" kicker="Plain-language summary" right={<Layers size={14} className="text-dim" />} />
              <div className="space-y-3 p-4">
                <p className="text-[11.5px] leading-relaxed text-ink">{data.summary}</p>
                <div className="grid grid-cols-2 gap-2">
                  <div className="rounded-md border border-line bg-shade/20 px-3 py-2">
                    <div className="panel-kicker">Correlation pairs</div>
                    <div className="tnum mt-1 font-display text-[17px] text-ink">{fmtNumber(data.correlation_stats?.pairs)}</div>
                    <div className="font-mono text-[8px] text-dim">avg score {Number(data.correlation_stats?.avg_score || 0).toFixed(2)}</div>
                  </div>
                  <div className="rounded-md border border-line bg-shade/20 px-3 py-2">
                    <div className="panel-kicker">Known exploited</div>
                    <div className="tnum mt-1 font-display text-[17px] text-crit">{fmtNumber(data.kpis?.known_exploited)}</div>
                    <div className="font-mono text-[8px] text-dim">CVEs confirmed in the wild</div>
                  </div>
                </div>
                <InlineNotice tone="violet">{data.summary_disclaimer}</InlineNotice>
                <div className="flex flex-wrap gap-2">
                  <Link to="/app/reports" className="btn btn-ghost btn-sm"><FileSpreadsheet size={12} /> Build a report</Link>
                  <Link to="/app/correlations" className="btn btn-ghost btn-sm"><ScanSearch size={12} /> Correlation graph</Link>
                  <Link to="/app/exposure" className="btn btn-ghost btn-sm"><Waves size={12} /> Exposure detail</Link>
                </div>
              </div>
            </Panel>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[8px] uppercase tracking-[0.12em] text-dim">
            <span><TrendingUp size={10} className="mr-1 inline" /> {data.data_quality?.note}</span>
            <span>Window {data.range?.granularity} · generated {relTime(data.generated_at)}</span>
          </div>
        </>
      )}
    </>
  );
}

function DeltaPill({ value }: { value: number | null | undefined }) {
  if (value === null || value === undefined) return <span className="trend-pill" data-tone="flat">no prior baseline</span>;
  const rounded = Number(value);
  if (Number.isNaN(rounded)) return <span className="trend-pill" data-tone="flat">change unavailable</span>;
  const rising = rounded >= 0;
  return (
    <span className="trend-pill" data-tone={rising ? "down" : "up"} title="Compared with the previous equal-length period">
      {rising ? <ArrowUpRight size={10} /> : <ArrowDownRight size={10} />}
      {Math.abs(rounded).toFixed(1)}%
    </span>
  );
}
