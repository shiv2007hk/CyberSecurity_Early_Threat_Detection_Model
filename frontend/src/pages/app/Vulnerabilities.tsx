import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertOctagon,
  ArrowUpRight,
  Bug,
  Download,
  ExternalLink,
  Flame,
  ShieldCheck,
  ShieldX,
  Sparkles,
} from "lucide-react";
import { api, downloadFile, qs, type Paginated, type Vulnerability } from "../../lib/api";
import { fmtDate, fmtNumber, fmtPct, relTime, riskColor, titleCase } from "../../lib/format";
import { useAuth } from "../../context/AuthContext";
import {
  CopyButton,
  Drawer,
  EmptyState,
  ErrorState,
  InlineNotice,
  LoadingBlock,
  PageHeader,
  Pagination,
  Panel,
  PanelHead,
  ProgressBar,
  RangeTabs,
  SearchField,
  SeverityBadge,
  StatusBadge,
  useToast,
  Toggle,
} from "../../components/ui";
import { CorrelationGraph, DistributionDonut, TrendArea } from "../../components/charts";
import { DailyBars, Treemap } from "../../components/analytics-charts";
import { DrawerSection, EvidenceList, FieldLabel, FilterSelect, ScoreChip, SectionLabel } from "./shared";

const SORTS = [
  { value: "published_at", label: "Newest first" },
  { value: "cvss", label: "Highest CVSS" },
  { value: "epss", label: "Highest EPSS" },
  { value: "severity", label: "Severity" },
  { value: "cve", label: "CVE ID" },
];

const CVSS_BANDS = ["Critical", "High", "Medium", "Low", "Unknown"];
const CVSS_COLORS: Record<string, string> = {
  Critical: "#ff4d5e",
  High: "#ff963d",
  Medium: "#ffd166",
  Low: "#42c98a",
  Unknown: "#78b7ff",
};
const SEVERITY_SERIES = ["critical", "high", "medium", "low"];

function publishedSlot(time: number, rangeKey: string) {
  const date = new Date(time);
  if (rangeKey === "24h") {
    date.setHours(Math.floor(date.getHours() / 6) * 6, 0, 0, 0);
    return date.getTime();
  }
  date.setHours(0, 0, 0, 0);
  if (rangeKey === "90d" || rangeKey === "30d") date.setDate(date.getDate() - ((date.getDay() + 6) % 7));
  return date.getTime();
}

function ProductList({ products }: { products?: Array<{ vendor?: string; product?: string; versions?: any; notes?: string }> }) {
  if (!products?.length) return <p className="text-[11px] text-dim">No affected-product range was supplied by the source.</p>;
  return (
    <div className="space-y-1.5">
      {products.map((product, index) => {
        const raw = product.versions;
        const versions = Array.isArray(raw)
          ? raw.join(", ")
          : raw && typeof raw === "object"
            ? raw.start && raw.end
              ? `${raw.start} – ${raw.end}`
              : raw.start || raw.end || raw.value || ""
            : raw
              ? String(raw)
              : "";
        return (
          <div key={`${product.product}-${index}`} className="rounded-md border border-line bg-shade/20 px-3 py-2">
            <div className="flex flex-wrap items-baseline gap-1.5">
              <span className="text-[11.5px] text-ink">{product.product || "Unspecified product"}</span>
              {product.vendor && <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">{product.vendor}</span>}
            </div>
            {versions && <div className="mt-1 font-mono text-[9.5px] text-ion/90">Affected {versions}</div>}
            {product.notes && <p className="mt-1 text-[10.5px] leading-relaxed text-mist">{product.notes}</p>}
          </div>
        );
      })}
    </div>
  );
}

export default function Vulnerabilities() {
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();

  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("all");
  const [source, setSource] = useState("all");
  const [kevOnly, setKevOnly] = useState(false);
  const [epssMin, setEpssMin] = useState("all");
  const [range, setRange] = useState("90d");
  const [sortBy, setSortBy] = useState("published_at");
  const [page, setPage] = useState(1);
  const [assessAsset, setAssessAsset] = useState("");

  const focus = searchParams.get("focus");
  useEffect(() => setPage(1), [q, severity, source, kevOnly, epssMin, range, sortBy]);

  const params = {
    q,
    severity,
    source,
    kev: kevOnly ? true : undefined,
    epss_min: epssMin === "all" ? undefined : epssMin,
    range,
    sort_by: sortBy,
    order: "desc",
    page,
    size: 20,
  };

  const listQuery = useQuery({
    queryKey: ["vulnerabilities", params],
    queryFn: () => api<Paginated<Vulnerability>>(`/vulnerabilities${qs(params)}`),
  });
  const statsQuery = useQuery({
    queryKey: ["vulnerability-stats", range],
    queryFn: () => api<any>(`/vulnerabilities/stats${qs({ range })}`),
  });
  const detailQuery = useQuery({
    queryKey: ["vulnerability-detail", focus],
    queryFn: () => api<any>(`/vulnerabilities/${focus}`),
    enabled: Boolean(focus),
  });
  const analyticsQuery = useQuery({
    queryKey: ["vulnerability-analytics", range],
    queryFn: () => api<Paginated<Vulnerability>>(`/vulnerabilities${qs({ range, size: 100, sort_by: "published_at", order: "desc" })}`),
  });

  const data = listQuery.data;
  const stats = statsQuery.data;
  const detail = detailQuery.data;
  const record: Vulnerability | undefined = detail?.vulnerability;

  const openDrawer = (cve: string) => {
    setAssessAsset("");
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("focus", cve);
      return next;
    });
  };
  const closeDrawer = () =>
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete("focus");
      return next;
    });

  const assess = useMutation({
    mutationFn: () =>
      api<any>(`/vulnerabilities/${focus}/assess${assessAsset ? qs({ asset_id: Number(assessAsset) }) : ""}`, { method: "POST" }),
    onSuccess: (result) => {
      push("success", `Assessment recorded at ${Number(result.assessment?.risk_score ?? 0).toFixed(1)}/100.`);
      queryClient.invalidateQueries({ queryKey: ["vulnerability-detail", focus] });
      queryClient.invalidateQueries({ queryKey: ["risk-summary"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (error: any) => push("error", error.message || "The assessment could not be created."),
  });

  const exportCsv = async () => {
    try {
      await downloadFile(`/vulnerabilities/export.csv${qs({ ...params, page: undefined, size: undefined })}`, "vulnerabilities.csv");
      push("success", "Vulnerability export downloaded.");
    } catch (error: any) {
      push("error", error.message || "Export failed.");
    }
  };

  const facets = data?.facets || {};
  const severities: Array<{ name: string; count: number }> = facets.severities || [];
  const sources: Array<{ name: string; count: number }> = facets.sources || [];
  const matchedAssets: any[] = detail?.asset_matches || [];
  const threats: any[] = detail?.threats || [];
  const hasValidated = matchedAssets.some((match) => ["potentially_exposed", "confirmed"].includes(match.status));
  const analyticsItems: Vulnerability[] = analyticsQuery.data?.items || [];

  const severitySplit = useMemo(() => {
    const counts = new Map<string, number>();
    analyticsItems.forEach((item) => {
      const label = titleCase(item.cvss_severity || "unknown");
      counts.set(label, (counts.get(label) || 0) + 1);
    });
    return CVSS_BANDS.filter((band) => counts.get(band)).map((band) => ({ name: band, value: counts.get(band) || 0 }));
  }, [analyticsItems]);

  const histogram = useMemo(() => {
    const bins = [
      { name: "0–2", min: 0, max: 2, color: "#42c98a" },
      { name: "2–4", min: 2, max: 4, color: "#6fdcb0" },
      { name: "4–6", min: 4, max: 6, color: "#ffd166" },
      { name: "6–8", min: 6, max: 8, color: "#ff963d" },
      { name: "8–10", min: 8, max: 10.01, color: "#ff4d5e" },
    ];
    return bins.map((bin) => ({
      name: bin.name,
      color: bin.color,
      value: analyticsItems.filter((item) => {
        const score = Number(item.cvss_score ?? 0);
        return score >= bin.min && score < bin.max;
      }).length,
    }));
  }, [analyticsItems]);

  const productTreemap = useMemo(() => {
    const counts = new Map<string, { count: number; maxCvss: number }>();
    analyticsItems.forEach((item) => {
      const seen = new Set<string>();
      (item.affected_products || []).forEach((product: any) => {
        const name = product.product || product.vendor || "Unspecified";
        if (seen.has(name)) return;
        seen.add(name);
        const entry = counts.get(name) || { count: 0, maxCvss: 0 };
        entry.count += 1;
        entry.maxCvss = Math.max(entry.maxCvss, Number(item.cvss_score ?? 0));
        counts.set(name, entry);
      });
    });
    return [...counts.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 12)
      .map(([name, entry]) => ({
        name,
        value: entry.count,
        color: riskColor(entry.maxCvss * 10),
        detail: `${entry.count} advisory(ies) · highest CVSS ${entry.maxCvss.toFixed(1)}`,
        meta: `${entry.count} · CVSS ${entry.maxCvss.toFixed(1)}`,
      }));
  }, [analyticsItems]);

  const timeline = useMemo(() => {
    if (!analyticsItems.length) return [];
    const times = analyticsItems.map((item) => new Date(item.published_at).getTime()).filter((value) => !Number.isNaN(value));
    if (!times.length) return [];
    const step = range === "24h" ? 6 * 3600_000 : range === "7d" ? 86400_000 : 7 * 86400_000;
    const start = publishedSlot(Math.min(...times), range);
    const end = publishedSlot(Math.max(...times), range);
    const buckets: Array<{ key: string; name: string; critical: number; high: number; medium: number; low: number }> = [];
    for (let cursor = start; cursor <= end; cursor += step) {
      const date = new Date(cursor);
      const iso = new Date(publishedSlot(cursor, range)).toISOString();
      buckets.push({
        key: iso,
        name: range === "24h" ? `${String(date.getHours()).padStart(2, "0")}:00` : range === "7d" ? fmtDate(iso) : `w/c ${fmtDate(iso.slice(0, 10))}`,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      });
    }
    const lookup = new Map(buckets.map((bucket) => [bucket.key, bucket]));
    analyticsItems.forEach((item) => {
      const time = new Date(item.published_at).getTime();
      if (Number.isNaN(time)) return;
      const bucket = lookup.get(new Date(publishedSlot(time, range)).toISOString());
      if (!bucket) return;
      const key = SEVERITY_SERIES.includes(item.cvss_severity) ? item.cvss_severity : "low";
      bucket[key as "critical" | "high" | "medium" | "low"] += 1;
    });
    return buckets;
  }, [analyticsItems, range]);

  const relationshipGraph = useMemo(() => {
    const productCves = new Map<string, Vulnerability[]>();
    analyticsItems.forEach((item) => {
      const names = new Set<string>();
      (item.affected_products || []).forEach((product: any) => {
        if (product.product) names.add(product.product);
      });
      names.forEach((name) => {
        if (!productCves.has(name)) productCves.set(name, []);
        productCves.get(name)!.push(item);
      });
    });
    const top = [...productCves.entries()].sort((a, b) => b[1].length - a[1].length).slice(0, 6);
    const nodes: any[] = [];
    const edges: any[] = [];
    const seen = new Set<string>();
    top.forEach(([name, vulns]) => {
      const productId = `product:${name}`;
      const maxCvss = Math.max(...vulns.map((item) => Number(item.cvss_score ?? 0)));
      nodes.push({
        id: productId,
        ref: productId,
        name,
        kind: "product",
        category: "Affected product",
        severity: maxCvss >= 9 ? "critical" : maxCvss >= 7 ? "high" : maxCvss >= 4 ? "medium" : "low",
        risk: maxCvss * 10,
        degree: vulns.length,
      });
      vulns.slice(0, 4).forEach((item) => {
        const cveId = item.cve_id;
        if (!seen.has(cveId)) {
          seen.add(cveId);
          nodes.push({
            id: cveId,
            ref: cveId,
            name: cveId,
            kind: "cve",
            cve: cveId,
            category: titleCase(item.cvss_severity || "unknown"),
            severity: item.cvss_severity,
            risk: Number(item.cvss_score ?? 0) * 10,
            degree: 0,
          });
        }
        edges.push({ source: productId, target: cveId, score: 0.7, reasons: [{ label: "affected product range" }] });
      });
    });
    const degree: Record<string, number> = {};
    edges.forEach((edge) => {
      degree[edge.source] = (degree[edge.source] || 0) + 1;
      degree[edge.target] = (degree[edge.target] || 0) + 1;
    });
    nodes.forEach((node) => { node.degree = degree[node.id] || node.degree || 0; });
    return { nodes, edges };
  }, [analyticsItems]);

  return (
    <>
      <PageHeader
        title="Vulnerability intelligence"
        kicker="Advisories · CVSS · EPSS · KEV"
        description="CVSS technical severity, EPSS exploitation probability and known-exploited status are kept as three independent signals. Asset exposure only counts after product and version validation."
        aside={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span><span className="text-ink">{fmtNumber(stats?.in_range)}</span> in range</span>
            <span><span className="text-crit">{fmtNumber(stats?.known_exploited)}</span> known exploited</span>
            <span><span className="text-high">{fmtNumber(stats?.epss_high)}</span> EPSS ≥ 50%</span>
            <span><span className="text-ink">{stats?.average_cvss ?? "—"}</span> avg CVSS</span>
          </div>
        }
        actions={
          <>
            <RangeTabs value={range} onChange={setRange} />
            <button className="btn btn-ghost btn-sm" onClick={exportCsv}><Download size={13} /> Export CSV</button>
          </>
        }
      />

      <Panel className="mb-4">
        <div className="grid gap-3 p-3.5 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-[minmax(220px,1.4fr)_repeat(3,minmax(128px,0.8fr))_minmax(248px,1fr)]">
          <div>
            <span className="field-label">Search</span>
            <SearchField value={q} onChange={setQ} placeholder="CVE, title, product, vendor…" />
          </div>
          <FilterSelect
            label="CVSS severity"
            value={severity}
            onChange={setSeverity}
            options={[
              { value: "all", label: `All severities (${fmtNumber(data?.total)})` },
              ...severities.map((entry) => ({ value: entry.name, label: `${titleCase(entry.name)} (${entry.count})` })),
            ]}
          />
          <FilterSelect
            label="Source"
            value={source}
            onChange={setSource}
            options={[{ value: "all", label: "All sources" }, ...sources.map((entry) => ({ value: entry.name, label: `${entry.name} (${entry.count})` }))]}
          />
          <FilterSelect
            label="EPSS floor"
            value={epssMin}
            onChange={setEpssMin}
            options={[
              { value: "all", label: "Any probability" },
              { value: "0.1", label: "≥ 10%" },
              { value: "0.5", label: "≥ 50%" },
              { value: "0.8", label: "≥ 80%" },
            ]}
          />
          <div className="flex items-center gap-2">
            <TogglePill active={kevOnly} onChange={() => setKevOnly((value) => !value)} />
            <select className="field h-[38px] min-w-0 flex-1 text-[11px]" value={sortBy} onChange={(event) => setSortBy(event.target.value)} aria-label="Sort vulnerabilities">
              {SORTS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
            </select>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line px-3.5 py-2 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
          <span>{fmtNumber(data?.total)} records</span>
          <span className="text-crit">{stats?.cvss_severity?.find((entry: any) => entry.name === "Critical")?.value ?? 0} critical in range</span>
          <span>{fmtNumber(stats?.kev_total)} ever listed as known exploited</span>
          <span className="ml-auto normal-case tracking-normal">{stats?.note}</span>
        </div>
      </Panel>

      <Panel className="mb-4" ticks>
        <PanelHead
          title="Vulnerability landscape"
          kicker={`${fmtNumber(analyticsItems.length)} advisories published in range`}
          right={<span className="chip">three independent signals</span>}
        />
        {analyticsQuery.isError ? (
          <ErrorState compact message={(analyticsQuery.error as any)?.message} retry={() => analyticsQuery.refetch()} />
        ) : analyticsQuery.isLoading ? (
          <LoadingBlock rows={6} label="Loading vulnerability analytics" />
        ) : !analyticsItems.length ? (
          <div className="px-4 py-12 text-center">
            <p className="text-[12px] text-mist">No advisories were published in this range.</p>
            <p className="mt-1 text-[10.5px] text-dim">Widen the range to see severity mix, affected products and the publication timeline.</p>
          </div>
        ) : (
          <div className="grid gap-px bg-line [&>*]:min-w-0 xl:grid-cols-2">
            <div className="bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">CVSS severity</span>}>
                CVE severity distribution
              </SectionLabel>
              <DistributionDonut
                data={severitySplit}
                height={168}
                centerLabel="advisories"
                centerValue={analyticsItems.length}
                colors={severitySplit.map((entry) => CVSS_COLORS[entry.name] || "#78b7ff")}
              />
              <p className="mt-2 text-[10px] leading-relaxed text-dim">
                CVSS bands describe technical severity only. Known-exploited status and EPSS are tracked separately and never folded into this count.
              </p>
            </div>
            <div className="bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">base score bins</span>}>
                CVSS histogram
              </SectionLabel>
              <DailyBars data={histogram} height={168} color="#49b8ff" emptyLabel="No scored advisories in range." />
              <p className="mt-2 text-[10px] leading-relaxed text-dim">
                Counts per CVSS band. A cluster in the 8–10 range marks severity concentration, not evidence that any estate asset is affected.
              </p>
            </div>
            <div className="bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">tile = advisory count</span>}>
                Affected software treemap
              </SectionLabel>
              <Treemap items={productTreemap} height={244} emptyLabel="No affected product ranges supplied." />
              <p className="mt-1 text-[10px] leading-relaxed text-dim">
                Tile area counts advisories naming each product; colour is the highest CVSS among them. No product match is treated as asset exposure until inventory validation.
              </p>
            </div>
            <div className="bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{timeline.length} bucket(s)</span>}>
                Publication timeline
              </SectionLabel>
              <TrendArea
                data={timeline}
                series={[
                  { key: "critical", name: "Critical", color: "#ff4d5e" },
                  { key: "high", name: "High", color: "#ff963d" },
                  { key: "medium", name: "Medium", color: "#ffd166" },
                  { key: "low", name: "Low", color: "#42c98a" },
                ]}
                height={214}
                stacked
              />
              <p className="mt-1 text-[10px] leading-relaxed text-dim">
                Advisories grouped by publication bucket and CVSS band. Publication timing reflects the feed, not when exploitation began.
              </p>
            </div>
            <div className="bg-surface p-4 xl:col-span-2">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">select a CVE to open · select a product to filter</span>}>
                CVE ↔ affected product relationships
              </SectionLabel>
              {relationshipGraph.nodes.length ? (
                <CorrelationGraph
                  nodes={relationshipGraph.nodes}
                  edges={relationshipGraph.edges}
                  height={500}
                  maxNodes={60}
                  onSelect={(node) => {
                    if (node.kind === "cve" && node.cve) openDrawer(String(node.cve));
                    else if (node.kind === "product") setQ(String(node.name));
                  }}
                />
              ) : (
                <p className="py-10 text-center text-[11px] text-dim">No structured product ranges were supplied for advisories in this range.</p>
              )}
              <p className="mt-1 text-[10px] leading-relaxed text-dim">
                Edges exist only where an advisory names the product range. Shared-product links are informational overlap, not proof of a shared exploit or campaign.
              </p>
            </div>
          </div>
        )}
      </Panel>

      <Panel>
        {listQuery.isError ? (
          <ErrorState message={(listQuery.error as any)?.message} retry={() => listQuery.refetch()} />
        ) : listQuery.isLoading ? (
          <LoadingBlock rows={9} label="Loading vulnerability intelligence" />
        ) : !data?.items.length ? (
          <EmptyState
            title="No vulnerability records match this view"
            detail="EPSS and CVSS are independent evidence. Widen the range or relax the probability floor rather than treating an empty view as an absence of risk."
            icon={<Bug size={19} />}
            action={<button className="btn btn-ghost btn-sm" onClick={() => { setQ(""); setSeverity("all"); setSource("all"); setKevOnly(false); setEpssMin("all"); setRange("90d"); }}>Reset filters</button>}
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-shell">
                <thead>
                  <tr>
                    <th>CVE</th>
                    <th>Advisory</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>EPSS</th>
                    <th>Exploited</th>
                    <th className="hidden md:table-cell">Affected</th>
                    <th className="hidden lg:table-cell">Published</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <tr key={item.id} onClick={() => openDrawer(item.cve_id)} className={focus === item.cve_id ? "bg-ion/[0.05]" : undefined}>
                      <td>
                        <div className="flex items-center gap-1.5 font-mono text-[10.5px] text-info">
                          {item.cve_id}
                        </div>
                        <div className="mt-0.5 font-mono text-[8px] uppercase tracking-[0.08em] text-dim">{item.source}</div>
                      </td>
                      <td className="max-w-[420px]">
                        <div className="truncate text-[12px] text-ink">{item.title}</div>
                        <div className="mt-0.5 font-mono text-[8px] uppercase tracking-[0.06em] text-dim">
                          {item.ransomware_use ? "Ransomware use observed" : "No ransomware-use flag"}
                        </div>
                      </td>
                      <td><SeverityBadge severity={item.cvss_severity} /></td>
                      <td>
                        <span className="tnum font-mono text-[11px]" style={{ color: riskColor((Number(item.cvss_score ?? 0)) * 10) }}>
                          {item.cvss_score ?? "—"}
                        </span>
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <span className="tnum font-mono text-[10.5px] text-ink">{fmtPct(item.epss_score, 0)}</span>
                          <div className="w-12"><ProgressBar value={(item.epss_score || 0) * 100} color="#9a8cff" height={3} /></div>
                        </div>
                      </td>
                      <td>
                        {item.known_exploited ? (
                          <span className="inline-flex items-center gap-1 font-mono text-[8.5px] uppercase tracking-[0.08em] text-high">
                            <Flame size={10} /> KEV
                          </span>
                        ) : (
                          <span className="font-mono text-[9px] text-dim">—</span>
                        )}
                      </td>
                      <td className="hidden md:table-cell">
                        <span className="font-mono text-[9.5px] text-dim">{item.affected_products?.length || 0} product range(s)</span>
                      </td>
                      <td className="hidden lg:table-cell">
                        <span className="text-[10.5px] text-mist">{fmtDate(item.published_at)}</span>
                        <div className="mt-0.5 font-mono text-[8px] text-dim">{relTime(item.published_at)}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={data.page} pages={data.pages} total={data.total} onPage={setPage} />
          </>
        )}
      </Panel>

      <Drawer
        open={Boolean(focus)}
        onClose={closeDrawer}
        width="max-w-[760px]"
        title={
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[13px] text-info">{record?.cve_id || focus}</span>
            {record && <SeverityBadge severity={record.cvss_severity} />}
          </div>
        }
        subtitle={
          record && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
              <span>{record.source}</span><span>·</span>
              <span>Published {fmtDate(record.published_at)}</span><span>·</span>
              <span>Modified {fmtDate(record.modified_at)}</span>
              {record.source_url && (
                <a href={record.source_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-ion hover:text-crystal">
                  Source advisory <ExternalLink size={9} />
                </a>
              )}
            </div>
          )
        }
        footer={
          can("analyst") ? (
            <>
              <span className="mr-auto font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
                {threats.length ? "Assessment uses the shared risk model" : "No linked threat — assessment unavailable"}
              </span>
              <select className="field h-[34px] w-[220px] text-[11px]" value={assessAsset} onChange={(event) => setAssessAsset(event.target.value)} aria-label="Asset for assessment">
                <option value="">Generic asset profile</option>
                {matchedAssets.map((match) => (
                  <option key={match.asset.id} value={match.asset.id}>{match.asset.ref} · {match.asset.name}</option>
                ))}
              </select>
              <button className="btn btn-primary btn-sm" disabled={!threats.length || assess.isPending} onClick={() => assess.mutate()}>
                <Sparkles size={12} /> {assess.isPending ? "Assessing…" : "Create assessment"}
              </button>
            </>
          ) : (
            <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">Read-only — analysts can create assessments</span>
          )
        }
      >
        {detailQuery.isError ? (
          <ErrorState message={(detailQuery.error as any)?.message} retry={() => detailQuery.refetch()} compact />
        ) : detailQuery.isLoading || !record ? (
          <LoadingBlock rows={8} label="Loading advisory" />
        ) : (
          <div>
            <h2 className="font-display text-[19px] font-semibold leading-snug text-ink">{record.title}</h2>

            <div className="mt-4 grid gap-2 sm:grid-cols-3">
              <div className="rounded-lg border border-line bg-shade/25 p-3">
                <div className="flex items-center justify-between">
                  <span className="panel-kicker">CVSS base</span>
                  <span className="font-mono text-[8px] text-dim">technical severity</span>
                </div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="tnum font-display text-[28px] font-semibold leading-none" style={{ color: riskColor((Number(record.cvss_score ?? 0)) * 10) }}>{record.cvss_score ?? "—"}</span>
                  <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">/ 10</span>
                </div>
                <div className="mt-2"><ProgressBar value={(Number(record.cvss_score ?? 0) / 10) * 100} color={riskColor((Number(record.cvss_score ?? 0)) * 10)} height={3} /></div>
              </div>
              <div className="rounded-lg border border-line bg-shade/25 p-3">
                <div className="flex items-center justify-between">
                  <span className="panel-kicker">EPSS</span>
                  <span className="font-mono text-[8px] text-dim">30-day probability</span>
                </div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="tnum font-display text-[28px] font-semibold leading-none text-violet">{fmtPct(record.epss_score, 1)}</span>
                  <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">pctl {record.epss_percentile != null ? fmtPct(record.epss_percentile, 0) : "—"}</span>
                </div>
                <div className="mt-2"><ProgressBar value={(record.epss_score || 0) * 100} color="#9a8cff" height={3} /></div>
              </div>
              <div className={`rounded-lg border p-3 ${record.known_exploited ? "border-high/30 bg-high/[0.06]" : "border-line bg-shade/25"}`}>
                <div className="flex items-center justify-between">
                  <span className="panel-kicker">Exploitation</span>
                  {record.known_exploited ? <Flame size={12} className="text-high" /> : <ShieldCheck size={12} className="text-low" />}
                </div>
                <div className="mt-2 font-display text-[15px] font-semibold leading-tight text-ink">
                  {record.known_exploited ? "Known exploited" : "No KEV evidence"}
                </div>
                <div className="mt-1 font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">
                  {record.kev_due_date ? `Remediation due ${fmtDate(record.kev_due_date)}` : "Absence is not proof of safety"}
                </div>
              </div>
            </div>

            <div className="mt-3"><InlineNotice tone="ion">{detail.evidence_note}</InlineNotice></div>

            <DrawerSection title="Advisory description" kicker="Source material">
              <p className="whitespace-pre-line text-[11.5px] leading-relaxed text-ink">{record.description || "The source did not include a description."}</p>
              {record.remediation && (
                <div className="mt-3 rounded-lg border border-low/20 bg-low/[0.04] px-3 py-2.5">
                  <div className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-low">Vendor remediation</div>
                  <p className="mt-1 text-[11.5px] leading-relaxed text-ink">{record.remediation}</p>
                </div>
              )}
            </DrawerSection>

            <DrawerSection title="Affected product ranges" kicker="Version validation input">
              <ProductList products={record.affected_products} />
            </DrawerSection>

            <DrawerSection
              title="Inventory exposure"
              kicker="Validated against registered assets"
              right={<span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{detail.validated_count} validated · {detail.needs_verification_count} need verification</span>}
            >
              {!matchedAssets.length ? (
                <p className="text-[11px] text-dim">No registered asset matched this advisory after product and version checks.</p>
              ) : (
                <div className="space-y-1.5">
                  {matchedAssets.map((match) => (
                    <div key={`${match.asset.id}-${match.status}`} className="rounded-md border border-line bg-shade/20 px-3 py-2.5">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[8.5px] text-dim">{match.asset.ref}</span>
                          <span className="text-[11.5px] text-ink">{match.asset.name}</span>
                          <StatusBadge status={match.status} />
                        </div>
                        <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">
                          {titleCase(match.asset.category)} · {match.asset.exposure} · criticality {match.asset.criticality}/5
                        </span>
                      </div>
                      <div className="mt-1.5 font-mono text-[9px] text-mist">{match.asset.software} {match.asset.software_version}</div>
                      <p className="mt-1 text-[10.5px] leading-relaxed text-dim">{match.reason}</p>
                    </div>
                  ))}
                </div>
              )}
            </DrawerSection>

            <DrawerSection title="Linked threat records" kicker="Ingested intelligence">
              {!threats.length ? (
                <p className="text-[11px] text-dim">No threat record references this CVE yet. Vulnerability data still stands on its own evidence.</p>
              ) : (
                <div className="space-y-1.5">
                  {threats.map((threat) => (
                    <Link key={threat.id} to={`/app/threats?focus=${threat.ref}`} className="flex items-center justify-between gap-3 rounded-md border border-line bg-shade/20 px-3 py-2 hover:border-ion/30">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[8.5px] text-dim">{threat.ref}</span>
                          <span className="truncate text-[11px] text-ink">{threat.name}</span>
                        </div>
                        <div className="mt-0.5 font-mono text-[8px] uppercase tracking-[0.08em] text-dim">{threat.source} · {relTime(threat.published_at)}</div>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <ScoreChip score={threat.risk_score} />
                        <SeverityBadge severity={threat.severity} />
                        <ArrowUpRight size={12} className="text-dim" />
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </DrawerSection>

            <DrawerSection title="Recorded assessments" kicker="Explainable scoring">
              {!detail.assessments?.length ? (
                <p className="text-[11px] text-dim">No assessment has been created for this advisory.</p>
              ) : (
                <div className="space-y-1.5">
                  {detail.assessments.map((assessment: any) => (
                    <div key={assessment.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-line bg-shade/20 px-3 py-2">
                      <div>
                        <div className="font-mono text-[8.5px] text-dim">{assessment.ref}</div>
                        <div className="mt-0.5 text-[11px] text-mist">{assessment.asset?.name || "Generic asset profile"}</div>
                      </div>
                      <div className="flex items-center gap-2">
                        <StatusBadge status={assessment.urgency} />
                        <span className="tnum font-mono text-[11px]" style={{ color: riskColor(assessment.risk_score) }}>{Number(assessment.risk_score).toFixed(1)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </DrawerSection>

            <DrawerSection title="References" kicker="Source provenance" right={<CopyButton value={record.cve_id} label="CVE" />}>
              {!record.references?.length ? (
                <p className="text-[11px] text-dim">No external references were attached.</p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {record.references.map((reference, index) => (
                    <a key={`${reference.url}-${index}`} href={reference.url} target="_blank" rel="noreferrer" className="chip hover:border-ion/40 hover:text-ion">
                      {reference.label || `Reference ${index + 1}`} <ExternalLink size={9} />
                    </a>
                  ))}
                </div>
              )}
            </DrawerSection>

            {hasValidated && (
              <InlineNotice tone="med" className="mt-2">
                At least one asset is version-validated for this advisory. Exposure is recorded only after analyst confirmation or automated range checking; no blocking action is executed by this platform.
              </InlineNotice>
            )}
          </div>
        )}
      </Drawer>
    </>
  );
}

function TogglePill({ active, onChange }: { active: boolean; onChange: () => void }) {
  return (
    <button
      onClick={onChange}
      aria-pressed={active}
      className={`btn btn-sm h-[38px] ${active ? "btn-primary" : "btn-ghost"}`}
      title="Show only vulnerabilities with known exploitation evidence"
    >
      <Flame size={12} /> KEV only
    </button>
  );
}
