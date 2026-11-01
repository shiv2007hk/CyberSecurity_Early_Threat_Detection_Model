import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowUpRight,
  Bookmark,
  BookmarkCheck,
  BrainCircuit,
  Download,
  ExternalLink,
  Fingerprint,
  GitFork,
  Layers,
  MessageSquarePlus,
  Radar,
  RefreshCw,
  ShieldAlert,
  Sparkles,
  Target,
} from "lucide-react";
import clsx from "clsx";
import { api, downloadFile, qs, type Paginated, type Threat } from "../../lib/api";
import { fmtDate, fmtNumber, fmtPct, objectEntries, relTime, riskColor, severityMeta, titleCase } from "../../lib/format";
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
  Tabs,
  useToast,
} from "../../components/ui";

const SORT_OPTIONS = [
  { value: "risk_score", label: "Risk score" },
  { value: "published_at", label: "Published" },
  { value: "cvss", label: "CVSS" },
  { value: "epss", label: "EPSS" },
  { value: "severity", label: "Severity" },
  { value: "name", label: "Record name" },
];

function FilterSelect({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: Array<{ value: string; label: string }> }) {
  return (
    <label className="min-w-0">
      <span className="field-label">{label}</span>
      <select className="field" value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
    </label>
  );
}

function FactorBars({ factors }: { factors: any[] }) {
  if (!factors?.length) return <p className="text-[11px] text-dim">No factor breakdown recorded.</p>;
  return (
    <div className="space-y-2.5">
      {factors.map((factor) => (
        <div key={factor.key}>
          <div className="flex items-baseline justify-between gap-3">
            <span className="text-[10.5px] text-mist">{factor.label}</span>
            <span className="tnum shrink-0 font-mono text-[9px] text-dim">
              {Number(factor.contribution).toFixed(1)} pts · w {Number(factor.weight).toFixed(2)}
            </span>
          </div>
          <div className="mt-1"><ProgressBar value={(Number(factor.normalized) / 10) * 100} color="#49b8ff" height={3} /></div>
          {factor.note && <p className="mt-1 text-[9.5px] leading-relaxed text-dim">{factor.note}</p>}
        </div>
      ))}
    </div>
  );
}

export default function Threats() {
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();

  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("all");
  const [category, setCategory] = useState("all");
  const [source, setSource] = useState("all");
  const [status, setStatus] = useState("all");
  const [savedOnly, setSavedOnly] = useState(false);
  const [range, setRange] = useState("90d");
  const [sortBy, setSortBy] = useState("risk_score");
  const [page, setPage] = useState(1);
  const [tab, setTab] = useState("overview");
  const [note, setNote] = useState("");
  const focus = searchParams.get("focus");

  useEffect(() => setPage(1), [q, severity, category, source, status, savedOnly, range, sortBy]);

  const params = { q, severity, category, source, status, saved: savedOnly ? true : undefined, range, sort_by: sortBy, order: "desc", page, size: 20 };
  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["threats", params],
    queryFn: () => api<Paginated<Threat>>(`/threats${qs(params)}`),
  });

  const detailQuery = useQuery({
    queryKey: ["threat-detail", focus],
    queryFn: () => api<any>(`/threats/${focus}`),
    enabled: Boolean(focus),
  });

  const detail = detailQuery.data;
  const threat = detail?.threat || data?.items.find((item) => item.ref === focus);

  const closeDrawer = () => {
    setTab("overview");
    setNote("");
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete("focus");
      return next;
    });
  };

  const openDrawer = (ref: string) => {
    setTab("overview");
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("focus", ref);
      return next;
    });
  };

  const updateThreat = useMutation({
    mutationFn: (payload: Record<string, any>) => api(`/threats/${focus}`, { method: "PATCH", body: JSON.stringify(payload) }),
    onSuccess: (_result, payload) => {
      push("success", payload.status ? `Threat marked ${titleCase(String(payload.status))}.` : "Saved state updated.");
      queryClient.invalidateQueries({ queryKey: ["threat-detail", focus] });
      queryClient.invalidateQueries({ queryKey: ["threats"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (err: any) => push("error", err.message || "The threat could not be updated."),
  });

  const addNote = useMutation({
    mutationFn: () => api(`/threats/${focus}/notes`, { method: "POST", body: JSON.stringify({ body: note }) }),
    onSuccess: () => {
      setNote("");
      push("success", "Investigation note attached to the record.");
      queryClient.invalidateQueries({ queryKey: ["threat-detail", focus] });
    },
    onError: (err: any) => push("error", err.message || "The note could not be saved."),
  });

  const assess = useMutation({
    mutationFn: () => api<any>("/risk/assess", { method: "POST", body: JSON.stringify({ threat_id: threat?.id }) }),
    onSuccess: (result) => {
      push("success", `Assessment recorded at ${Number(result.assessment?.risk_score ?? 0).toFixed(1)}/100.`);
      setTab("risk");
      queryClient.invalidateQueries({ queryKey: ["threat-detail", focus] });
      queryClient.invalidateQueries({ queryKey: ["risk-summary"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (err: any) => push("error", err.message || "Assessment could not be created."),
  });

  const facets = data?.facets || {};
  const severities: Array<{ name: string; count: number }> = facets.severities || [];
  const cats: Array<{ name: string; count: number }> = facets.categories || [];
  const sources: Array<{ name: string; count: number }> = facets.sources || [];
  const statuses: Array<{ name: string; count: number }> = facets.statuses || [];
  const criticalCount = severities.find((entry) => entry.name === "critical")?.count || 0;
  const highCount = severities.find((entry) => entry.name === "high")?.count || 0;

  const activeFilterCount = [severity, category, source, status].filter((value) => value !== "all").length + (savedOnly ? 1 : 0) + (q ? 1 : 0);

  const exportCsv = async () => {
    try {
      await downloadFile(`/threats/export.csv${qs({ ...params, page: undefined, size: undefined })}`, "threats.csv");
      push("success", "Threat export downloaded.");
    } catch (err: any) {
      push("error", err.message || "Export failed.");
    }
  };

  return (
    <>
      <PageHeader
        title="Threat intelligence"
        description="Ingested reports with provenance, deterministic AI-assisted classification, evidence-backed risk and analyst investigation. Source text is never presented as verified fact."
        aside={
          <div className="flex flex-wrap items-center gap-2 rounded-lg border border-line/70 bg-surface/80 px-2.5 py-1.5 font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim backdrop-blur-md">
            <span>{fmtNumber(data?.total)} records</span><span>·</span>
            <span className="text-crit">{criticalCount} critical</span><span>·</span>
            <span className="text-high">{highCount} high</span><span>·</span>
            <span>{fmtNumber(sources.length)} sources in view</span>
          </div>
        }
        actions={
          <>
            <RangeTabs value={range} onChange={setRange} />
            <button className="btn btn-ghost btn-sm" onClick={exportCsv}><Download size={13} /> Export CSV</button>
          </>
        }
      />

      <Panel className="mb-4" ticks={false}>
        <div className="grid gap-3 p-3.5 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-[minmax(220px,1.6fr)_repeat(4,minmax(120px,0.8fr))_auto]">
          <div>
            <span className="field-label">Search</span>
            <SearchField value={q} onChange={setQ} placeholder="Name, CVE, technology, reference…" />
          </div>
          <FilterSelect
            label="Severity"
            value={severity}
            onChange={setSeverity}
            options={[{ value: "all", label: `All severities (${fmtNumber(data?.total)})` }, ...severities.map((entry) => ({ value: entry.name, label: `${titleCase(entry.name)} (${entry.count})` }))]}
          />
          <FilterSelect
            label="Category"
            value={category}
            onChange={setCategory}
            options={[{ value: "all", label: "All categories" }, ...cats.map((entry) => ({ value: entry.name, label: `${titleCase(entry.name)} (${entry.count})` }))]}
          />
          <FilterSelect
            label="Source"
            value={source}
            onChange={setSource}
            options={[{ value: "all", label: "All sources" }, ...sources.map((entry) => ({ value: entry.name, label: `${entry.name} (${entry.count})` }))]}
          />
          <FilterSelect
            label="Analyst status"
            value={status}
            onChange={setStatus}
            options={[{ value: "all", label: "Any status" }, ...statuses.map((entry) => ({ value: entry.name, label: `${titleCase(entry.name)} (${entry.count})` }))]}
          />
          <div className="flex items-end gap-2">
            <button
              onClick={() => setSavedOnly((value) => !value)}
              className={clsx("btn btn-sm flex-1 sm:flex-none", savedOnly ? "btn-primary" : "btn-ghost")}
              aria-pressed={savedOnly}
            >
              <Bookmark size={12} /> Saved
            </button>
            <select className="field h-[31px] w-[124px] text-[11px]" value={sortBy} onChange={(event) => setSortBy(event.target.value)} aria-label="Sort threats">
              {SORT_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
            </select>
          </div>
        </div>
        {activeFilterCount > 0 && (
          <div className="flex flex-wrap items-center gap-2 border-t border-line px-3.5 py-2">
            <span className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">{activeFilterCount} filter(s) applied</span>
            <button
              onClick={() => { setQ(""); setSeverity("all"); setCategory("all"); setSource("all"); setStatus("all"); setSavedOnly(false); }}
              className="font-mono text-[9px] uppercase tracking-[0.1em] text-ion hover:text-crystal"
            >
              Clear all
            </button>
            {isFetching && <span className="ml-auto flex items-center gap-1.5 font-mono text-[8px] uppercase tracking-[0.1em] text-dim"><RefreshCw size={9} className="animate-spin" /> refreshing</span>}
          </div>
        )}
      </Panel>

      <Panel>
        {isError ? (
          <ErrorState message={(error as any)?.message} retry={() => refetch()} />
        ) : isLoading ? (
          <LoadingBlock rows={8} label="Loading threat intelligence" />
        ) : !data?.items.length ? (
          <EmptyState
            title="No threat records match the current filters"
            detail="Adjust the severity, source or time window. An empty result is not evidence that no threat exists."
            icon={<Radar size={19} />}
            action={<button className="btn btn-ghost btn-sm" onClick={() => { setQ(""); setSeverity("all"); setCategory("all"); setSource("all"); setStatus("all"); setSavedOnly(false); setRange("90d"); }}>Reset filters</button>}
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-shell">
                <thead>
                  <tr>
                    <th>Record</th>
                    <th>Severity</th>
                    <th className="hidden lg:table-cell">Technical signal</th>
                    <th className="hidden xl:table-cell">Classification</th>
                    <th>Risk</th>
                    <th className="hidden md:table-cell">Source</th>
                    <th className="hidden sm:table-cell">Published</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <tr key={item.id} onClick={() => openDrawer(item.ref)} className={focus === item.ref ? "bg-ion/[0.05]" : undefined}>
                      <td className="max-w-[330px]">
                        <div className="flex items-start gap-2">
                          <span className="mt-0.5 shrink-0 font-mono text-[8.5px] text-dim">{item.ref}</span>
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5">
                              <span className="truncate text-[12px] text-ink">{item.name}</span>
                              {item.is_saved && <BookmarkCheck size={11} className="shrink-0 text-ion" />}
                            </div>
                            <div className="mt-0.5 flex flex-wrap items-center gap-x-1.5 font-mono text-[8px] uppercase tracking-[0.06em] text-dim">
                              {item.affected_technology && <span>{item.affected_technology}</span>}
                              {item.cve_id && <><span>·</span><span className="text-info">{item.cve_id}</span></>}
                              {item.indicator_count > 0 && <><span>·</span><span>{item.indicator_count} indicators</span></>}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td><SeverityBadge severity={item.severity} /></td>
                      <td className="hidden lg:table-cell">
                        <div className="flex items-center gap-2 font-mono text-[9px] text-dim">
                          <span title="CVSS base score">CVSS <span className="text-ink">{item.cvss_score ?? "—"}</span></span>
                          <span title="EPSS probability">EPSS <span className="text-ink">{item.epss_score !== null && item.epss_score !== undefined ? `${(item.epss_score * 100).toFixed(0)}%` : "—"}</span></span>
                          {item.known_exploited && <span className="rounded border border-high/30 bg-high/10 px-1 py-[1px] text-[7px] uppercase tracking-[0.08em] text-high">KEV</span>}
                        </div>
                      </td>
                      <td className="hidden xl:table-cell">
                        <div className="text-[10.5px] text-ink">{titleCase(item.ai_category || item.category)}</div>
                        <div className="mt-0.5 font-mono text-[8px] uppercase tracking-[0.08em] text-dim">AI confidence {fmtPct(item.ai_confidence, 0)}</div>
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <span className="tnum font-mono text-[11.5px]" style={{ color: riskColor(item.risk_score) }}>{Number(item.risk_score ?? 0).toFixed(0)}</span>
                          <div className="w-10"><ProgressBar value={Number(item.risk_score ?? 0)} color={riskColor(item.risk_score)} height={3} /></div>
                        </div>
                        <div className="mt-0.5 font-mono text-[8px] uppercase tracking-[0.06em] text-dim">{item.risk_category}</div>
                      </td>
                      <td className="hidden whitespace-nowrap font-mono text-[9px] uppercase tracking-[0.06em] text-dim md:table-cell">{item.source}</td>
                      <td className="hidden whitespace-nowrap text-[10px] text-dim sm:table-cell">{relTime(item.published_at)}</td>
                      <td><StatusBadge status={item.status} /></td>
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
        width="max-w-[720px]"
        title={
          threat ? (
            <div className="pr-6">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={threat.severity} />
                <span className="font-mono text-[9px] text-dim">{threat.ref}</span>
                <StatusBadge status={threat.status} />
              </div>
              <h2 className="mt-2 font-display text-[19px] font-semibold leading-snug text-ink">{threat.name}</h2>
            </div>
          ) : (
            <span className="font-mono text-[10px] text-dim">Loading record…</span>
          )
        }
        subtitle={
          threat ? (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">
              <span>{threat.source}</span>
              <span>·</span>
              <span>published {fmtDate(threat.published_at, true)}</span>
              {threat.cve_id && <><span>·</span><span className="text-info">{threat.cve_id}</span></>}
            </div>
          ) : undefined
        }
        footer={
          threat ? (
            <>
              <span className="mr-auto font-mono text-[8px] uppercase tracking-[0.1em] text-dim">Recorded evidence only · no external live lookup</span>
              {can("analyst") && (
                <>
                  <button className="btn btn-ghost btn-sm" onClick={() => updateThreat.mutate({ is_saved: !threat.is_saved })} disabled={updateThreat.isPending}>
                    {threat.is_saved ? <BookmarkCheck size={13} /> : <Bookmark size={13} />}
                    {threat.is_saved ? "Saved" : "Save record"}
                  </button>
                  <button className="btn btn-primary btn-sm" onClick={() => assess.mutate()} disabled={assess.isPending || !threat.id}>
                    <Sparkles size={13} className={assess.isPending ? "animate-pulse" : undefined} />
                    {assess.isPending ? "Scoring" : "Run risk assessment"}
                  </button>
                </>
              )}
            </>
          ) : undefined
        }
      >
        {detailQuery.isLoading ? (
          <LoadingBlock rows={10} label="Loading threat detail" />
        ) : detailQuery.isError ? (
          <ErrorState message={(detailQuery.error as any)?.message} retry={() => detailQuery.refetch()} compact />
        ) : detail && threat ? (
          <div className="space-y-5">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {[
                ["Risk score", `${Number(threat.risk_score ?? 0).toFixed(1)}`, riskColor(threat.risk_score)],
                ["CVSS", threat.cvss_score ?? "—", "#eef6ff"],
                ["EPSS", threat.epss_score !== null && threat.epss_score !== undefined ? `${(threat.epss_score * 100).toFixed(1)}%` : "—", "#eef6ff"],
                ["Evidence confidence", fmtPct(threat.confidence, 0), "#9a8cff"],
              ].map(([label, value, color]) => (
                <div key={String(label)} className="panel-quiet px-3 py-2.5">
                  <div className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">{label}</div>
                  <div className="tnum mt-1 font-display text-[18px] font-semibold" style={{ color: String(color) }}>{value}</div>
                </div>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-2 rounded-lg border border-line bg-shade/20 px-3 py-2">
              <span className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">Exploitation status</span>
              <span className="font-mono text-[10px] text-ink">{titleCase(threat.exploitation_status)}</span>
              <span className="mx-1 text-dim">·</span>
              <span className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">Urgency</span>
              <span className="font-mono text-[10px] text-ink">{titleCase(threat.urgency)}</span>
              <span className="mx-1 text-dim">·</span>
              <span className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">Assigned</span>
              <span className="font-mono text-[10px] text-ink">{threat.assigned_to ? `user ${threat.assigned_to}` : "unassigned"}</span>
              {can("analyst") && (
                <select
                  className="field ml-auto h-[27px] w-[138px] px-2 text-[10.5px]"
                  value={threat.status}
                  onChange={(event) => updateThreat.mutate({ status: event.target.value })}
                  aria-label="Update threat status"
                >
                  {["new", "investigating", "resolved", "dismissed"].map((option) => <option key={option} value={option}>{titleCase(option)}</option>)}
                </select>
              )}
            </div>

            <Tabs
              value={tab}
              onChange={setTab}
              tabs={[
                { value: "overview", label: "Overview" },
                { value: "analysis", label: "AI analysis" },
                { value: "risk", label: "Risk & evidence" },
                { value: "exposure", label: "Exposure" },
                { value: "investigation", label: "Investigation", count: (detail.notes || []).length },
              ]}
            />

            {tab === "overview" && (
              <div className="space-y-5">
                <section>
                  <div className="mb-2 flex items-center gap-2 font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim"><Layers size={11} /> Source description</div>
                  <p className="whitespace-pre-line text-[12px] leading-relaxed text-ink">{threat.description}</p>
                </section>
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="panel-quiet p-3.5">
                    <div className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">Affected technology</div>
                    <div className="mt-1.5 text-[12px] text-ink">{threat.affected_technology || "Not identified"}</div>
                    <div className="mt-2 font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">Affected versions</div>
                    <div className="mt-1 font-mono text-[10.5px] text-ink">{threat.affected_versions || "Not supplied by source"}</div>
                  </div>
                  <div className="panel-quiet p-3.5">
                    <div className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">Provenance</div>
                    <div className="mt-1.5 text-[11.5px] text-ink">{threat.source}</div>
                    <div className="mt-1 font-mono text-[9px] text-dim">Retrieved {threat.retrieval_timestamp ? relTime(threat.retrieval_timestamp) : "at ingestion"}</div>
                    <div className="mt-2 flex flex-wrap items-center gap-2">
                      <span className="chip">Reliability {threat.source_reliability ?? "—"}/100</span>
                      {threat.source_url && (
                        <a href={threat.source_url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-[10px] text-ion hover:text-crystal">
                          Source record <ExternalLink size={10} />
                        </a>
                      )}
                    </div>
                  </div>
                </div>
                <div className="rounded-lg border border-ion/20 bg-ion/[0.04] p-3.5">
                  <div className="flex items-center gap-1.5 font-mono text-[8.5px] uppercase tracking-[0.14em] text-ion"><BrainCircuit size={11} /> AI-assisted summary</div>
                  <p className="mt-1.5 text-[12px] leading-relaxed text-ink">{threat.ai_summary || "No summary was produced for this record."}</p>
                  <div className="mt-2 font-mono text-[8px] uppercase tracking-[0.1em] text-dim">Method · {threat.ai_method || "heuristic extraction"} · confidence {fmtPct(threat.ai_confidence, 0)}</div>
                </div>
                {threat.recommended_action && (
                  <InlineNotice tone="med" title="Source-recommended defensive action">{threat.recommended_action}</InlineNotice>
                )}
                {detail.vulnerability && (
                  <div className="panel-quiet flex flex-wrap items-center gap-2 px-3.5 py-3">
                    <ShieldAlert size={14} className="text-high" />
                    <Link to={`/app/vulnerabilities?focus=${detail.vulnerability.cve_id}`} className="font-mono text-[11px] text-ion">{detail.vulnerability.cve_id}</Link>
                    <span className="truncate text-[11px] text-mist">{detail.vulnerability.title}</span>
                    <span className="ml-auto font-mono text-[9px] text-dim">CVSS {detail.vulnerability.cvss ?? "—"} · {detail.vulnerability.known_exploited ? "known exploited" : "no KEV evidence"}</span>
                  </div>
                )}
              </div>
            )}

            {tab === "analysis" && (
              <div className="space-y-5">
                <div>
                  <div className="mb-2 flex items-center justify-between font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">
                    <span>Classification</span>
                    <span>{titleCase(threat.ai_category)} · {fmtPct(threat.ai_confidence, 0)} confidence</span>
                  </div>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {objectEntries(threat.ai_explanation).map(([key, value]) => (
                      <div key={key} className="panel-quiet px-3 py-2.5">
                        <div className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">{titleCase(key)}</div>
                        <div className="mt-1 text-[11px] leading-relaxed text-ink">{value}</div>
                      </div>
                    ))}
                    {!objectEntries(threat.ai_explanation).length && <p className="text-[11px] text-dim">No classification explanation is stored.</p>}
                  </div>
                </div>
                <div>
                  <div className="mb-2 font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">Extracted keywords</div>
                  <div className="flex flex-wrap gap-1.5">
                    {(threat.ai_keywords || []).map((keyword: string) => <span key={keyword} className="chip">{keyword}</span>)}
                    {!(threat.ai_keywords || []).length && <span className="text-[11px] text-dim">No keywords extracted.</span>}
                  </div>
                </div>
                <div>
                  <div className="mb-2 flex items-center gap-1.5 font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim"><Fingerprint size={11} /> Extracted entities</div>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {Object.entries(threat.ai_entities || {}).map(([key, values]: [string, any]) => (
                      <div key={key} className="panel-quiet px-3 py-2.5">
                        <div className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">{titleCase(key)}</div>
                        <div className="mt-1 flex flex-wrap gap-1">
                          {(Array.isArray(values) ? values : [values]).map((value: string) => (
                            <span key={value} className="rounded border border-veil/10 bg-veil/[0.03] px-1.5 py-0.5 font-mono text-[9px] text-ink">{value}</span>
                          ))}
                        </div>
                      </div>
                    ))}
                    {!Object.keys(threat.ai_entities || {}).length && <p className="text-[11px] text-dim">No entities were extracted from the source text.</p>}
                  </div>
                </div>
                <div>
                  <div className="mb-2 font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">Structured indicators</div>
                  {(threat.indicators || []).length ? (
                    <div className="overflow-hidden rounded-lg border border-line">
                      <table className="table-shell">
                        <thead><tr><th>Type</th><th>Value</th><th className="hidden sm:table-cell">Estimated location</th><th /></tr></thead>
                        <tbody>
                          {threat.indicators.map((indicator: any, index: number) => (
                            <tr key={`${indicator.value}-${index}`}>
                              <td className="font-mono text-[9px] uppercase text-dim">{indicator.type}</td>
                              <td className="font-mono text-[10px] text-ink">{indicator.value}</td>
                              <td className="hidden text-[10px] text-dim sm:table-cell">{indicator.geo?.country ? `${indicator.geo.country}${indicator.geo.city ? ` · ${indicator.geo.city}` : ""}` : "—"}</td>
                              <td className="text-right"><CopyButton value={indicator.value} label="" /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p className="text-[11px] text-dim">No structured indicators are attached; evidence is limited to the source description.</p>
                  )}
                </div>
                <InlineNotice tone="violet" title="Analysis boundary">
                  Classification is produced by a deterministic offline lexicon, not a generative model. Confidence reflects
                  the strength of lexical evidence, not the truth of the underlying source claim.
                </InlineNotice>
              </div>
            )}

            {tab === "risk" && (
              <div className="space-y-5">
                <div className="flex items-center gap-4 rounded-lg border border-line bg-shade/20 p-4">
                  <div className="font-display text-[34px] font-semibold leading-none" style={{ color: riskColor(detail.risk_breakdown?.risk_score) }}>
                    {Number(detail.risk_breakdown?.risk_score ?? threat.risk_score ?? 0).toFixed(1)}
                  </div>
                  <div className="min-w-0">
                    <div className="text-[12px] text-ink">{detail.risk_breakdown?.risk_category || threat.risk_category} band · {titleCase(detail.risk_breakdown?.urgency || threat.urgency)}</div>
                    <p className="mt-1 text-[10.5px] leading-relaxed text-mist">{detail.risk_breakdown?.explanation || "The stored model explanation is not available."}</p>
                  </div>
                  <span className="ml-auto shrink-0 font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{detail.risk_breakdown?.model_version || "aegis-risk-v1"}</span>
                </div>
                <div>
                  <div className="mb-2 flex items-center justify-between font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">
                    <span>Factor contributions</span>
                    <span>Σ = risk score</span>
                  </div>
                  <FactorBars factors={detail.risk_breakdown?.factors || []} />
                </div>
                <div>
                  <div className="mb-2 font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">Stored assessments</div>
                  {(detail.assessments || []).length ? (
                    <div className="divide-y divide-veil/[0.05] rounded-lg border border-line">
                      {detail.assessments.map((assessment: any) => (
                        <Link key={assessment.id} to={`/app/risk?assessment=${assessment.id}`} className="flex items-center gap-3 px-3.5 py-2.5 hover:bg-veil/[0.025]">
                          <span className="font-mono text-[9px] text-dim">{assessment.ref}</span>
                          <span className="text-[11px] text-ink">{assessment.risk_category} · {titleCase(assessment.urgency)}</span>
                          <span className="ml-auto tnum font-mono text-[11px]" style={{ color: riskColor(assessment.risk_score) }}>{Number(assessment.risk_score).toFixed(1)}</span>
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] text-dim">No assessment has been stored for this record. Analysts can create one from this panel.</p>
                  )}
                </div>
                <div>
                  <div className="mb-2 font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">Evidence references</div>
                  <div className="space-y-1.5">
                    {(threat.evidence_refs || []).map((ref: any, index: number) => (
                      <div key={`${ref.label}-${index}`} className="flex items-center gap-2 text-[11px] text-mist">
                        <span className="h-1 w-1 rounded-full bg-ion" />
                        {ref.url ? <a href={ref.url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-ion hover:text-crystal">{ref.label} <ExternalLink size={10} /></a> : ref.label}
                      </div>
                    ))}
                    {!(threat.evidence_refs || []).length && <p className="text-[11px] text-dim">No structured evidence references were supplied.</p>}
                  </div>
                </div>
              </div>
            )}

            {tab === "exposure" && (
              <div className="space-y-5">
                <div>
                  <div className="mb-2 flex items-center gap-1.5 font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim"><Target size={11} /> Version-validated asset matches</div>
                  {(detail.exposed_assets || []).length ? (
                    <div className="divide-y divide-veil/[0.05] rounded-lg border border-line">
                      {detail.exposed_assets.map((match: any, index: number) => (
                        <button
                          key={`${match.asset.ref}-${index}`}
                          onClick={() => setSearchParams({ focus: threat.ref })}
                          className="flex w-full items-center gap-3 px-3.5 py-3 text-left hover:bg-veil/[0.025]"
                        >
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-[9px] text-dim">{match.asset.ref}</span>
                              <span className="truncate text-[11.5px] text-ink">{match.asset.name}</span>
                            </div>
                            <div className="mt-0.5 text-[10px] text-dim">{match.asset.category} · criticality {match.asset.criticality}/5 · {match.asset.exposure}</div>
                          </div>
                          <span className="shrink-0 font-mono text-[9px] text-dim">{Number(match.confidence).toFixed(0)}%</span>
                          <StatusBadge status={match.status} />
                        </button>
                      ))}
                    </div>
                  ) : (
                    <div className="rounded-lg border border-line bg-veil/[0.02] px-4 py-5 text-center">
                      <p className="text-[11.5px] text-mist">No verified asset match is recorded for this CVE.</p>
                      <p className="mt-1 text-[10px] text-dim">Absence of a match is scoped to the registered inventory; it does not prove no system is affected.</p>
                    </div>
                  )}
                </div>
                {(detail.alerts || []).length > 0 && (
                  <div>
                    <div className="mb-2 font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">Warnings citing this record</div>
                    <div className="divide-y divide-veil/[0.05] rounded-lg border border-line">
                      {detail.alerts.map((alert: any) => (
                        <Link key={alert.id} to={`/app/alerts?focus=${alert.ref}`} className="flex items-center gap-3 px-3.5 py-2.5 hover:bg-veil/[0.025]">
                          <SeverityBadge severity={alert.severity} />
                          <span className="truncate text-[11px] text-mist">{alert.title}</span>
                          <span className="ml-auto font-mono text-[9px] text-dim">{alert.ref}</span>
                        </Link>
                      ))}
                    </div>
                  </div>
                )}
                {(detail.correlations || []).length > 0 && (
                  <div>
                    <div className="mb-2 flex items-center gap-1.5 font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim"><GitFork size={11} /> Correlated reports</div>
                    <div className="divide-y divide-veil/[0.05] rounded-lg border border-line">
                      {detail.correlations.slice(0, 6).map((pair: any) => (
                        <button key={pair.threat.ref} onClick={() => openDrawer(pair.threat.ref)} className="flex w-full items-center gap-3 px-3.5 py-2.5 text-left hover:bg-veil/[0.025]">
                          <span className="font-mono text-[9px] text-dim">{pair.threat.ref}</span>
                          <span className="truncate text-[11px] text-mist">{pair.threat.name}</span>
                          <span className="ml-auto font-mono text-[9px] text-ion">{Number(pair.score).toFixed(2)}</span>
                        </button>
                      ))}
                    </div>
                    <p className="mt-1.5 text-[9.5px] leading-relaxed text-dim">Similarity indicates related reporting, not verified attribution to one actor.</p>
                  </div>
                )}
              </div>
            )}

            {tab === "investigation" && (
              <div className="space-y-5">
                <div className="flex items-center gap-2 font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">
                  <MessageSquarePlus size={11} /> Analyst notes · {(detail.notes || []).length}
                </div>
                {can("analyst") ? (
                  <div className="rounded-lg border border-line bg-shade/20 p-3">
                    <textarea
                      className="field min-h-[86px] text-[12px]"
                      value={note}
                      onChange={(event) => setNote(event.target.value)}
                      placeholder="Record what you verified, the evidence used and any remaining uncertainty. Notes are attributed and audited."
                      maxLength={4000}
                    />
                    <div className="mt-2 flex items-center justify-between gap-2">
                      <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{note.length}/4000 · attributed to your account</span>
                      <button className="btn btn-primary btn-sm" onClick={() => addNote.mutate()} disabled={note.trim().length < 2 || addNote.isPending}>
                        Attach note
                      </button>
                    </div>
                  </div>
                ) : (
                  <InlineNotice tone="violet" title="Read-only access">Viewer accounts can read investigation notes but not add them.</InlineNotice>
                )}
                <div className="space-y-2.5">
                  {(detail.notes || []).map((entry: any) => (
                    <div key={entry.id} className="rounded-lg border border-line bg-veil/[0.018] p-3.5">
                      <div className="flex items-center gap-2">
                        <span className="grid h-6 w-6 place-items-center rounded-md border border-line bg-veil/[0.03] font-mono text-[8.5px] text-mist">{entry.author?.initials || "—"}</span>
                        <span className="text-[11px] text-ink">{entry.author?.full_name || "Unknown author"}</span>
                        <span className="font-mono text-[8px] uppercase tracking-[0.08em] text-dim">{entry.author?.role}</span>
                        <span className="ml-auto font-mono text-[8.5px] text-dim">{relTime(entry.created_at)}</span>
                      </div>
                      <p className="mt-2 whitespace-pre-line text-[11.5px] leading-relaxed text-ink">{entry.body}</p>
                    </div>
                  ))}
                  {!(detail.notes || []).length && <p className="text-[11px] text-dim">No analyst notes are attached to this record.</p>}
                </div>
                {(detail.recommendations || []).length > 0 && (
                  <div>
                    <div className="mb-2 font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">Linked recommendations</div>
                    <div className="divide-y divide-veil/[0.05] rounded-lg border border-line">
                      {detail.recommendations.map((rec: any) => (
                        <Link key={rec.id} to={`/app/recommendations?focus=${rec.ref}`} className="flex items-center gap-3 px-3.5 py-2.5 hover:bg-veil/[0.025]">
                          <span className="font-mono text-[9px] text-dim">{rec.ref}</span>
                          <span className="truncate text-[11px] text-mist">{rec.title}</span>
                          <StatusBadge status={rec.status} />
                        </Link>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        ) : null}
      </Drawer>
    </>
  );
}
