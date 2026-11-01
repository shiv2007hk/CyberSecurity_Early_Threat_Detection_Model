import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  ArrowDownToLine,
  Cable,
  Database,
  FlaskConical,
  KeyRound,
  Loader2,
  Play,
  PlugZap,
  RefreshCcw,
  Radar,
  ScanSearch,
  ShieldCheck,
  Signal,
  TerminalSquare,
} from "lucide-react";
import clsx from "clsx";
import { api, qs, type Paginated } from "../../lib/api";
import { fmtDate, fmtNumber, relTime, titleCase } from "../../lib/format";
import { useAuth } from "../../context/AuthContext";
import {
  EmptyState,
  ErrorState,
  InlineNotice,
  Kpi,
  LoadingBlock,
  PageHeader,
  Pagination,
  Panel,
  PanelHead,
  ReadOnlyHint,
  Toggle,
  useToast,
} from "../../components/ui";
import { HBarList } from "../../components/charts";
import { DailyBars, PriorityMatrix, Treemap } from "../../components/analytics-charts";
import { MiniBar, SectionLabel } from "./shared";

type Source = {
  id: number;
  key: string;
  name: string;
  description: string;
  url: string;
  category: string;
  requires_key: boolean;
  key_configured: boolean;
  enabled: boolean;
  status: string;
  reliability: number;
  last_sync_at?: string | null;
  last_success_at?: string | null;
  items_ingested: number;
  latency_ms?: number | null;
  last_message?: string | null;
  automated_sync?: boolean;
};

const STATUS_TONE: Record<string, string> = {
  operational: "border-low/30 bg-low/[0.08] text-low",
  degraded: "border-med/30 bg-med/[0.08] text-med",
  awaiting_key: "border-violet/30 bg-violet/[0.08] text-violet",
  disabled: "border-veil/10 bg-veil/[0.03] text-dim",
  reference: "border-info/25 bg-info/[0.06] text-info",
  "manual-import": "border-info/25 bg-info/[0.06] text-info",
  error: "border-crit/30 bg-crit/[0.08] text-crit",
};

function SourceStatus({ status }: { status: string }) {
  return (
    <span className={clsx("inline-flex h-[20px] items-center rounded-[4px] border px-1.5 font-mono text-[8.5px] uppercase tracking-[0.12em]", STATUS_TONE[status] || "border-veil/10 bg-veil/5 text-mist")}>
      {titleCase(status)}
    </span>
  );
}

export default function Sources() {
  const { can, user } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();

  const [logSource, setLogSource] = useState("all");
  const [logStatus, setLogStatus] = useState("all");
  const [page, setPage] = useState(1);
  const [indicatorType, setIndicatorType] = useState("ip");
  const [indicatorValue, setIndicatorValue] = useState("");
  const [enrichment, setEnrichment] = useState<any>(null);

  const sourcesQuery = useQuery({
    queryKey: ["sources"],
    queryFn: () => api<{ items: Source[]; configuration: any; sync_policy: Record<string, string>; secret_policy: string }>("/sources"),
  });

  const logsQuery = useQuery({
    queryKey: ["source-logs", logSource, logStatus, page],
    queryFn: () =>
      api<Paginated<any>>(
        `/sources/logs${qs({
          source: logSource === "all" ? undefined : logSource,
          status: logStatus === "all" ? undefined : logStatus,
          page,
          size: 15,
        })}`,
      ),
  });

  const analyticsLogsQuery = useQuery({
    queryKey: ["source-logs-analytics"],
    queryFn: () => api<Paginated<any>>(`/sources/logs${qs({ size: 100 })}`),
  });
  const feedQuery = useQuery({
    queryKey: ["source-feed-analytics"],
    queryFn: () => api<Paginated<any>>(`/threats${qs({ range: "90d", size: 100, sort_by: "published_at", order: "desc" })}`),
  });

  const sources = sourcesQuery.data?.items || [];
  const configuration = sourcesQuery.data?.configuration;
  const logs = logsQuery.data;
  const analyticsLogs: any[] = analyticsLogsQuery.data?.items || [];
  const analyticsFeed: any[] = feedQuery.data?.items || [];

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["sources"] });
    queryClient.invalidateQueries({ queryKey: ["source-logs"] });
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    queryClient.invalidateQueries({ queryKey: ["analytics"] });
  };

  const toggle = useMutation({
    mutationFn: (vars: { key: string; enabled: boolean }) =>
      api(`/sources/${vars.key}`, { method: "PATCH", body: JSON.stringify({ enabled: vars.enabled }) }),
    onSuccess: (_response, vars) => {
      push("success", vars.enabled ? "Source enabled." : "Source disabled.");
      invalidate();
    },
    onError: (error: any) => push("error", error.message || "The source could not be updated."),
  });

  const sync = useMutation({
    mutationFn: (key: string) => api<any>(`/sources/${key}/sync`, { method: "POST" }),
    onSuccess: (result) => {
      const outcome = result?.result || {};
      push("success", `${outcome.mode || "Sync"} finished · ${fmtNumber(outcome.items_new ?? 0)} new record(s).`);
      invalidate();
    },
    onError: (error: any) => push("error", error.message || "The synchronisation request failed."),
  });

  const enrich = useMutation({
    mutationFn: (payload: { indicator_type: string; value: string }) =>
      api<any>("/sources/enrich", { method: "POST", body: JSON.stringify(payload) }),
    onSuccess: (result) => {
      setEnrichment(result);
      push(result.configured ? "success" : "info", result.message);
    },
    onError: (error: any) => push("error", error.message || "Enrichment failed."),
  });

  const operational = sources.filter((source) => ["operational", "degraded"].includes(source.status)).length;
  const awaitingKey = sources.filter((source) => source.status === "awaiting_key").length;
  const totalItems = sources.reduce((acc, source) => acc + (source.items_ingested || 0), 0);
  const automated = sources.filter((source) => source.automated_sync).length;

  const contribution = useMemo(
    () =>
      sources
        .map((source) => ({ name: source.name, value: source.items_ingested || 0 }))
        .filter((entry) => entry.value > 0)
        .sort((a, b) => b.value - a.value)
        .slice(0, 10),
    [sources],
  );

  const ingestionTimeline = useMemo(() => {
    const buckets = new Map<string, { name: string; value: number }>();
    analyticsLogs.forEach((log: any) => {
      const time = new Date(log.started_at).getTime();
      if (Number.isNaN(time)) return;
      const key = new Date(time).toISOString().slice(0, 10);
      const entry = buckets.get(key) || { name: fmtDate(`${key}T12:00:00Z`), value: 0 };
      entry.value += Number(log.items_new || 0);
      buckets.set(key, entry);
    });
    return [...buckets.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, value]) => value);
  }, [analyticsLogs]);

  const categoryTreemap = useMemo(() => {
    const counts = new Map<string, { count: number; maxRisk: number }>();
    analyticsFeed.forEach((threat: any) => {
      const entry = counts.get(threat.category) || { count: 0, maxRisk: 0 };
      entry.count += 1;
      entry.maxRisk = Math.max(entry.maxRisk, Number(threat.risk_score ?? 0));
      counts.set(threat.category, entry);
    });
    const palette = ["#49b8ff", "#64d8ff", "#9a8cff", "#ffd166", "#42c98a", "#ff963d", "#78b7ff", "#ff4d5e", "#7f94ad", "#c9a6ff"];
    return [...counts.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .map(([name, entry], index) => ({
        name,
        value: entry.count,
        color: palette[index % palette.length],
        detail: `${entry.count} record(s) · highest risk ${entry.maxRisk.toFixed(0)}`,
        meta: `${entry.count} · risk ${entry.maxRisk.toFixed(0)}`,
      }));
  }, [analyticsFeed]);

  const healthMatrix = useMemo(() => {
    const columns = ["success", "partial", "failed", "skipped"];
    const keys = [...new Set(analyticsLogs.map((log: any) => String(log.source_key)))].sort();
    const values = keys.map((key) =>
      columns.map((status) => analyticsLogs.filter((log: any) => log.source_key === key && log.status === status).length),
    );
    return { rows: keys, cols: columns.map((status) => titleCase(status)), values };
  }, [analyticsLogs]);

  const focusHealthCell = (row: string, col: string) => {
    const status = col.toLowerCase();
    if (!analyticsLogs.some((log: any) => log.source_key === row && log.status === status)) return;
    setLogSource(row);
    setLogStatus(status);
    setPage(1);
  };

  return (
    <>
      <PageHeader
        title="Sources & data provenance"
        kicker="Connectors · ingestion · provenance"
        description="Connector health, import state and retrieval history. A connector that cannot reach its provider is reported as failed; the platform never writes substitute data in its place."
        aside={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span><span className="text-ink">{operational}</span> operational</span>
            <span>·</span>
            <span><span className={awaitingKey ? "text-violet" : "text-ink"}>{awaitingKey}</span> awaiting key</span>
            <span>·</span>
            <span><span className="text-ink">{fmtNumber(totalItems)}</span> items ingested</span>
            {user && <span>·</span>}
            {user && <ReadOnlyHint role={user.role} />}
          </div>
        }
        actions={
          <button className="btn btn-ghost btn-sm" onClick={() => { sourcesQuery.refetch(); logsQuery.refetch(); }}>
            <RefreshCcw size={13} /> Refresh state
          </button>
        }
      />

      <div className="mb-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Operational sources" value={`${operational}/${sources.length}`} detail="Includes degraded connectors" icon={<Signal size={15} />} tone="low" />
        <Kpi label="Automated connectors" value={fmtNumber(automated)} detail="NVD, KEV and EPSS sync paths" icon={<PlugZap size={15} />} tone="ion" />
        <Kpi label="Awaiting API key" value={fmtNumber(awaitingKey)} detail="Server-side keys required" icon={<KeyRound size={15} />} tone="violet" />
        <Kpi label="Records ingested" value={fmtNumber(totalItems)} detail="Cumulative across connectors" icon={<Database size={15} />} tone="med" />
      </div>

      <div className="mb-4 grid gap-3 lg:grid-cols-2 xl:grid-cols-4">
        {[
          { label: "Live threat feeds", value: configuration?.live_feeds_enabled, detail: "Outbound fetches permitted", tone: "ion" },
          { label: "Aegis AI provider", value: configuration?.chat_enabled, detail: "DeepSeek key held server-side", tone: "violet" },
          { label: "AI analysis", value: configuration?.ai_analysis_enabled, detail: "Deterministic offline classifier", tone: "low" },
          { label: "Email alerts", value: configuration?.email_alerts_enabled, detail: "Requires SMTP configuration", tone: "med" },
        ].map((entry) => (
          <div key={entry.label} className="panel-quiet flex items-center justify-between gap-3 px-4 py-3">
            <div className="min-w-0">
              <div className="font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">{entry.label}</div>
              <div className="mt-1 text-[11px] text-ink">{entry.detail}</div>
            </div>
            <span className={clsx("inline-flex h-[22px] items-center rounded-[5px] border px-2 font-mono text-[8.5px] uppercase tracking-[0.12em]", entry.value ? "border-low/30 bg-low/[0.08] text-low" : "border-veil/10 bg-veil/[0.03] text-dim")}>
              {entry.value ? "Enabled" : "Disabled"}
            </span>
          </div>
        ))}
      </div>

      {sourcesQuery.isError ? (
        <Panel className="mb-4"><ErrorState message={(sourcesQuery.error as any)?.message} retry={() => sourcesQuery.refetch()} /></Panel>
      ) : sourcesQuery.isLoading ? (
        <Panel className="mb-4"><LoadingBlock rows={6} label="Loading connectors" /></Panel>
      ) : !sources.length ? (
        <Panel className="mb-4"><EmptyState title="No connectors registered" detail="Source configuration is seeded by the backend. Check the database seed state." icon={<Cable size={19} />} /></Panel>
      ) : (
        <div className="mb-4 grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
          {sources.map((source) => (
            <div key={source.key} className="panel flex flex-col">
              <div className="flex items-start justify-between gap-3 border-b border-line px-4 py-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <SourceStatus status={source.status} />
                    <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{titleCase(source.category)}</span>
                  </div>
                  <h3 className="mt-1.5 truncate text-[12px] font-semibold text-ink">{source.name}</h3>
                  <p className="mt-1 line-clamp-2 text-[10px] leading-relaxed text-dim">{source.description}</p>
                </div>
                {can("admin") && (
                  <Toggle
                    checked={source.enabled}
                    label={`Toggle ${source.name}`}
                    disabled={toggle.isPending}
                    onChange={(next) => toggle.mutate({ key: source.key, enabled: next })}
                  />
                )}
              </div>
              <div className="flex-1 px-4 py-3">
                <div className="flex items-baseline justify-between">
                  <span className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">Reliability</span>
                  <span className="tnum font-mono text-[10px] text-mist">{Math.round(source.reliability || 0)}%</span>
                </div>
                <div className="mt-1.5"><MiniBar value={source.reliability || 0} color={source.reliability >= 90 ? "#42c98a" : "#64d8ff"} /></div>
                <div className="mt-3 grid grid-cols-2 gap-2 font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">
                  <div>
                    <div>Items</div>
                    <div className="tnum mt-0.5 text-[11px] normal-case tracking-normal text-ink">{fmtNumber(source.items_ingested)}</div>
                  </div>
                  <div>
                    <div>Last success</div>
                    <div className="mt-0.5 text-[11px] normal-case tracking-normal text-ink">{source.last_success_at ? relTime(source.last_success_at) : "never"}</div>
                  </div>
                </div>
                {source.last_message && <p className="mt-2 line-clamp-2 border-t border-veil/[0.05] pt-2 text-[9.5px] leading-relaxed text-dim">{source.last_message}</p>}
              </div>
              <div className="flex items-center justify-between gap-2 border-t border-line px-4 py-2.5">
                <div className="flex flex-wrap items-center gap-1">
                  {source.requires_key && (
                    <span className={clsx("chip", source.key_configured ? "text-low" : "text-violet")}>
                      <KeyRound size={9} className="mr-1" /> {source.key_configured ? "key set" : "no key"}
                    </span>
                  )}
                  {source.automated_sync ? (
                    <span className="chip text-ion"><ArrowDownToLine size={9} className="mr-1" /> automated</span>
                  ) : (
                    <span className="chip text-dim">manual / reference</span>
                  )}
                </div>
                {can("analyst") && (
                  <button
                    className="btn btn-quiet btn-sm"
                    disabled={!source.automated_sync || !source.enabled || sync.isPending}
                    onClick={() => sync.mutate(source.key)}
                    title={!source.automated_sync ? "This connector is reference or on-demand only." : undefined}
                  >
                    {sync.isPending && sync.variables === source.key ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />}
                    Sync
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      <Panel className="mb-4" ticks>
        <PanelHead
          title="Feed intelligence"
          kicker={`${fmtNumber(analyticsLogs.length)} retrieval runs · ${fmtNumber(analyticsFeed.length)} recent records`}
          right={<span className="chip">stored logs only</span>}
        />
        {analyticsLogsQuery.isError || feedQuery.isError ? (
          <ErrorState
            compact
            message={(analyticsLogsQuery.error as any)?.message || (feedQuery.error as any)?.message}
            retry={() => {
              analyticsLogsQuery.refetch();
              feedQuery.refetch();
            }}
          />
        ) : analyticsLogsQuery.isLoading || feedQuery.isLoading ? (
          <LoadingBlock rows={6} label="Loading feed analytics" />
        ) : (
          <div className="grid gap-px bg-line [&>*]:min-w-0 xl:grid-cols-2">
            <div className="bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">cumulative records</span>}>
                Source contribution
              </SectionLabel>
              <HBarList data={contribution} suffix=" records" color="#49b8ff" />
              {!contribution.length && <p className="py-8 text-center text-[11px] text-dim">No connector has reported ingested records yet.</p>}
              <p className="mt-3 text-[10px] leading-relaxed text-dim">
                Counts are the items each connector reports as ingested. An awaiting-key connector contributes nothing until a server-side key is configured.
              </p>
            </div>
            <div className="bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{ingestionTimeline.length} day(s)</span>}>
                Ingestion timeline
              </SectionLabel>
              <DailyBars data={ingestionTimeline} height={196} color="#64d8ff" emptyLabel="No retrieval runs recorded." />
              <p className="mt-1 text-[10px] leading-relaxed text-dim">
                Records added per retrieval day from stored runs. Flat stretches mean no run was attempted or no new record was found, not that no threat exists.
              </p>
            </div>
            <div className="bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">tile = records</span>}>
                Threat-category treemap
              </SectionLabel>
              <Treemap items={categoryTreemap} height={244} emptyLabel="No ingested threat records yet." />
              <p className="mt-1 text-[10px] leading-relaxed text-dim">
                Recent stored threat records grouped by category. Colour is presentational; tile size is the record count in the 90-day window.
              </p>
            </div>
            <div className="bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">select to filter history</span>}>
                Source health matrix
              </SectionLabel>
              <PriorityMatrix rows={healthMatrix.rows} cols={healthMatrix.cols} values={healthMatrix.values} onSelect={focusHealthCell} height={168} />
              <p className="mt-2 text-[10px] leading-relaxed text-dim">
                Run outcomes per connector from stored logs. Selecting a populated cell filters the ingestion history table below to that connector and outcome.
              </p>
            </div>
          </div>
        )}
      </Panel>

      <div className="mb-4 grid gap-4 xl:grid-cols-[1.15fr_1fr]">
        <Panel>
          <PanelHead
            title="On-demand indicator enrichment"
            kicker="Server-side provider lookup"
            right={<span className="chip text-dim"><FlaskConical size={9} className="mr-1" /> analyst tool</span>}
          />
          <div className="p-4">
            <form
              className="grid gap-2 sm:grid-cols-[118px_1fr_auto]"
              onSubmit={(event) => {
                event.preventDefault();
                if (!can("analyst")) return;
                if (indicatorValue.trim().length < 3) {
                  push("error", "Enter an indicator of at least three characters.");
                  return;
                }
                enrich.mutate({ indicator_type: indicatorType, value: indicatorValue.trim() });
              }}
            >
              <label>
                <span className="field-label">Type</span>
                <select className="field" value={indicatorType} onChange={(event) => setIndicatorType(event.target.value)}>
                  <option value="ip">IP address</option>
                  <option value="domain">Domain</option>
                  <option value="url">URL</option>
                  <option value="sha256">SHA-256</option>
                </select>
              </label>
              <label>
                <span className="field-label">Indicator</span>
                <input
                  className="field font-mono text-[11px]"
                  value={indicatorValue}
                  onChange={(event) => setIndicatorValue(event.target.value)}
                  placeholder={indicatorType === "ip" ? "203.0.113.42" : indicatorType === "sha256" ? "64 hex characters" : "example.org"}
                  disabled={!can("analyst")}
                />
              </label>
              <div className="flex items-end">
                <button className="btn btn-primary w-full" disabled={!can("analyst") || enrich.isPending}>
                  {enrich.isPending ? <Loader2 size={13} className="animate-spin" /> : <ScanSearch size={13} />} Look up
                </button>
              </div>
            </form>

            {!can("analyst") ? (
              <p className="mt-3 text-[10px] leading-relaxed text-dim">Viewer accounts can read connector state but cannot trigger lookups.</p>
            ) : (
              <p className="mt-3 text-[10px] leading-relaxed text-dim">
                Only providers with an authorised server-side key respond. Unconfigured providers are listed explicitly — lookup results are returned only for providers with an authorised server-side key.
              </p>
            )}

            {enrichment && (
              <div className="mt-4 space-y-2">
                <SectionLabel right={<span className="chip text-dim">{enrichment.configured ? "configured" : "not configured"}</span>}>Lookup result</SectionLabel>
                <p className="text-[10.5px] leading-relaxed text-mist">{enrichment.message}</p>
                {enrichment.results?.length ? (
                  <div className="grid gap-2 sm:grid-cols-2">
                    {enrichment.results.map((result: any, index: number) => (
                      <div key={`${result.source}-${index}`} className="rounded-md border border-line bg-shade/20 px-3 py-2">
                        <div className="flex items-center justify-between">
                          <span className="text-[10.5px] text-ink">{result.source}</span>
                          <span className={clsx("chip", result.status === "ok" ? "text-low" : "text-med")}>{result.status}</span>
                        </div>
                        <div className="mt-1.5 space-y-0.5 font-mono text-[9px] text-dim">
                          {Object.entries(result)
                            .filter(([key]) => !["source", "status"].includes(key))
                            .map(([key, value]) => (
                              <div key={key} className="flex justify-between gap-2">
                                <span>{key.replace(/_/g, " ")}</span>
                                <span className="text-ink">{String(value ?? "—")}</span>
                              </div>
                            ))}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            )}
          </div>
        </Panel>

        <Panel>
          <PanelHead title="Sync policy" kicker="How each connector behaves" right={<Radar size={14} className="text-dim" />} />
          <div className="divide-y divide-veil/[0.05]">
            {Object.entries(sourcesQuery.data?.sync_policy || {}).map(([key, text]) => (
              <div key={key} className="px-4 py-2.5">
                <div className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-ion">{titleCase(key.replace(/_/g, " "))}</div>
                <p className="mt-0.5 text-[10.5px] leading-relaxed text-mist">{text}</p>
              </div>
            ))}
          </div>
          <div className="border-t border-line px-4 py-3">
            <div className="flex items-start gap-2">
              <ShieldCheck size={13} className="mt-0.5 shrink-0 text-low" />
              <p className="text-[10px] leading-relaxed text-dim">{sourcesQuery.data?.secret_policy}</p>
            </div>
          </div>
        </Panel>
      </div>

      <Panel>
        <PanelHead
          title="Ingestion history"
          kicker="Every retrieval attempt is logged"
          right={<span className="font-mono text-[9px] uppercase tracking-[0.1em] text-dim">{fmtNumber(logs?.total)} runs</span>}
        />
        <div className="grid gap-2 border-b border-line px-4 py-3 sm:grid-cols-[1fr_170px_170px_auto]">
          <div className="flex items-center font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">Filter retrieval history</div>
          <select className="field h-[34px] text-[10.5px]" value={logSource} onChange={(event) => { setLogSource(event.target.value); setPage(1); }} aria-label="Filter by source">
            <option value="all">All sources</option>
            {sources.map((source) => <option key={source.key} value={source.key}>{source.name}</option>)}
          </select>
          <select className="field h-[34px] text-[10.5px]" value={logStatus} onChange={(event) => { setLogStatus(event.target.value); setPage(1); }} aria-label="Filter by status">
            <option value="all">Any outcome</option>
            {["success", "partial", "failed", "skipped"].map((status) => <option key={status} value={status}>{titleCase(status)}</option>)}
          </select>
          <span className="flex items-center font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">page {logs?.page || 1}</span>
        </div>

        {logsQuery.isError ? (
          <ErrorState compact message={(logsQuery.error as any)?.message} retry={() => logsQuery.refetch()} />
        ) : logsQuery.isLoading ? (
          <LoadingBlock rows={6} label="Loading ingestion history" />
        ) : !logs?.items?.length ? (
          <EmptyState title="No ingestion runs match" detail="Run a connector sync or clear the filters to see earlier attempts." icon={<TerminalSquare size={19} />} />
        ) : (
          <div className="table-shell overflow-x-auto border-0">
            <table className="w-full">
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Source</th>
                  <th>Mode</th>
                  <th>Outcome</th>
                  <th className="text-right">Found</th>
                  <th className="text-right">New</th>
                  <th className="text-right">Duration</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {logs.items.map((log: any) => (
                  <tr key={log.id}>
                    <td className="whitespace-nowrap font-mono text-[9.5px] text-dim" title={log.started_at}>{relTime(log.started_at)}</td>
                    <td className="font-mono text-[10px] text-ink">{log.source_key}</td>
                    <td><span className="chip text-dim">{log.mode}</span></td>
                    <td>
                      <span className={clsx("chip", log.status === "success" ? "text-low" : log.status === "failed" ? "text-crit" : "text-med")}>
                        {titleCase(log.status)}
                      </span>
                    </td>
                    <td className="tnum text-right font-mono text-[10px] text-mist">{fmtNumber(log.items_found)}</td>
                    <td className="tnum text-right font-mono text-[10px] text-mist">{fmtNumber(log.items_new)}</td>
                    <td className="tnum text-right font-mono text-[9.5px] text-dim">{log.duration_ms ? `${fmtNumber(log.duration_ms)} ms` : "—"}</td>
                    <td className="max-w-[340px]"><span className="block truncate text-[10px] text-dim" title={log.message}>{log.message || "—"}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {logs && <Pagination page={logs.page} pages={logs.pages} total={logs.total} onPage={setPage} />}
        <div className="border-t border-line px-4 py-2.5">
          <div className="flex items-start gap-2">
            <AlertCircle size={12} className="mt-0.5 shrink-0 text-dim" />
            <p className="text-[9.5px] leading-relaxed text-dim">
              Failed retrievals are shown exactly as recorded, with the provider response and timestamp. A failed fetch writes nothing.
            </p>
          </div>
        </div>
      </Panel>

      <InlineNotice tone="ion" className="mt-4">
        Keys are read from environment variables on the server. This interface exposes configuration state only, never key values. Enable a live connector only after confirming outbound access and rate-limit policy for your environment.
      </InlineNotice>
    </>
  );
}
