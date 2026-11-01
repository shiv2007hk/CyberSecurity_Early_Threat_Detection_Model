import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlarmClock,
  ArrowRight,
  BellRing,
  BookOpenCheck,
  Download,
  GitBranch,
  MessageSquarePlus,
  Radar,
  RefreshCw,
  Siren,
  UserCheck,
} from "lucide-react";
import clsx from "clsx";
import { api, downloadFile, qs, type Alert, type Paginated } from "../../lib/api";
import { fmtDate, fmtNumber, fmtPct, relTime, riskColor, titleCase } from "../../lib/format";
import { useAuth } from "../../context/AuthContext";
import {
  Drawer,
  EmptyState,
  ErrorState,
  InlineNotice,
  Kpi,
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
} from "../../components/ui";
import { ChartLegend, TrendArea } from "../../components/charts";
import { PriorityMatrix, RISK_HEX, ScatterPlot, Waterfall } from "../../components/analytics-charts";
import { DrawerSection, EvidenceList, FieldLabel, FilterSelect, ScoreChip, SectionLabel, StatRow } from "./shared";

const FLOW: Record<string, string[]> = {
  new: ["acknowledged", "investigating", "dismissed", "resolved"],
  acknowledged: ["investigating", "resolved", "dismissed", "new"],
  investigating: ["resolved", "dismissed", "acknowledged"],
  resolved: ["new"],
  dismissed: ["new"],
};

const STATUS_LABEL: Record<string, string> = {
  acknowledged: "Acknowledge",
  investigating: "Start investigation",
  resolved: "Resolve",
  dismissed: "Dismiss",
  new: "Reopen",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
const SEVERITY_HEX = { critical: "#ff4d5e", high: "#ff963d", medium: "#ffd166", low: "#42c98a" };
const WORKFLOW_ORDER = ["new", "acknowledged", "investigating", "resolved", "dismissed"];

/* Alerts store confidence either as a 0–1 fraction or a 0–100 percentage. */
function confidencePct(value?: number | null) {
  const raw = Number(value ?? 0);
  return raw > 0 && raw <= 1 ? raw * 100 : raw;
}

function timelineSlot(time: number, rangeKey: string) {
  const date = new Date(time);
  if (rangeKey === "24h") {
    date.setHours(Math.floor(date.getHours() / 6) * 6, 0, 0, 0);
    return date.getTime();
  }
  date.setHours(0, 0, 0, 0);
  if (rangeKey === "90d") date.setDate(date.getDate() - ((date.getDay() + 6) % 7));
  return date.getTime();
}

export default function Alerts() {
  const { can, user } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();

  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [rule, setRule] = useState("all");
  const [range, setRange] = useState("30d");
  const [sortBy, setSortBy] = useState("detected_at");
  const [page, setPage] = useState(1);
  const [showRules, setShowRules] = useState(false);
  const [note, setNote] = useState("");
  const [assignee, setAssignee] = useState("");

  const focus = searchParams.get("focus");
  useEffect(() => setPage(1), [q, severity, status, rule, range, sortBy]);

  const params = { q, severity, status, rule, range, sort_by: sortBy, order: "desc", page, size: 20 };
  const listQuery = useQuery({
    queryKey: ["alerts", params],
    queryFn: () => api<Paginated<Alert>>(`/alerts${qs(params)}`),
  });
  const summaryQuery = useQuery({ queryKey: ["alert-summary"], queryFn: () => api<any>("/alerts/summary") });
  const rulesQuery = useQuery({ queryKey: ["alert-rules"], queryFn: () => api<any>("/alerts/rules"), enabled: showRules });
  const usersQuery = useQuery({
    queryKey: ["admin-users-lite"],
    queryFn: () => api<any>("/admin/users?size=100&active=true"),
    enabled: can("admin"),
  });
  const detailQuery = useQuery({
    queryKey: ["alert-detail", focus],
    queryFn: () => api<any>(`/alerts/${focus}`),
    enabled: Boolean(focus),
  });

  const analyticsParams = { q, severity, status, rule, range, sort_by: "risk_score", order: "desc", size: 100 };
  const analyticsQuery = useQuery({
    queryKey: ["alert-analytics", analyticsParams],
    queryFn: () => api<Paginated<Alert>>(`/alerts${qs(analyticsParams)}`),
  });

  const data = listQuery.data;
  const summary = summaryQuery.data;
  const detail = detailQuery.data;
  const alert: Alert | undefined = detail?.alert;
  const allowedTransitions = alert ? FLOW[alert.status] || [] : [];

  useEffect(() => {
    if (alert && can("admin")) setAssignee(alert.assignee_id ? String(alert.assignee_id) : "");
  }, [alert, can]);

  const openDrawer = (ref: string) =>
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("focus", ref);
      return next;
    });
  const closeDrawer = () => {
    setNote("");
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete("focus");
      return next;
    });
  };

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["alerts"] });
    queryClient.invalidateQueries({ queryKey: ["alert-analytics"] });
    queryClient.invalidateQueries({ queryKey: ["alert-summary"] });
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    queryClient.invalidateQueries({ queryKey: ["alert-detail", focus] });
  };

  const updateAlert = useMutation({
    mutationFn: (payload: Record<string, any>) => api(`/alerts/${focus}`, { method: "PATCH", body: JSON.stringify(payload) }),
    onSuccess: (_result, payload) => {
      push("success", payload.status ? `Alert moved to ${titleCase(String(payload.status))}.` : "Assignee updated.");
      invalidate();
    },
    onError: (error: any) => push("error", error.message || "The alert could not be updated."),
  });

  const addNote = useMutation({
    mutationFn: () => api(`/alerts/${focus}/notes`, { method: "POST", body: JSON.stringify({ body: note }) }),
    onSuccess: () => {
      setNote("");
      push("success", "Investigation note attached.");
      queryClient.invalidateQueries({ queryKey: ["alert-detail", focus] });
    },
    onError: (error: any) => push("error", error.message || "The note could not be saved."),
  });

  const scan = useMutation({
    mutationFn: () => api<any>("/alerts/scan", { method: "POST" }),
    onSuccess: (result) => {
      push("success", `Detection run created ${result.alerts_created} alert(s) across ${result.rules_evaluated ?? 5} rules.`);
      invalidate();
    },
    onError: (error: any) => push("error", error.message || "The detection run could not complete."),
  });

  const exportCsv = async () => {
    try {
      await downloadFile(`/alerts/export.csv${qs({ ...params, page: undefined, size: undefined })}`, "alerts.csv");
      push("success", "Alert export downloaded.");
    } catch (error: any) {
      push("error", error.message || "Export failed.");
    }
  };

  const facets = data?.facets || {};
  const ruleOptions: Array<{ name: string; count: number }> = facets.rules || [];
  const rules: any[] = rulesQuery.data?.rules || [];
  const stats = data?.stats || {};
  const employees: any[] = usersQuery.data?.items || [];
  const analyticsItems: Alert[] = analyticsQuery.data?.items || [];

  const scatterPoints = useMemo(
    () =>
      analyticsItems.map((item) => ({
        x: Number(item.risk_score ?? 0),
        y: Math.round(confidencePct(item.confidence) * 10) / 10,
        size: 3.5 + Math.min(5, (item.evidence?.length || 0) * 0.9),
        color: SEVERITY_HEX[item.severity as keyof typeof SEVERITY_HEX] || "#49b8ff",
        label: item.ref,
        detail: `${titleCase(item.severity)} · ${titleCase(item.status)} · ${item.rule_key}`,
      })),
    [analyticsItems],
  );

  const priorityMatrix = useMemo(() => {
    const rows = SEVERITY_ORDER.map((key) => titleCase(key));
    const cols = WORKFLOW_ORDER.map((key) => titleCase(key));
    const values = SEVERITY_ORDER.map((severityKey) =>
      WORKFLOW_ORDER.map((statusKey) => analyticsItems.filter((item) => item.severity === severityKey && item.status === statusKey).length),
    );
    return { rows, cols, values };
  }, [analyticsItems]);

  const timeline = useMemo(() => {
    if (!analyticsItems.length) return [];
    const times = analyticsItems.map((item) => new Date(item.detected_at).getTime()).filter((value) => !Number.isNaN(value));
    if (!times.length) return [];
    const step = range === "24h" ? 6 * 3600_000 : range === "90d" ? 7 * 86400_000 : 86400_000;
    const start = timelineSlot(Math.min(...times), range);
    const end = timelineSlot(Math.max(...times), range);
    const buckets: Array<{ key: string; name: string; critical: number; high: number; medium: number; low: number }> = [];
    for (let cursor = start; cursor <= end; cursor += step) {
      const date = new Date(cursor);
      buckets.push({
        key: new Date(timelineSlot(cursor, range)).toISOString(),
        name: range === "24h" ? `${String(date.getHours()).padStart(2, "0")}:00` : fmtDate(date.toISOString()),
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      });
    }
    const lookup = new Map(buckets.map((bucket) => [bucket.key, bucket]));
    analyticsItems.forEach((item) => {
      const time = new Date(item.detected_at).getTime();
      if (Number.isNaN(time)) return;
      const bucket = lookup.get(new Date(timelineSlot(time, range)).toISOString());
      if (!bucket) return;
      const severityKey = SEVERITY_ORDER.includes(item.severity) ? item.severity : "low";
      bucket[severityKey as "critical" | "high" | "medium" | "low"] += 1;
    });
    return buckets;
  }, [analyticsItems, range]);

  const riskLoad = useMemo(() => {
    const items = SEVERITY_ORDER.map((severityKey) => {
      const rows = analyticsItems.filter((item) => item.severity === severityKey);
      return {
        label: titleCase(severityKey),
        value: Math.round(rows.reduce((sum, item) => sum + Number(item.risk_score ?? 0), 0) * 10) / 10,
        color: SEVERITY_HEX[severityKey as keyof typeof SEVERITY_HEX],
        note: `${rows.length} alert(s) · summed risk score`,
      };
    }).filter((item) => item.value > 0);
    return { items, total: Math.round(items.reduce((sum, item) => sum + item.value, 0) * 10) / 10 };
  }, [analyticsItems]);

  const focusCell = (row: string, col: string) => {
    const severityKey = row.toLowerCase();
    const statusKey = col.toLowerCase();
    if (!analyticsItems.some((item) => item.severity === severityKey && item.status === statusKey)) return;
    setSeverity(severityKey);
    setStatus(statusKey);
  };

  return (
    <>
      <PageHeader
        title="Early warning"
        kicker="Detection · triage · response"
        description="Deterministic, evidence-backed alerts generated from known-exploited exposure, multi-source corroboration, repeated indicators and activity velocity. Rules describe observations, not attack predictions."
        aside={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span><span className="text-ink">{fmtNumber(summary?.active)}</span> active</span>
            <span><span className="text-crit">{fmtNumber(summary?.critical)}</span> critical</span>
            <span><span className="text-high">{fmtNumber(summary?.high)}</span> high</span>
            <span><span className="text-med">{fmtNumber(summary?.unassigned)}</span> unassigned</span>
            {summary?.latest_at && <span>latest {relTime(summary.latest_at)}</span>}
          </div>
        }
        actions={
          <>
            <RangeTabs value={range} onChange={setRange} options={[{ value: "24h", label: "24H" }, { value: "7d", label: "7D" }, { value: "30d", label: "30D" }, { value: "90d", label: "90D" }]} />
            <button className={clsx("btn btn-sm", showRules ? "btn-primary" : "btn-ghost")} onClick={() => setShowRules((value) => !value)}>
              <BookOpenCheck size={13} /> Rules
            </button>
            <button className="btn btn-ghost btn-sm" onClick={exportCsv}><Download size={13} /> Export</button>
            {can("analyst") && (
              <button className="btn btn-primary btn-sm" onClick={() => scan.mutate()} disabled={scan.isPending}>
                <RefreshCw size={13} className={scan.isPending ? "animate-spin" : undefined} /> {scan.isPending ? "Running detection…" : "Run detection"}
              </button>
            )}
          </>
        }
      />

      <div className="mb-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Active warnings" value={fmtNumber(summary?.active)} detail={`${fmtNumber(summary?.total)} generated in total`} icon={<Siren size={15} />} tone="crit" />
        <Kpi label="Critical active" value={fmtNumber(summary?.critical)} detail="Requires immediate triage" icon={<AlarmClock size={15} />} tone="high" />
        <Kpi label="Unassigned" value={fmtNumber(summary?.unassigned)} detail="Active without an accountable analyst" icon={<UserCheck size={15} />} tone="med" />
        <Kpi label="In view" value={fmtNumber(stats.total)} detail={`${fmtNumber(stats.resolved)} resolved in range`} icon={<Radar size={15} />} tone="ion" />
      </div>

      <Panel className="mb-4" ticks>
        <PanelHead
          title="Triage analytics"
          kicker={`${fmtNumber(analyticsItems.length)} alert(s) in the current view`}
          right={<span className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">stored evidence only</span>}
        />
        {analyticsQuery.isError ? (
          <ErrorState compact message={(analyticsQuery.error as any)?.message} retry={() => analyticsQuery.refetch()} />
        ) : analyticsQuery.isLoading ? (
          <LoadingBlock rows={6} label="Loading triage analytics" />
        ) : !analyticsItems.length ? (
          <div className="px-4 py-12 text-center">
            <p className="text-[12px] text-mist">No alerts match this view.</p>
            <p className="mt-1 text-[10.5px] text-dim">Analytics draw only on alerts inside the active filters and range.</p>
          </div>
        ) : (
          <>
            <div className="grid gap-px bg-line [&>*]:min-w-0 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
              <div className="bg-surface p-4">
                <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{fmtNumber(scatterPoints.length)} scored</span>}>
                  Risk vs evidence confidence
                </SectionLabel>
                <ScatterPlot
                  points={scatterPoints}
                  height={268}
                  xLabel="Risk score"
                  yLabel="Confidence %"
                  xMax={100}
                  yMax={100}
                  quadrants={["Triage first", "", "", "Monitor"]}
                  emptyLabel="No scored alerts in this view."
                />
                <p className="mt-1 text-[10px] leading-relaxed text-dim">
                  Top-right is the triage queue: high stored risk with strong recorded evidence. Confidence reflects source reliability and indicator coverage, not proof of exploitation.
                </p>
              </div>
              <div className="bg-surface p-4">
                <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">select to filter</span>}>
                  Priority heatmap · severity × workflow
                </SectionLabel>
                <PriorityMatrix rows={priorityMatrix.rows} cols={priorityMatrix.cols} values={priorityMatrix.values} onSelect={focusCell} height={200} />
                <p className="mt-2 text-[10px] leading-relaxed text-dim">
                  Counts follow the active range and search. Selecting a populated cell applies both filters to the log below.
                </p>
              </div>
            </div>
            <div className="grid gap-px border-t border-line bg-line xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
              <div className="bg-surface p-4">
                <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{timeline.length} bucket(s)</span>}>
                  Alert timeline
                </SectionLabel>
                <TrendArea
                  data={timeline}
                  series={[
                    { key: "critical", name: "Critical", color: "#ff4d5e" },
                    { key: "high", name: "High", color: "#ff963d" },
                    { key: "medium", name: "Medium", color: "#ffd166" },
                    { key: "low", name: "Low", color: "#42c98a" },
                  ]}
                  height={206}
                  stacked
                />
                <ChartLegend
                  className="mt-1 justify-center"
                  items={[
                    { name: "Critical", color: "#ff4d5e" },
                    { name: "High", color: "#ff963d" },
                    { name: "Medium", color: "#ffd166" },
                    { name: "Low", color: "#42c98a" },
                  ]}
                />
              </div>
              <div className="bg-surface p-4">
                <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{fmtNumber(riskLoad.total)} pts</span>}>
                  Risk load by severity
                </SectionLabel>
                <Waterfall items={riskLoad.items} total={riskLoad.total} height={206} unit="risk pts" />
                <p className="mt-1 text-[10px] leading-relaxed text-dim">
                  Summed risk scores of alerts in view, split by severity. Risk points are a prioritisation scale, not a probability of compromise.
                </p>
              </div>
            </div>
          </>
        )}
      </Panel>

      {showRules && (
        <Panel className="mb-4" ticks>
          <PanelHead
            title="Detection rulebook"
            kicker="Deterministic engine"
            right={rulesQuery.data?.engine && <span className="chip">window {rulesQuery.data.engine.window_hours}h · baseline {rulesQuery.data.engine.baseline_days}d</span>}
          />
          {rulesQuery.isLoading ? (
            <LoadingBlock rows={4} label="Loading rules" />
          ) : (
            <>
              <div className="grid gap-px overflow-hidden bg-line sm:grid-cols-2 xl:grid-cols-3">
                {rules.map((entry) => (
                  <div key={entry.key} className="bg-surface p-4">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[11.5px] font-semibold text-ink">{entry.name}</span>
                      <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{entry.severity}</span>
                    </div>
                    <p className="mt-1.5 text-[10.5px] leading-relaxed text-mist">{entry.logic}</p>
                  </div>
                ))}
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-4 py-2.5">
                <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{rulesQuery.data?.engine?.note}</span>
                <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">dedupe {rulesQuery.data?.engine?.duplicate_suppression_days} days · max {rulesQuery.data?.engine?.max_new_alerts_per_run}/run</span>
              </div>
            </>
          )}
        </Panel>
      )}

      <Panel className="mb-4">
        <div className="grid gap-3 p-3.5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-[minmax(230px,1.4fr)_repeat(4,minmax(120px,0.8fr))_minmax(120px,0.7fr)]">
          <div>
            <span className="field-label">Search alerts</span>
            <SearchField value={q} onChange={setQ} placeholder="Reference, title, trigger reason…" />
          </div>
          <FilterSelect label="Severity" value={severity} onChange={setSeverity} options={[{ value: "all", label: "All severities" }, ...(facets.severities || []).map((entry: any) => ({ value: entry.name, label: `${titleCase(entry.name)} (${entry.count})` }))]} />
          <FilterSelect label="Workflow status" value={status} onChange={setStatus} options={[{ value: "all", label: "Any status" }, ...(facets.statuses || []).map((entry: any) => ({ value: entry.name, label: `${titleCase(entry.name)} (${entry.count})` }))]} />
          <FilterSelect label="Rule" value={rule} onChange={setRule} options={[{ value: "all", label: "All rules" }, ...ruleOptions.map((entry) => ({ value: entry.name, label: `${entry.name} (${entry.count})` }))]} />
          <FilterSelect label="Sort" value={sortBy} onChange={setSortBy} options={[{ value: "detected_at", label: "Newest" }, { value: "risk_score", label: "Risk score" }, { value: "severity", label: "Severity" }, { value: "status", label: "Status" }]} />
          <div className="flex items-end">
            <button className="btn btn-ghost btn-sm h-[38px] w-full" onClick={() => { setQ(""); setSeverity("all"); setStatus("all"); setRule("all"); }}>Clear filters</button>
          </div>
        </div>
      </Panel>

      <Panel>
        {listQuery.isError ? (
          <ErrorState message={(listQuery.error as any)?.message} retry={() => listQuery.refetch()} />
        ) : listQuery.isLoading ? (
          <LoadingBlock rows={9} label="Loading early warnings" />
        ) : !data?.items.length ? (
          <EmptyState
            title="No alerts in this view"
            detail="No rule fired inside the selected range and filters. That is an observation about stored evidence, not a guarantee that no risk exists."
            icon={<BellRing size={19} />}
            action={can("analyst") ? <button className="btn btn-primary btn-sm" onClick={() => scan.mutate()} disabled={scan.isPending}>Run detection now</button> : undefined}
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-shell">
                <thead>
                  <tr>
                    <th>Warning</th>
                    <th>Severity</th>
                    <th className="hidden xl:table-cell">Rule</th>
                    <th className="hidden lg:table-cell">Trigger</th>
                    <th>Risk</th>
                    <th>Status</th>
                    <th className="hidden sm:table-cell">Detected</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <tr key={item.id} onClick={() => openDrawer(item.ref)} className={focus === item.ref ? "bg-ion/[0.05]" : undefined}>
                      <td className="max-w-[360px]">
                        <div className="flex items-start gap-2">
                          <span className="mt-0.5 shrink-0 font-mono text-[8.5px] text-dim">{item.ref}</span>
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5">
                              <span className="truncate text-[12px] text-ink">{item.title}</span>
                            </div>
                            <div className="mt-0.5 font-mono text-[8px] uppercase tracking-[0.06em] text-dim">{item.category} · {item.source}</div>
                          </div>
                        </div>
                      </td>
                      <td><SeverityBadge severity={item.severity} /></td>
                      <td className="hidden xl:table-cell"><span className="font-mono text-[9px] text-mist">{item.rule_key}</span></td>
                      <td className="hidden lg:table-cell max-w-[300px]"><p className="line-clamp-2 text-[10.5px] leading-relaxed text-mist">{item.trigger_reason}</p></td>
                      <td>
                        <span className="tnum font-mono text-[11.5px]" style={{ color: riskColor(item.risk_score) }}>{Number(item.risk_score ?? 0).toFixed(0)}</span>
                        <div className="mt-1 w-12"><ProgressBar value={Number(item.risk_score ?? 0)} color={riskColor(item.risk_score)} height={3} /></div>
                      </td>
                      <td><StatusBadge status={item.status} /></td>
                      <td className="hidden sm:table-cell">
                        <span className="font-mono text-[9px] text-dim">{relTime(item.detected_at)}</span>
                        <div className="mt-0.5 font-mono text-[8px] text-dim">{fmtDate(item.detected_at, true)}</div>
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
            <SeverityBadge severity={alert?.severity} />
            <span className="text-[14px] font-semibold text-ink">{alert?.title || focus}</span>
          </div>
        }
        subtitle={
          alert && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
              <span>{alert.ref}</span><span>·</span><span>{alert.rule_key}</span><span>·</span>
              <span>detected {fmtDate(alert.detected_at, true)}</span><span>·</span>
              <StatusBadge status={alert.status} />
            </div>
          )
        }
        footer={
          can("analyst") && alert ? (
            <>
              {can("admin") && (
                <div className="mr-auto flex items-center gap-2">
                  <select className="field h-[34px] w-[190px] text-[10.5px]" value={assignee} onChange={(event) => setAssignee(event.target.value)} aria-label="Alert assignee">
                    <option value="">Unassigned</option>
                    {employees.map((person: any) => <option key={person.id} value={person.id}>{person.full_name} · {person.role}</option>)}
                  </select>
                  <button
                    className="btn btn-ghost btn-sm"
                    onClick={() => updateAlert.mutate({ assignee_id: assignee ? Number(assignee) : null })}
                    disabled={updateAlert.isPending}
                  >
                    <UserCheck size={12} /> Assign
                  </button>
                </div>
              )}
              {allowedTransitions.map((next) => (
                <button
                  key={next}
                  className={clsx("btn btn-sm", next === "resolved" ? "btn-primary" : next === "dismissed" ? "btn-danger" : "btn-ghost")}
                  onClick={() => updateAlert.mutate({ status: next })}
                  disabled={updateAlert.isPending}
                >
                  {STATUS_LABEL[next] || titleCase(next)}
                </button>
              ))}
            </>
          ) : (
            <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">Read-only — analysts manage warning workflow</span>
          )
        }
      >
        {detailQuery.isError ? (
          <ErrorState message={(detailQuery.error as any)?.message} retry={() => detailQuery.refetch()} compact />
        ) : detailQuery.isLoading || !alert ? (
          <LoadingBlock rows={8} label="Loading warning detail" />
        ) : (
          <div>
            <div className="rounded-xl border border-line bg-shade/25 p-4">
              <StatRow
                entries={[
                  { label: "Risk", value: <span style={{ color: riskColor(alert.risk_score) }}>{Number(alert.risk_score ?? 0).toFixed(0)}/100</span> },
                  { label: "Confidence", value: fmtPct(alert.confidence, 0) },
                  { label: "Category", value: alert.category },
                  { label: "Source", value: alert.source || "internal" },
                ]}
              />
              <p className="mt-3 text-[11.5px] leading-relaxed text-ink">{alert.trigger_reason}</p>
              {detail.rule && (
                <div className="mt-3 rounded-lg border border-ion/15 bg-ion/[0.04] px-3 py-2.5">
                  <div className="font-mono text-[8px] uppercase tracking-[0.12em] text-ion">{detail.rule.name}</div>
                  <p className="mt-1 text-[10.5px] leading-relaxed text-mist">{detail.rule.logic}</p>
                </div>
              )}
            </div>

            {alert.recommended_action && (
              <InlineNotice tone="med" className="mt-3" title="Suggested next action">
                {alert.recommended_action}
              </InlineNotice>
            )}

            <DrawerSection title="Evidence recorded by the rule" kicker="Why the alert fired">
              <EvidenceList items={alert.evidence} empty="No evidence payload was stored with this alert." />
            </DrawerSection>

            <DrawerSection title="Timeline" kicker="Workflow history">
              <ol className="relative ml-2 space-y-3 border-l border-line pl-4">
                {(detail.timeline || []).map((entry: any, index: number) => (
                  <li key={`${entry.at}-${index}`} className="relative">
                    <span className="absolute -left-[21px] top-1 h-2 w-2 rounded-full border border-ion/60 bg-surface" />
                    <div className="text-[11px] text-ink">{entry.label}</div>
                    <div className="font-mono text-[8.5px] text-dim">{fmtDate(entry.at, true)}</div>
                  </li>
                ))}
              </ol>
              <div className="mt-3 flex items-center gap-2 font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">
                <Activity size={10} /> assignee {detail.assignee?.full_name || "unassigned"}
              </div>
            </DrawerSection>

            {(detail.threat || detail.vulnerability) && (
              <DrawerSection title="Linked intelligence" kicker="Underlying records">
                <div className="flex flex-wrap gap-2">
                  {detail.threat && (
                    <Link to={`/app/threats?focus=${detail.threat.ref}`} className="rounded-md border border-line bg-shade/20 px-3 py-2 hover:border-ion/30">
                      <div className="font-mono text-[8px] text-dim">{detail.threat.ref}</div>
                      <div className="max-w-[240px] truncate text-[11px] text-ink">{detail.threat.name}</div>
                    </Link>
                  )}
                  {detail.vulnerability && (
                    <Link to={`/app/vulnerabilities?focus=${detail.vulnerability.cve_id}`} className="rounded-md border border-line bg-shade/20 px-3 py-2 hover:border-ion/30">
                      <div className="font-mono text-[8px] text-dim">{detail.vulnerability.cve_id}</div>
                      <div className="max-w-[240px] truncate text-[11px] text-ink">{detail.vulnerability.title}</div>
                    </Link>
                  )}
                </div>
              </DrawerSection>
            )}

            {!!detail.assets?.length && (
              <DrawerSection title="Assets in scope" kicker="Registered inventory">
                <div className="space-y-1.5">
                  {detail.assets.map((asset: any) => (
                    <Link key={asset.id} to={`/app/assets?focus=${asset.ref}`} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-line bg-shade/20 px-3 py-2 hover:border-ion/30">
                      <div>
                        <span className="mr-2 font-mono text-[8px] text-dim">{asset.ref}</span>
                        <span className="text-[11px] text-ink">{asset.name}</span>
                      </div>
                      <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">{asset.software} {asset.software_version} · criticality {asset.criticality}/5</span>
                    </Link>
                  ))}
                </div>
              </DrawerSection>
            )}

            {!!detail.recommendations?.length && (
              <DrawerSection title="Linked recommendations" kicker="Advisory actions">
                <div className="space-y-1.5">
                  {detail.recommendations.map((rec: any) => (
                    <Link key={rec.id} to={`/app/recommendations?focus=${rec.ref}`} className="flex items-center justify-between gap-3 rounded-md border border-line bg-shade/20 px-3 py-2 hover:border-ion/30">
                      <div className="min-w-0">
                        <div className="font-mono text-[8px] text-dim">{rec.ref}</div>
                        <div className="truncate text-[11px] text-ink">{rec.title}</div>
                      </div>
                      <div className="flex shrink-0 items-center gap-2"><SeverityBadge severity={rec.priority} /><StatusBadge status={rec.status} /><ArrowRight size={11} className="text-dim" /></div>
                    </Link>
                  ))}
                </div>
              </DrawerSection>
            )}

            <DrawerSection title="Investigation notes" kicker="Analyst record" right={<span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{detail.notes?.length || 0} note(s)</span>}>
              {can("analyst") && (
                <div className="mb-3">
                  <textarea
                    className="field"
                    rows={3}
                    value={note}
                    onChange={(event) => setNote(event.target.value)}
                    placeholder="Record what you checked, what the evidence supports and what remains uncertain…"
                    maxLength={4000}
                  />
                  <div className="mt-2 flex justify-end">
                    <button className="btn btn-ghost btn-sm" disabled={note.trim().length < 2 || addNote.isPending} onClick={() => addNote.mutate()}>
                      <MessageSquarePlus size={12} /> {addNote.isPending ? "Saving…" : "Add note"}
                    </button>
                  </div>
                </div>
              )}
              {!detail.notes?.length ? (
                <p className="text-[11px] text-dim">No investigation notes yet.</p>
              ) : (
                <div className="space-y-1.5">
                  {detail.notes.map((entry: any) => (
                    <div key={entry.id} className="rounded-md border border-line bg-shade/20 px-3 py-2">
                      <div className="font-mono text-[8px] uppercase tracking-[0.08em] text-dim">{entry.author?.full_name || "Analyst"} · {fmtDate(entry.created_at, true)}</div>
                      <p className="mt-1 whitespace-pre-line text-[11px] leading-relaxed text-mist">{entry.body}</p>
                    </div>
                  ))}
                </div>
              )}
            </DrawerSection>
          </div>
        )}
      </Drawer>
    </>
  );
}
