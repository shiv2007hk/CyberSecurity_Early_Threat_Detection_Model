import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CalendarClock,
  CheckCheck,
  ChevronRight,
  CircleDot,
  Download,
  ListChecks,
  Play,
  RotateCcw,
  ShieldCheck,
  UserRound,
  X,
} from "lucide-react";
import clsx from "clsx";
import { api, downloadFile, qs, type Paginated, type Recommendation } from "../../lib/api";
import { fmtDate, fmtNumber, relTime, titleCase } from "../../lib/format";
import { useAuth } from "../../context/AuthContext";
import {
  Drawer,
  EmptyState,
  ErrorState,
  InlineNotice,
  Kpi,
  LoadingBlock,
  PageHeader,
  Panel,
  PanelHead,
  RangeTabs,
  SearchField,
  SeverityBadge,
  StatusBadge,
  useToast,
} from "../../components/ui";
import { DistributionDonut } from "../../components/charts";
import { DrawerSection, EvidenceList, FieldLabel, FilterSelect, SectionLabel } from "./shared";

const LANES = [
  { key: "open", label: "Queued", hint: "Not started", icon: <CircleDot size={12} /> },
  { key: "in_progress", label: "In progress", hint: "Being worked", icon: <Play size={12} /> },
  { key: "closed", label: "Closed", hint: "Done or dismissed", icon: <CheckCheck size={12} /> },
];

function laneOf(status: string) {
  if (status === "open") return "open";
  if (status === "in_progress") return "in_progress";
  return "closed";
}

function isOverdue(rec: Recommendation) {
  return Boolean(rec.due_at) && new Date(rec.due_at as string).getTime() < Date.now() && !["done", "dismissed"].includes(rec.status);
}

export default function Recommendations() {
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();

  const [q, setQ] = useState("");
  const [priority, setPriority] = useState("all");
  const [range, setRange] = useState("90d");
  const [owner, setOwner] = useState("");
  const [dueInDays, setDueInDays] = useState("30");

  const focus = searchParams.get("focus");

  const params = { q, priority, range, size: 100, page: 1 };
  const listQuery = useQuery({
    queryKey: ["recommendations", params],
    queryFn: () => api<Paginated<Recommendation>>(`/recommendations${qs(params)}`),
  });
  const summaryQuery = useQuery({ queryKey: ["recommendation-summary"], queryFn: () => api<any>("/recommendations/summary") });
  const usersQuery = useQuery({
    queryKey: ["admin-users-lite"],
    queryFn: () => api<any>("/admin/users?size=100&active=true"),
    enabled: can("admin"),
  });
  const detailQuery = useQuery({
    queryKey: ["recommendation-detail", focus],
    queryFn: () => api<any>(`/recommendations/${focus}`),
    enabled: Boolean(focus),
  });

  const data = listQuery.data;
  const summary = summaryQuery.data;
  const detail = detailQuery.data;
  const items = data?.items || [];
  const active: Recommendation | undefined = detail || items.find((item) => item.ref === focus);

  useEffect(() => {
    if (active) {
      setOwner(active.owner_id ? String(active.owner_id) : "");
    }
  }, [active]);

  const openDrawer = (ref: string) =>
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("focus", ref);
      return next;
    });
  const closeDrawer = () =>
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete("focus");
      return next;
    });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["recommendations"] });
    queryClient.invalidateQueries({ queryKey: ["recommendation-summary"] });
    queryClient.invalidateQueries({ queryKey: ["recommendation-detail", focus] });
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  };

  const update = useMutation({
    mutationFn: (vars: { ref: string; payload: Record<string, any> }) =>
      api(`/recommendations/${vars.ref}`, { method: "PATCH", body: JSON.stringify(vars.payload) }),
    onSuccess: (_result, vars) => {
      push("success", vars.payload.status ? `Recommendation marked ${titleCase(String(vars.payload.status))}.` : "Owner assignment updated.");
      invalidate();
    },
    onError: (error: any) => push("error", error.message || "The recommendation could not be updated."),
  });

  const exportCsv = async () => {
    try {
      await downloadFile(`/recommendations/export.csv${qs({ q, priority, range })}`, "recommendations.csv");
      push("success", "Recommendation export downloaded.");
    } catch (error: any) {
      push("error", error.message || "Export failed.");
    }
  };

  const lanes = useMemo(() => {
    const grouped: Record<string, Recommendation[]> = { open: [], in_progress: [], closed: [] };
    items.forEach((item) => grouped[laneOf(item.status)].push(item));
    return grouped;
  }, [items]);

  const feedbackOwners: any[] = usersQuery.data?.items || [];
  const statusDistribution = (summary?.status_distribution || []).map((entry: any) => ({ name: entry.name, value: entry.value }));
  const overdue = items.filter(isOverdue).length;

  const laneAction = (rec: Recommendation) => {
    if (rec.status === "open") return { label: "Start", next: "in_progress", icon: <Play size={11} /> };
    if (rec.status === "in_progress") return { label: "Complete", next: "done", icon: <CheckCheck size={11} /> };
    return { label: "Reopen", next: "open", icon: <RotateCcw size={11} /> };
  };

  return (
    <>
      <PageHeader
        title="Remediation recommendations"
        description="Advisory, non-disruptive actions derived from validated exposure, known-exploited evidence and alert triggers. Nothing here executes containment, blocking or host changes automatically."
        aside={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span><span className="text-ink">{fmtNumber(summary?.open)}</span> open</span>
            <span><span className="text-ink">{fmtNumber(summary?.in_progress)}</span> in progress</span>
            <span><span className="text-ink">{fmtNumber(summary?.done)}</span> done</span>
            <span><span className={overdue ? "text-crit" : "text-ink"}>{overdue}</span> overdue in view</span>
          </div>
        }
        actions={
          <>
            <RangeTabs value={range} onChange={setRange} />
            <button className="btn btn-ghost btn-sm" onClick={exportCsv}><Download size={13} /> Export</button>
          </>
        }
      />

      <div className="mb-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Open actions" value={fmtNumber(summary?.open)} detail="Awaiting an owner or start" icon={<ListChecks size={15} />} tone="ion" />
        <Kpi label="In progress" value={fmtNumber(summary?.in_progress)} detail="Actively being remediated" icon={<ShieldCheck size={15} />} tone="violet" />
        <Kpi
          label="Critical open"
          value={fmtNumber(summary?.active_by_priority?.find((entry: any) => entry.name === "Critical")?.value)}
          detail="Critical priority and still active"
          icon={<CircleDot size={15} />}
          tone="crit"
        />
        <Kpi label="Overdue in view" value={fmtNumber(overdue)} detail={`${fmtNumber(items.length)} recommendations in the current filter`} icon={<CalendarClock size={15} />} tone="med" />
      </div>

      <div className="mb-4 grid gap-4 xl:grid-cols-[1fr_1.4fr]">
        <Panel>
          <PanelHead title="Workflow state" kicker="All recommendations" />
          <div className="p-4">
            <DistributionDonut data={statusDistribution} height={168} centerLabel="actions" centerValue={summary?.total ?? 0} colors={["#49b8ff", "#64d8ff", "#42c98a", "#64798f"]} />
          </div>
        </Panel>
        <Panel>
          <PanelHead title="Active by priority" kicker="Open and in-progress" />
          <div className="grid gap-2 p-4 sm:grid-cols-2">
            {["Critical", "High", "Medium", "Low"].map((name) => {
              const value = summary?.active_by_priority?.find((entry: any) => entry.name === name)?.value ?? 0;
              const max = Math.max(1, ...(summary?.active_by_priority || []).map((entry: any) => entry.value));
              return (
                <div key={name} className="rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                  <div className="flex items-baseline justify-between">
                    <SeverityBadge severity={name.toLowerCase()} />
                    <span className="tnum font-display text-[19px] font-semibold text-ink">{value}</span>
                  </div>
                  <div className="mt-2 h-[3px] overflow-hidden rounded-full bg-veil/[0.06]">
                    <div className="h-full rounded-full" style={{ width: `${(value / max) * 100}%`, background: name === "Critical" ? "#ff4d5e" : name === "High" ? "#ff963d" : name === "Medium" ? "#ffd166" : "#42c98a" }} />
                  </div>
                </div>
              );
            })}
          </div>
          <div className="border-t border-line px-4 py-2 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{data?.note}</div>
        </Panel>
      </div>

      <Panel className="mb-4">
        <div className="grid gap-3 p-3.5 sm:grid-cols-[minmax(220px,1.5fr)_minmax(140px,0.7fr)_auto]">
          <div>
            <span className="field-label">Search actions</span>
            <SearchField value={q} onChange={setQ} placeholder="Title, action, reason, reference…" />
          </div>
          <FilterSelect
            label="Priority"
            value={priority}
            onChange={setPriority}
            options={[
              { value: "all", label: "All priorities" },
              ...["critical", "high", "medium", "low"].map((name) => ({ value: name, label: titleCase(name) })),
            ]}
          />
          <div className="flex items-end">
            <span className="rounded-md border border-line bg-shade/20 px-3 py-2 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
              {fmtNumber(data?.total)} action(s)
            </span>
          </div>
        </div>
      </Panel>

      {listQuery.isError ? (
        <Panel><ErrorState message={(listQuery.error as any)?.message} retry={() => listQuery.refetch()} /></Panel>
      ) : listQuery.isLoading ? (
        <Panel><LoadingBlock rows={8} label="Loading remediation workflow" /></Panel>
      ) : !items.length ? (
        <Panel>
          <EmptyState
            title="No recommendations in this view"
            detail="Recommendations appear when validated exposure or early-warning logic produces an actionable defensive step. Adjust the range or priority filter."
            icon={<ListChecks size={19} />}
          />
        </Panel>
      ) : (
        <div className="grid gap-4 lg:grid-cols-3">
          {LANES.map((lane) => {
            const laneItems = lanes[lane.key];
            return (
              <section key={lane.key} className="min-w-0">
                <div className="mb-2 flex items-center justify-between gap-2 px-1">
                  <div className="flex items-center gap-2">
                    <span className="grid h-6 w-6 place-items-center rounded-md border border-line bg-veil/[0.02] text-mist">{lane.icon}</span>
                    <span className="text-[12px] font-semibold text-ink">{lane.label}</span>
                    <span className="font-mono text-[9px] text-dim">{laneItems.length}</span>
                  </div>
                  <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{lane.hint}</span>
                </div>
                <div className="flex min-h-[220px] flex-col gap-2 rounded-xl border border-line bg-shade/15 p-2">
                  {!laneItems.length ? (
                    <div className="grid flex-1 place-items-center py-8 text-center">
                      <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">No actions in this state</span>
                    </div>
                  ) : (
                    laneItems.map((rec) => {
                      const action = laneAction(rec);
                      const overdueFlag = isOverdue(rec);
                      return (
                        <article
                          key={rec.id}
                          className="group cursor-pointer rounded-lg border border-line bg-surface/85 p-3 transition-colors hover:border-ion/35"
                          onClick={() => openDrawer(rec.ref)}
                        >
                          <div className="flex items-start justify-between gap-2">
                            <div className="flex items-center gap-1.5">
                              <SeverityBadge severity={rec.priority} />
                              <span className="font-mono text-[8px] text-dim">{rec.ref}</span>
                            </div>
                            <ChevronRight size={12} className="text-dim transition-transform group-hover:translate-x-0.5" />
                          </div>
                          <h3 className="mt-2 break-words text-[12px] leading-snug text-ink">{rec.title}</h3>
                          <div className="mt-2 flex flex-wrap items-center gap-1.5">
                            {rec.vulnerability && <span className="chip text-info">{rec.vulnerability.cve_id}</span>}
                            {rec.asset && <span className="chip">{rec.asset.ref}</span>}
                            {rec.threat && <span className="chip">{rec.threat.ref}</span>}
                          </div>
                          <div className="mt-2.5 flex items-center justify-between gap-2 border-t border-veil/[0.05] pt-2">
                            <div className="min-w-0 font-mono text-[8px] uppercase tracking-[0.08em] text-dim">
                              <div className="flex items-center gap-1 truncate">
                                <UserRound size={9} /> {rec.owner?.full_name || "Unassigned"}
                              </div>
                              <div className={clsx("mt-0.5 flex items-center gap-1", overdueFlag ? "text-crit" : "text-dim")}>
                                <CalendarClock size={9} /> {rec.due_at ? `due ${fmtDate(rec.due_at)}` : "no due date"}
                              </div>
                            </div>
                            {can("analyst") && (
                              <button
                                className="btn btn-quiet btn-sm"
                                onClick={(event) => {
                                  event.stopPropagation();
                                  setSearchParams((prev) => {
                                    const next = new URLSearchParams(prev);
                                    next.set("focus", rec.ref);
                                    return next;
                                  });
                                  update.mutate({ ref: rec.ref, payload: { status: action.next } });
                                }}
                                disabled={update.isPending}
                              >
                                {action.icon} {action.label}
                              </button>
                            )}
                          </div>
                          {lane.key === "closed" && <div className="mt-2"><StatusBadge status={rec.status} /></div>}
                        </article>
                      );
                    })
                  )}
                </div>
              </section>
            );
          })}
        </div>
      )}

      <Drawer
        open={Boolean(focus && active)}
        onClose={closeDrawer}
        width="max-w-[680px]"
        title={
          active ? (
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={active.priority} />
              <span className="text-[14px] font-semibold text-ink">{active.title}</span>
            </div>
          ) : (
            <span>Recommendation</span>
          )
        }
        subtitle={
          active && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
              <span>{active.ref}</span><span>·</span><StatusBadge status={active.status} /><span>·</span>
              <span>created {fmtDate(active.created_at)}</span>
            </div>
          )
        }
        footer={
          can("analyst") && active ? (
            <>
              <div className="mr-auto flex flex-wrap items-center gap-2">
                {can("admin") && (
                  <select className="field h-[34px] w-[176px] text-[10.5px]" value={owner} onChange={(event) => setOwner(event.target.value)} aria-label="Recommendation owner">
                    <option value="">Unassigned</option>
                    {feedbackOwners.map((person: any) => <option key={person.id} value={person.id}>{person.full_name}</option>)}
                  </select>
                )}
                <select className="field h-[34px] w-[126px] text-[10.5px]" value={dueInDays} onChange={(event) => setDueInDays(event.target.value)} aria-label="Due window">
                  <option value="7">Due in 7d</option>
                  <option value="14">Due in 14d</option>
                  <option value="30">Due in 30d</option>
                  <option value="60">Due in 60d</option>
                </select>
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => update.mutate({ ref: active.ref, payload: { owner_id: owner ? Number(owner) : null, due_in_days: Number(dueInDays) } })}
                  disabled={update.isPending}
                >
                  Save assignment
                </button>
              </div>
              {active.status !== "done" && <button className="btn btn-ghost btn-sm" onClick={() => update.mutate({ ref: active.ref, payload: { status: "dismissed" } })} disabled={update.isPending}><X size={12} /> Dismiss</button>}
              {active.status === "open" && <button className="btn btn-ghost btn-sm" onClick={() => update.mutate({ ref: active.ref, payload: { status: "in_progress" } })} disabled={update.isPending}><Play size={12} /> Start</button>}
              {active.status !== "done" ? (
                <button className="btn btn-primary btn-sm" onClick={() => update.mutate({ ref: active.ref, payload: { status: "done" } })} disabled={update.isPending}><CheckCheck size={12} /> Mark complete</button>
              ) : (
                <button className="btn btn-primary btn-sm" onClick={() => update.mutate({ ref: active.ref, payload: { status: "open" } })} disabled={update.isPending}><RotateCcw size={12} /> Reopen</button>
              )}
            </>
          ) : (
            <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">Read-only — analysts manage this workflow</span>
          )
        }
      >
        {detailQuery.isError ? (
          <ErrorState message={(detailQuery.error as any)?.message} retry={() => detailQuery.refetch()} compact />
        ) : detailQuery.isLoading || !active ? (
          <LoadingBlock rows={7} label="Loading recommendation" />
        ) : (
          <div>
            <div className="rounded-xl border border-line bg-shade/25 p-4">
              <div className="panel-kicker">Recommended action</div>
              <p className="mt-1.5 text-[12px] leading-relaxed text-ink">{detail.action}</p>
              {detail.reason && (
                <>
                  <div className="panel-kicker mt-4">Why it was raised</div>
                  <p className="mt-1.5 text-[11px] leading-relaxed text-mist">{detail.reason}</p>
                </>
              )}
            </div>

            <DrawerSection title="Workflow context" kicker="Ownership and timing">
              <div className="grid gap-2 sm:grid-cols-3">
                <div className="rounded-md border border-line bg-shade/20 px-3 py-2">
                  <div className="panel-kicker">Owner</div>
                  <div className="mt-1 text-[11px] text-ink">{detail.owner?.full_name || "Unassigned"}</div>
                </div>
                <div className="rounded-md border border-line bg-shade/20 px-3 py-2">
                  <div className="panel-kicker">Due</div>
                  <div className={clsx("mt-1 text-[11px]", isOverdue(active) ? "text-crit" : "text-ink")}>{detail.due_at ? fmtDate(detail.due_at) : "Not set"}</div>
                </div>
                <div className="rounded-md border border-line bg-shade/20 px-3 py-2">
                  <div className="panel-kicker">State</div>
                  <div className="mt-1"><StatusBadge status={detail.status} /></div>
                </div>
              </div>
            </DrawerSection>

            <DrawerSection title="Evidence" kicker="Basis for the action">
              <EvidenceList items={detail.evidence} empty="No structured evidence was attached; see the linked records." />
            </DrawerSection>

            <DrawerSection title="Linked records" kicker="Traceability">
              <div className="flex flex-wrap gap-2">
                {detail.vulnerability && (
                  <Link to={`/app/vulnerabilities?focus=${detail.vulnerability.cve_id}`} className="rounded-md border border-line bg-shade/20 px-3 py-2 hover:border-ion/30">
                    <div className="font-mono text-[8px] text-dim">VULNERABILITY</div>
                    <div className="text-[11px] text-ink">{detail.vulnerability.cve_id}</div>
                    <div className="max-w-[220px] truncate font-mono text-[8.5px] text-dim">{detail.vulnerability.title}</div>
                  </Link>
                )}
                {detail.threat && (
                  <Link to={`/app/threats?focus=${detail.threat.ref}`} className="rounded-md border border-line bg-shade/20 px-3 py-2 hover:border-ion/30">
                    <div className="font-mono text-[8px] text-dim">THREAT · {detail.threat.ref}</div>
                    <div className="max-w-[220px] truncate text-[11px] text-ink">{detail.threat.name}</div>
                  </Link>
                )}
                {detail.asset && (
                  <Link to={`/app/assets?focus=${detail.asset.ref}`} className="rounded-md border border-line bg-shade/20 px-3 py-2 hover:border-ion/30">
                    <div className="font-mono text-[8px] text-dim">ASSET · {detail.asset.ref}</div>
                    <div className="max-w-[220px] truncate text-[11px] text-ink">{detail.asset.name}</div>
                  </Link>
                )}
                {detail.alert && (
                  <Link to={`/app/alerts?focus=${detail.alert.ref}`} className="rounded-md border border-line bg-shade/20 px-3 py-2 hover:border-ion/30">
                    <div className="font-mono text-[8px] text-dim">ALERT · {detail.alert.ref}</div>
                    <div className="max-w-[220px] truncate text-[11px] text-ink">{detail.alert.title}</div>
                  </Link>
                )}
              </div>
              {detail.source_url && (
                <a href={detail.source_url} target="_blank" rel="noreferrer" className="mt-3 inline-flex items-center gap-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-ion hover:text-crystal">
                  Source advisory <ChevronRight size={10} />
                </a>
              )}
            </DrawerSection>

            <DrawerSection title="Methodology" kicker="Boundaries">
              <p className="text-[11px] leading-relaxed text-mist">{detail.methodology}</p>
            </DrawerSection>

            <InlineNotice tone="med" className="mt-3">
              This is an advisory action requiring human approval through approved change processes. The platform has no authority to alter production hosts or block traffic.
            </InlineNotice>
          </div>
        )}
      </Drawer>
    </>
  );
}
