import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  Download,
  FileClock,
  Fingerprint,
  History,
  ListFilter,
  ShieldCheck,
  UserRound,
} from "lucide-react";
import clsx from "clsx";
import { api, downloadFile, qs, type Paginated } from "../../lib/api";
import { fmtDate, fmtNumber, relTime, titleCase } from "../../lib/format";
import { useAuth } from "../../context/AuthContext";
import {
  CopyButton,
  Drawer,
  ErrorState,
  Kpi,
  LoadingBlock,
  PageHeader,
  Pagination,
  Panel,
  PanelHead,
  RangeTabs,
  SearchField,
  useToast,
} from "../../components/ui";
import { DrawerSection, FilterSelect, SectionLabel } from "./shared";

type AuditRow = {
  id: number;
  user_email: string;
  action: string;
  entity_type: string;
  entity_id: string;
  detail: string;
  ip_address: string;
  created_at: string;
};

const ENTITIES = [
  "threat",
  "vulnerability",
  "asset",
  "alert",
  "recommendation",
  "risk_assessment",
  "risk_setting",
  "user",
  "threat_source",
  "indicator",
  "chat",
  "threat_correlation",
  "setting",
  "auth",
];

const ACTION_TONE: Record<string, string> = {
  user: "text-ion",
  auth: "text-violet",
  risk: "text-med",
  alert: "text-crit",
  source: "text-low",
  asset: "text-info",
  threat: "text-high",
  vulnerability: "text-info",
  chat: "text-violet",
  correlation: "text-ion",
  model: "text-med",
  export: "text-dim",
};

function actionTone(action: string) {
  return ACTION_TONE[action.split(".")[0]] || "text-mist";
}

export default function Audit() {
  const { user } = useAuth();
  const { push } = useToast();

  const [q, setQ] = useState("");
  const [action, setAction] = useState("all");
  const [entity, setEntity] = useState("all");
  const [range, setRange] = useState("30d");
  const [page, setPage] = useState(1);
  const [focus, setFocus] = useState<AuditRow | null>(null);

  const query = useQuery({
    queryKey: ["audit-logs", q, action, entity, range, page],
    queryFn: () =>
      api<Paginated<AuditRow> & { actions: string[] }>(
        `/admin/audit${qs({
          q: q || undefined,
          action: action === "all" ? undefined : action,
          entity: entity === "all" ? undefined : entity,
          range,
          page,
          size: 40,
        })}`,
      ),
  });

  const data = query.data;
  const rows = data?.items || [];
  const actions = data?.actions || [];
  const actors = new Set(rows.map((row) => row.user_email)).size;

  const exportCsv = async () => {
    try {
      await downloadFile(`/admin/audit/export.csv${qs({ range })}`, "cyberguard-audit.csv");
      push("success", "Audit export downloaded (range-filtered, up to 10,000 rows).");
    } catch (error: any) {
      push("error", error.message || "Audit export failed.");
    }
  };

  return (
    <>
      <PageHeader
        title="Audit trail"
        description="Append-only record of privileged and analytical actions. Each entry captures the actor, affected entity, summary and source address. Entries are written in the same transaction as the change they describe."
        aside={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span><span className="text-ink">{fmtNumber(data?.total)}</span> events in range</span>
            <span>·</span>
            <span><span className="text-ink">{rows.length}</span> in view</span>
            <span>·</span>
            <span>{actions.length} action types</span>
            {user && <><span>·</span><span>{user.role} view</span></>}
          </div>
        }
        actions={
          <>
            <RangeTabs value={range} onChange={(value) => { setRange(value); setPage(1); }} />
            <button className="btn btn-ghost btn-sm" onClick={exportCsv}><Download size={13} /> Export CSV</button>
          </>
        }
      />

      <div className="mb-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Events in range" value={fmtNumber(data?.total)} detail="Across all recorded actions" icon={<History size={15} />} tone="ion" />
        <Kpi label="Distinct actors in view" value={String(actors)} detail="Unique accounts on this page" icon={<UserRound size={15} />} tone="violet" />
        <Kpi label="Action types" value={String(actions.length)} detail="Distinct verbs recorded" icon={<ListFilter size={15} />} tone="med" />
        <Kpi label="Most recent" value={rows[0] ? relTime(rows[0].created_at) : "—"} detail={rows[0]?.action || "No events in range"} icon={<Activity size={15} />} tone="low" />
      </div>

      <Panel>
        <PanelHead
          title="Event stream"
          kicker="Newest first"
          right={<span className="font-mono text-[9px] uppercase tracking-[0.1em] text-dim">page {data?.page ?? 1} / {Math.max(1, data?.pages ?? 1)}</span>}
        />
        <div className="grid gap-2 border-b border-line px-4 py-3 sm:grid-cols-[minmax(200px,1.4fr)_190px_170px_auto]">
          <div>
            <span className="field-label">Search</span>
            <SearchField value={q} onChange={(value) => { setQ(value); setPage(1); }} placeholder="Actor, detail, entity or action…" />
          </div>
          <FilterSelect
            label="Action"
            value={action}
            onChange={(value) => { setAction(value); setPage(1); }}
            options={[{ value: "all", label: "All actions" }, ...actions.map((entry) => ({ value: entry, label: entry }))]}
          />
          <FilterSelect
            label="Entity"
            value={entity}
            onChange={(value) => { setEntity(value); setPage(1); }}
            options={[{ value: "all", label: "All entities" }, ...ENTITIES.map((entry) => ({ value: entry, label: titleCase(entry.replace(/_/g, " ")) }))]}
          />
          <div className="flex items-end">
            <span className="rounded-md border border-line bg-shade/20 px-3 py-2 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">immutable log</span>
          </div>
        </div>

        {query.isError ? (
          <ErrorState message={(query.error as any)?.message} retry={() => query.refetch()} />
        ) : query.isLoading ? (
          <LoadingBlock rows={10} label="Loading audit trail" />
        ) : !rows.length ? (
          <div className="py-16 text-center">
            <FileClock size={19} className="mx-auto text-dim" />
            <p className="mt-2 text-[12px] text-mist">No audit entries match these filters.</p>
            <p className="mt-1 text-[10.5px] text-dim">Try a wider range or clear the action and entity filters.</p>
          </div>
        ) : (
          <div className="table-shell overflow-x-auto border-0">
            <table className="w-full">
              <thead>
                <tr>
                  <th className="w-[150px]">Timestamp</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Entity</th>
                  <th>Detail</th>
                  <th className="w-[110px]">Address</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id} className="cursor-pointer" onClick={() => setFocus(row)}>
                    <td className="whitespace-nowrap">
                      <div className="font-mono text-[9.5px] text-ink">{fmtDate(row.created_at)}</div>
                      <div className="font-mono text-[8.5px] text-dim">{relTime(row.created_at)}</div>
                    </td>
                    <td className="max-w-[190px]"><span className="block truncate font-mono text-[9.5px] text-mist">{row.user_email}</span></td>
                    <td><span className={clsx("font-mono text-[9.5px]", actionTone(row.action))}>{row.action}</span></td>
                    <td>
                      {row.entity_type ? (
                        <div>
                          <div className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">{titleCase(row.entity_type.replace(/_/g, " "))}</div>
                          {row.entity_id && <div className="font-mono text-[9px] text-mist">{row.entity_id}</div>}
                        </div>
                      ) : <span className="text-dim">—</span>}
                    </td>
                    <td className="max-w-[360px]"><span className="block truncate text-[10px] text-dim" title={row.detail}>{row.detail || "—"}</span></td>
                    <td><span className="font-mono text-[9px] text-dim">{row.ip_address || "—"}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && <Pagination page={data.page} pages={data.pages} total={data.total} onPage={setPage} />}
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-4 py-2.5 font-mono text-[8px] uppercase tracking-[0.1em] text-dim">
          <span>Export includes the time range only — apply filters for on-screen review</span>
          <span>CSV limited to 10,000 rows</span>
        </div>
      </Panel>

      <Drawer
        open={Boolean(focus)}
        onClose={() => setFocus(null)}
        title={<span className="font-mono text-[13px] text-ink">{focus?.action}</span>}
        subtitle={
          focus && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
              <span>{fmtDate(focus.created_at)}</span><span>·</span><span>{relTime(focus.created_at)}</span>
            </div>
          )
        }
        width="max-w-[520px]"
      >
        {focus && (
          <div>
            <div className="rounded-xl border border-line bg-shade/25 p-4">
              <div className="flex items-center gap-2">
                <span className="grid h-8 w-8 place-items-center rounded-lg border border-ion/25 bg-ion/[0.06] text-ion"><Fingerprint size={14} /></span>
                <div>
                  <div className="font-mono text-[9px] uppercase tracking-[0.12em] text-dim">Actor</div>
                  <div className="text-[12px] text-ink">{focus.user_email}</div>
                </div>
              </div>
              <p className="mt-3 text-[11px] leading-relaxed text-mist">{focus.detail || "No additional detail was recorded for this event."}</p>
              <div className="mt-3 flex flex-wrap gap-2">
                <CopyButton value={String(focus.id)} label="Copy event ID" />
              </div>
            </div>

            <DrawerSection title="Event attributes" kicker="Immutable record">
              <div className="grid gap-2 sm:grid-cols-2">
                {[
                  ["Event ID", String(focus.id)],
                  ["Action", focus.action],
                  ["Entity type", focus.entity_type || "—"],
                  ["Entity ID", focus.entity_id || "—"],
                  ["Source address", focus.ip_address || "—"],
                  ["Recorded", `${fmtDate(focus.created_at)} (${relTime(focus.created_at)})`],
                ].map(([label, value]) => (
                  <div key={label} className="rounded-md border border-line bg-shade/20 px-3 py-2">
                    <div className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{label}</div>
                    <div className="mt-0.5 break-words font-mono text-[10px] text-ink">{value}</div>
                  </div>
                ))}
              </div>
            </DrawerSection>

            <DrawerSection title="Detail" kicker="Full recorded context">
              <pre className="overflow-x-auto whitespace-pre-wrap break-words rounded-md border border-line bg-shade/25 p-3 font-mono text-[10px] leading-relaxed text-mist">{focus.detail || "—"}</pre>
            </DrawerSection>

            <DrawerSection title="Integrity" kicker="How to read this entry">
              <SectionLabel>Append-only</SectionLabel>
              <p className="text-[10.5px] leading-relaxed text-mist">
                Audit rows are inserted when the corresponding change commits. They are not editable from the interface. Database-level access could still alter history; export periodic snapshots if regulatory retention applies.
              </p>
              <div className="mt-3 flex items-start gap-2 rounded-md border border-low/20 bg-low/[0.04] px-3 py-2">
                <ShieldCheck size={12} className="mt-0.5 shrink-0 text-low" />
                <span className="text-[9.5px] leading-relaxed text-mist">Secrets, tokens and password values are never written to this trail.</span>
              </div>
            </DrawerSection>
          </div>
        )}
      </Drawer>
    </>
  );
}
