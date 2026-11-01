import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BadgeCheck,
  CircleSlash,
  Crosshair,
  Download,
  GitCompareArrows,
  Radar,
  ScanSearch,
  ShieldAlert,
  ShieldQuestion,
} from "lucide-react";
import clsx from "clsx";
import { api, downloadFile, qs, type Paginated } from "../../lib/api";
import { fmtNumber, fmtPct, relTime, riskColor, titleCase } from "../../lib/format";
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
  SearchField,
  SeverityBadge,
  StatusBadge,
  useToast,
} from "../../components/ui";
import { DistributionDonut } from "../../components/charts";
import { DrawerSection, EvidenceList, FieldLabel, FilterSelect, MiniBar, ScoreChip } from "./shared";

const STATUS_OPTIONS = [
  { value: "confirmed", label: "Confirmed exposure" },
  { value: "potentially_exposed", label: "Potentially exposed" },
  { value: "needs_verification", label: "Needs verification" },
  { value: "not_affected", label: "Not affected" },
];

const STATUS_ICON: Record<string, React.ReactNode> = {
  confirmed: <BadgeCheck size={12} />,
  potentially_exposed: <ShieldAlert size={12} />,
  needs_verification: <ShieldQuestion size={12} />,
  not_affected: <CircleSlash size={12} />,
};

export default function Exposure() {
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();

  const [q, setQ] = useState("");
  const [status, setStatus] = useState("all");
  const [category, setCategory] = useState("all");
  const [minCvss, setMinCvss] = useState("all");
  const [page, setPage] = useState(1);
  const [verdict, setVerdict] = useState("confirmed");
  const [note, setNote] = useState("");

  const focus = searchParams.get("match");
  useEffect(() => setPage(1), [q, status, category, minCvss]);

  const params = {
    q,
    status,
    category,
    min_cvss: minCvss === "all" ? undefined : minCvss,
    page,
    size: 25,
  };
  const listQuery = useQuery({
    queryKey: ["exposure", params],
    queryFn: () => api<Paginated<any>>(`/exposure${qs(params)}`),
  });
  const summaryQuery = useQuery({
    queryKey: ["exposure-summary"],
    queryFn: () => api<any>("/exposure/summary"),
  });

  const data = listQuery.data;
  const summary = summaryQuery.data;
  const rows: any[] = data?.items || [];
  const selected = rows.find((row) => String(row.id) === focus) || null;

  const openMatch = (row: any) => {
    setVerdict(row.status === "needs_verification" ? "needs_verification" : row.status);
    setNote("");
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("match", String(row.id));
      return next;
    });
  };
  const closeMatch = () =>
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete("match");
      return next;
    });

  const scan = useMutation({
    mutationFn: () => api<any>("/exposure/scan", { method: "POST" }),
    onSuccess: (result) => {
      push(
        "success",
        `Scan complete: ${result.validated_matches} validated, ${result.needs_verification} need verification, ${result.recommendations_created} recommendation(s).`,
      );
      queryClient.invalidateQueries({ queryKey: ["exposure"] });
      queryClient.invalidateQueries({ queryKey: ["exposure-summary"] });
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      queryClient.invalidateQueries({ queryKey: ["recommendations"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (error: any) => push("error", error.message || "The exposure scan could not run."),
  });

  const updateMatch = useMutation({
    mutationFn: () => api(`/exposure/matches/${selected?.id}`, { method: "PATCH", body: JSON.stringify({ status: verdict, note }) }),
    onSuccess: () => {
      push("success", "Verification recorded. Counts and recommendations will reflect the confirmed state.");
      closeMatch();
      queryClient.invalidateQueries({ queryKey: ["exposure"] });
      queryClient.invalidateQueries({ queryKey: ["exposure-summary"] });
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      queryClient.invalidateQueries({ queryKey: ["recommendations"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (error: any) => push("error", error.message || "The verification could not be saved."),
  });

  const exportCsv = async () => {
    try {
      await downloadFile(`/exposure/export.csv${qs({ ...params, page: undefined, size: undefined })}`, "exposure.csv");
      push("success", "Exposure export downloaded.");
    } catch (error: any) {
      push("error", error.message || "Export failed.");
    }
  };

  const statusFacets: Array<{ name: string; count: number }> = data?.facets?.statuses || [];
  const categoryFacets: Array<{ name: string; count: number }> = data?.facets?.categories || [];
  const statusDistribution = (summary?.status_distribution || []).map((entry: any) => ({ name: entry.name, value: entry.value }));

  return (
    <>
      <PageHeader
        title="Exposure matching"
        description="Product- and version-validated links between vulnerabilities and registered assets, with analyst verification. An incomplete version match stays in 'needs verification' and never counts as confirmed exposure."
        actions={
          <>
            <button className="btn btn-ghost btn-sm" onClick={exportCsv}><Download size={13} /> Export</button>
            {can("analyst") && (
              <button className="btn btn-primary btn-sm" onClick={() => scan.mutate()} disabled={scan.isPending}>
                <ScanSearch size={13} /> {scan.isPending ? "Scanning inventory…" : "Run exposure scan"}
              </button>
            )}
          </>
        }
      />

      <div className="mb-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Validated exposure" value={fmtNumber(summary?.validated_matches)} detail={`${fmtNumber(summary?.assets_with_validated_exposure)} of ${fmtNumber(summary?.assets)} assets affected`} icon={<Crosshair size={15} />} tone="high" />
        <Kpi label="Confirmed by analyst" value={fmtNumber(summary?.confirmed)} detail="Human-verified affected assets" icon={<BadgeCheck size={15} />} tone="crit" />
        <Kpi label="Needs verification" value={fmtNumber(summary?.needs_verification)} detail="Incomplete or ambiguous version match" icon={<ShieldQuestion size={15} />} tone="med" />
        <Kpi label="Inventory coverage" value={`${summary?.coverage_percent ?? 0}%`} detail={`${fmtNumber(summary?.critical_assets_exposed)} high-criticality assets exposed`} icon={<Radar size={15} />} tone="ion" />
      </div>

      <div className="mb-4 grid gap-4 xl:grid-cols-[1.45fr_1fr]">
        <Panel ticks>
          <PanelHead title="Verification posture" kicker="Match states across inventory" right={<span className="chip">{fmtNumber(summary?.matches)} total matches</span>} />
          <div className="grid gap-4 p-4 sm:grid-cols-[200px_1fr]">
            <DistributionDonut data={statusDistribution} height={176} centerLabel="matches" centerValue={summary?.matches ?? 0} colors={["#42c98a", "#ff963d", "#ffd166", "#64798f"]} />
            <div className="space-y-2.5">
              {[
                { label: "Confirmed", value: summary?.confirmed ?? 0, color: "#42c98a", hint: "Analyst-verified affected" },
                { label: "Potentially exposed", value: (summary?.validated_matches ?? 0) - (summary?.confirmed ?? 0), color: "#ff963d", hint: "Version range validated" },
                { label: "Needs verification", value: summary?.needs_verification ?? 0, color: "#ffd166", hint: "Incomplete version evidence" },
                { label: "Not affected", value: summary?.not_affected ?? 0, color: "#64798f", hint: "Cleared by analyst" },
              ].map((row) => {
                const max = Math.max(1, summary?.matches ?? 1);
                return (
                  <div key={row.label}>
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="text-[10.5px] text-ink">{row.label}</span>
                      <span className="tnum font-mono text-[9.5px] text-dim">{row.value}</span>
                    </div>
                    <div className="mt-1"><MiniBar value={(row.value / max) * 100} color={row.color} /></div>
                    <p className="mt-0.5 text-[8.5px] text-dim">{row.hint}</p>
                  </div>
                );
              })}
            </div>
          </div>
          <div className="border-t border-line px-4 py-2 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{summary?.note}</div>
        </Panel>

        <Panel>
          <PanelHead title="Exposed by asset category" kicker="Validated matches only" />
          {summaryQuery.isLoading ? (
            <LoadingBlock rows={4} label="Loading exposure summary" />
          ) : !summary?.by_category?.length ? (
            <EmptyState title="No validated exposure yet" detail="Run an exposure scan after registering assets with software versions." icon={<GitCompareArrows size={18} />} />
          ) : (
            <div className="space-y-2.5 p-4">
              {summary.by_category.map((entry: any) => {
                const max = Math.max(1, ...summary.by_category.map((item: any) => item.value));
                return (
                  <div key={entry.name}>
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="text-[10.5px] text-ink">{entry.name}</span>
                      <span className="tnum font-mono text-[9.5px] text-dim">{entry.value}</span>
                    </div>
                    <div className="mt-1"><MiniBar value={(entry.value / max) * 100} color="#ff963d" /></div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
      </div>

      <Panel className="mb-4">
        <div className="grid gap-3 p-3.5 sm:grid-cols-2 lg:grid-cols-[minmax(230px,1.5fr)_repeat(3,minmax(140px,0.8fr))]">
          <div>
            <span className="field-label">Search matches</span>
            <SearchField value={q} onChange={setQ} placeholder="Asset, CVE, software, reason…" />
          </div>
          <FilterSelect
            label="Match status"
            value={status}
            onChange={setStatus}
            options={[{ value: "all", label: `Any status (${fmtNumber(data?.total)})` }, ...statusFacets.map((entry) => ({ value: entry.name, label: `${titleCase(entry.name)} (${entry.count})` }))]}
          />
          <FilterSelect
            label="Asset category"
            value={category}
            onChange={setCategory}
            options={[{ value: "all", label: "All categories" }, ...categoryFacets.map((entry) => ({ value: entry.name, label: `${entry.name} (${entry.count})` }))]}
          />
          <FilterSelect
            label="Minimum CVSS"
            value={minCvss}
            onChange={setMinCvss}
            options={[
              { value: "all", label: "Any CVSS" },
              { value: "7", label: "≥ 7.0 high" },
              { value: "9", label: "≥ 9.0 critical" },
            ]}
          />
        </div>
      </Panel>

      <Panel>
        {listQuery.isError ? (
          <ErrorState message={(listQuery.error as any)?.message} retry={() => listQuery.refetch()} />
        ) : listQuery.isLoading ? (
          <LoadingBlock rows={9} label="Loading exposure matches" />
        ) : !rows.length ? (
          <EmptyState
            title="No exposure matches in this view"
            detail="A missing match is not proof that an asset is unaffected. Confirm inventory software versions and run a scan before drawing that conclusion."
            icon={<GitCompareArrows size={19} />}
            action={can("analyst") ? <button className="btn btn-primary btn-sm" onClick={() => scan.mutate()} disabled={scan.isPending}>Run exposure scan</button> : undefined}
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-shell">
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th>Vulnerability</th>
                    <th>Match state</th>
                    <th className="hidden lg:table-cell">Match basis</th>
                    <th className="hidden md:table-cell">Evidence</th>
                    <th>Detected</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr key={row.id} onClick={() => openMatch(row)} className={focus === String(row.id) ? "bg-ion/[0.05]" : undefined}>
                      <td className="max-w-[280px]">
                        <div className="flex items-start gap-2">
                          <span className="mt-0.5 shrink-0 font-mono text-[8.5px] text-dim">{row.asset.ref}</span>
                          <div className="min-w-0">
                            <div className="truncate text-[12px] text-ink">{row.asset.name}</div>
                            <div className="mt-0.5 truncate font-mono text-[8px] uppercase tracking-[0.06em] text-dim">
                              {row.asset.software} {row.asset.software_version} · {titleCase(row.asset.exposure)}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="max-w-[300px]">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-[10px] text-info">{row.vulnerability.cve_id}</span>
                        </div>
                        <div className="mt-0.5 truncate text-[10.5px] text-mist">{row.vulnerability.title}</div>
                      </td>
                      <td>
                        <div className="flex flex-col gap-1">
                          <StatusBadge status={row.status} />
                          <span className="font-mono text-[8px] uppercase tracking-[0.08em] text-dim">confidence {Math.round(row.confidence || 0)}%</span>
                        </div>
                      </td>
                      <td className="hidden lg:table-cell max-w-[300px]">
                        <p className="line-clamp-2 text-[10.5px] leading-relaxed text-mist">{row.reason}</p>
                      </td>
                      <td className="hidden md:table-cell">
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={row.vulnerability.severity} />
                          <span className="font-mono text-[9px] text-dim">CVSS {row.vulnerability.cvss ?? "—"}</span>
                          {row.vulnerability.known_exploited && <span className="font-mono text-[8px] uppercase text-high">KEV</span>}
                        </div>
                      </td>
                      <td><span className="font-mono text-[9px] text-dim">{relTime(row.created_at)}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={data!.page} pages={data!.pages} total={data!.total} onPage={setPage} />
          </>
        )}
      </Panel>

      <Drawer
        open={Boolean(focus && selected)}
        onClose={closeMatch}
        width="max-w-[680px]"
        title={
          selected ? (
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge status={selected.status} />
              <span className="font-mono text-[12px] text-info">{selected.vulnerability.cve_id}</span>
              <span className="text-[13px] text-ink">on {selected.asset.name}</span>
            </div>
          ) : (
            <span>Verification</span>
          )
        }
        subtitle={selected && <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">match #{selected.id} · detected {relTime(selected.created_at)}</span>}
        footer={
          can("analyst") && selected ? (
            <>
              <button className="btn btn-ghost btn-sm" onClick={() => { setVerdict("not_affected"); updateMatch.mutate(); }} disabled={updateMatch.isPending}>
                <CircleSlash size={12} /> Mark not affected
              </button>
              <button className="btn btn-primary btn-sm" onClick={() => updateMatch.mutate()} disabled={updateMatch.isPending}>
                <BadgeCheck size={12} /> {updateMatch.isPending ? "Saving…" : "Record verification"}
              </button>
            </>
          ) : (
            <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">Read-only — analysts verify exposure</span>
          )
        }
      >
        {selected && (
          <div>
            <div className="rounded-xl border border-line bg-shade/25 p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="panel-kicker">Match rationale</div>
                  <h2 className="mt-1 font-display text-[17px] font-semibold text-ink">{selected.vulnerability.title}</h2>
                </div>
                <div className="text-right">
                  <div className="tnum font-display text-[26px] font-semibold leading-none" style={{ color: riskColor((Number(selected.vulnerability.cvss ?? 0)) * 10) }}>
                    {selected.vulnerability.cvss ?? "—"}
                  </div>
                  <div className="mt-1 font-mono text-[8px] uppercase tracking-[0.1em] text-dim">CVSS</div>
                </div>
              </div>
              <p className="mt-3 text-[11.5px] leading-relaxed text-ink">{selected.reason}</p>
              <div className="mt-3">
                <div className="mb-1 flex items-center justify-between font-mono text-[8px] uppercase tracking-[0.08em] text-dim">
                  <span>Match confidence</span><span>{Math.round(selected.confidence || 0)}%</span>
                </div>
                <ProgressBar value={selected.confidence || 0} color={selected.confidence >= 80 ? "#42c98a" : selected.confidence >= 50 ? "#ffd166" : "#ff963d"} />
              </div>
            </div>

            <DrawerSection title="Asset on record" kicker="Inventory context">
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                <div>
                  <div className="font-mono text-[8px] text-dim">{selected.asset.ref}</div>
                  <Link to={`/app/assets?focus=${selected.asset.ref}`} className="text-[12px] text-ink hover:text-ion">{selected.asset.name}</Link>
                  <div className="mt-0.5 font-mono text-[8.5px] uppercase tracking-[0.06em] text-dim">
                    {selected.asset.category} · {selected.asset.software} {selected.asset.software_version} · {titleCase(selected.asset.exposure)}
                  </div>
                </div>
                <div className="text-right">
                  <div className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">criticality</div>
                  <div className="tnum font-display text-[18px] font-semibold text-ink">{selected.asset.criticality}/5</div>
                </div>
              </div>
            </DrawerSection>

            <DrawerSection title="Vulnerability evidence" kicker="Independent signals">
              <div className="grid gap-2 sm:grid-cols-3">
                <div className="rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                  <div className="panel-kicker">EPSS</div>
                  <div className="tnum mt-1 font-mono text-[16px] text-violet">{fmtPct(selected.vulnerability.epss, 1)}</div>
                </div>
                <div className="rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                  <div className="panel-kicker">Known exploited</div>
                  <div className={clsx("mt-1 font-mono text-[16px]", selected.vulnerability.known_exploited ? "text-high" : "text-dim")}>
                    {selected.vulnerability.known_exploited ? "YES" : "NO"}
                  </div>
                </div>
                <div className="rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                  <div className="panel-kicker">Published</div>
                  <div className="mt-1 text-[11px] text-mist">{relTime(selected.vulnerability.published_at)}</div>
                </div>
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                <Link to={`/app/vulnerabilities?focus=${selected.vulnerability.cve_id}`} className="btn btn-ghost btn-sm">Open advisory</Link>
                {selected.threat && <Link to={`/app/threats?focus=${selected.threat.ref}`} className="btn btn-ghost btn-sm">Linked threat {selected.threat.ref}</Link>}
              </div>
            </DrawerSection>

            {can("analyst") && (
              <DrawerSection title="Analyst verification" kicker="Recorded in the audit trail">
                <div className="grid gap-3">
                  <FieldLabel label="Verification verdict">
                    <select className="field" value={verdict} onChange={(event) => setVerdict(event.target.value)}>
                      {STATUS_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                    </select>
                  </FieldLabel>
                  <FieldLabel label="Verification note" hint="Cite configuration evidence, compensating controls or why the version does not apply.">
                    <textarea className="field" rows={4} value={note} onChange={(event) => setNote(event.target.value)} maxLength={1000} />
                  </FieldLabel>
                </div>
                <InlineNotice tone="med" className="mt-3">
                  Confirmation does not trigger automated blocking, exploitation or host changes. It changes the evidence state used in scoring and reporting.
                </InlineNotice>
              </DrawerSection>
            )}

            <DrawerSection title="Methodology" kicker="Why this row exists">
              <p className="text-[11px] leading-relaxed text-mist">{listQuery.data?.methodology}</p>
            </DrawerSection>
          </div>
        )}
      </Drawer>
    </>
  );
}
