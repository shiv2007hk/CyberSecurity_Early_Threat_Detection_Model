import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  CalendarRange,
  Check,
  ChevronRight,
  ClipboardCheck,
  Download,
  FileText,
  Printer,
  ShieldCheck,
  Stamp,
} from "lucide-react";
import clsx from "clsx";
import { api, downloadFile, qs } from "../../lib/api";
import { fmtDate, fmtNumber, relTime, titleCase } from "../../lib/format";
import {
  CopyButton,
  ErrorState,
  LoadingBlock,
  PageHeader,
  Panel,
  PanelHead,
  RangeTabs,
  StatusBadge,
  useToast,
} from "../../components/ui";

type ReportType = {
  kind: string;
  title: string;
  default_range: string;
  range_label: string;
  description: string;
  formats: string[];
};

type Section = {
  id: string;
  title: string;
  paragraphs: string[];
  items: Array<Record<string, any>>;
  columns: string[];
  rows: Array<Array<any>>;
};

export default function Reports() {
  const { push } = useToast();
  const params = useParams();
  const navigate = useNavigate();
  const [range, setRange] = useState<string>("");

  const typesQuery = useQuery({
    queryKey: ["report-types"],
    queryFn: () => api<{ types: ReportType[]; disclaimer: string }>("/reports"),
  });

  const types = typesQuery.data?.types || [];
  const kind = params.kind || "weekly";
  const activeType = useMemo(() => types.find((entry) => entry.kind === kind), [types, kind]);

  useEffect(() => {
    if (activeType && (!range || range === "")) setRange(activeType.default_range);
  }, [activeType, range]);

  const reportQuery = useQuery({
    queryKey: ["report", kind, range],
    queryFn: () => api<any>(`/reports/${kind}${qs({ range: range || undefined })}`),
    enabled: Boolean(kind) && (range !== "" || Boolean(activeType)),
  });

  const report = reportQuery.data;

  const selectType = (type: ReportType) => {
    setRange(type.default_range);
    navigate(`/app/reports/${type.kind}`);
  };

  const download = async () => {
    try {
      await downloadFile(`/reports/${kind}/export.csv${qs({ range })}`, `cyberguard-${kind}.csv`);
      push("success", "Report dataset downloaded as CSV.");
    } catch (error: any) {
      push("error", error.message || "Report export failed.");
    }
  };

  return (
    <>
      <PageHeader
        title="Intelligence reports"
        description="Structured, provenance-aware reporting for daily operations, weekly trends, critical dossiers, exposure and asset risk. Generated from stored records at request time — printable, citeable and exportable."
        aside={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span><span className="text-ink">{types.length}</span> report templates</span>
            <span>·</span>
            <span>view · csv · print</span>
            {report && <><span>·</span><span>generated {relTime(report.generated_at)}</span></>}
          </div>
        }
        actions={
          <>
            {activeType && (
              <RangeTabs
                value={range}
                onChange={setRange}
                options={[
                  { value: "24h", label: "24H" },
                  { value: "7d", label: "7D" },
                  { value: "30d", label: "30D" },
                  { value: "90d", label: "90D" },
                ]}
              />
            )}
            <button className="btn btn-ghost btn-sm" onClick={download} disabled={!report}>
              <Download size={13} /> CSV
            </button>
            <button className="btn btn-primary btn-sm" onClick={() => window.print()} disabled={!report}>
              <Printer size={13} /> Print / PDF
            </button>
          </>
        }
      />

      <div className="grid gap-4 xl:grid-cols-[292px_minmax(0,1fr)]">
        <aside className="no-print xl:sticky xl:top-[86px] xl:self-start">
          <div className="panel overflow-hidden">
            <div className="panel-head">
              <div>
                <div className="panel-kicker">Template library</div>
                <div className="panel-title">Select a report</div>
              </div>
            </div>
            <div className="divide-y divide-veil/[0.05]">
              {typesQuery.isLoading ? (
                <LoadingBlock rows={4} label="Loading templates" />
              ) : (
                types.map((type) => {
                  const active = type.kind === kind;
                  return (
                    <button
                      key={type.kind}
                      onClick={() => selectType(type)}
                      className={clsx(
                        "block w-full px-4 py-3 text-left transition-colors",
                        active ? "bg-ion/[0.07]" : "hover:bg-veil/[0.025]",
                      )}
                      aria-current={active ? "page" : undefined}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className={clsx("grid h-6 w-6 place-items-center rounded-md border", active ? "border-ion/35 bg-ion/10 text-ion" : "border-line bg-veil/[0.02] text-dim")}>
                            <FileText size={12} />
                          </span>
                          <span className={clsx("text-[11.5px] font-medium", active ? "text-ink" : "text-ink")}>{type.title.replace(" Report", "")}</span>
                        </div>
                        {active && <Check size={12} className="mt-1 shrink-0 text-ion" />}
                      </div>
                      <p className="mt-1.5 line-clamp-2 text-[10px] leading-relaxed text-dim">{type.description}</p>
                      <div className="mt-1.5 flex items-center gap-2 font-mono text-[8px] uppercase tracking-[0.1em] text-dim">
                        <CalendarRange size={9} /> {type.range_label}
                      </div>
                    </button>
                  );
                })
              )}
            </div>
            <div className="border-t border-line px-4 py-3 text-[9.5px] leading-relaxed text-dim">
              {typesQuery.data?.disclaimer}
            </div>
          </div>
        </aside>

        <div className="min-w-0">
          {reportQuery.isError ? (
            <Panel><ErrorState message={(reportQuery.error as any)?.message} retry={() => reportQuery.refetch()} /></Panel>
          ) : reportQuery.isLoading || !report ? (
            <Panel><LoadingBlock rows={10} label="Compiling report" /></Panel>
          ) : (
            <article className="print-sheet">
              <div className="panel mb-4 overflow-hidden">
                <div className="relative border-b border-line px-6 py-5">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="min-w-0">
                      <div className="panel-kicker">CyberGuard AI · Intelligence product</div>
                      <h2 className="mt-1.5 font-display text-[clamp(1.45rem,2vw,1.9rem)] font-semibold leading-tight text-ink">{report.title}</h2>
                      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
                        <span>{fmtDate(report.range?.start)} → {fmtDate(report.range?.end)}</span>
                        <span>·</span>
                        <span>{report.generated_by?.name} ({report.generated_by?.role})</span>
                        <span>·</span>
                        <span>generated {relTime(report.generated_at)}</span>
                      </div>
                    </div>
                    <div className="no-print flex flex-wrap items-center gap-1.5">
                      <StatusBadge status="draft" />
                      <CopyButton value={`${window.location.origin}/app/reports/${report.kind}`} label="Copy link" />
                    </div>
                  </div>
                  <div className="mt-4 rounded-lg border border-med/20 bg-med/[0.035] px-3.5 py-2.5">
                    <div className="flex items-start gap-2">
                      <Stamp size={13} className="mt-0.5 shrink-0 text-med" />
                      <p className="text-[10px] leading-relaxed text-ink">{report.classification}</p>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-2 divide-x divide-veil/[0.05] border-b border-line sm:grid-cols-3 lg:grid-cols-6">
                  {[
                    ["Threats", report.metrics?.threats],
                    ["Vulnerabilities", report.metrics?.vulnerabilities],
                    ["Alerts", report.metrics?.alerts],
                    ["Exposed assets", report.metrics?.exposed_assets],
                    ["Known exploited", report.metrics?.known_exploited],
                    ["Open actions", report.metrics?.open_recommendations],
                  ].map(([label, value], index) => (
                    <div key={label as string} className={clsx("px-4 py-3", index >= 3 && "max-lg:border-t max-lg:border-veil/[0.05]")}>
                      <div className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">{label}</div>
                      <div className="tnum mt-1 font-display text-[20px] font-semibold text-ink">{fmtNumber(value as number)}</div>
                    </div>
                  ))}
                </div>

                <div className="px-6 py-5">
                  <div className="panel-kicker mb-2">Executive summary</div>
                  <div className="space-y-2">
                    {(report.executive_summary || []).map((paragraph: string, index: number) => (
                      <p key={index} className={clsx("text-[12px] leading-relaxed", index === 0 ? "text-ink" : "text-mist")}>{paragraph}</p>
                    ))}
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                {(report.sections || []).map((section: Section) => (
                  <Panel key={section.id} className="scroll-mt-24" >
                    <PanelHead title={section.title} kicker={`Section · ${section.id}`} right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">traceable</span>} />
                    <div className="px-4 pb-4">
                      {section.paragraphs?.map((paragraph, index) => (
                        <p key={index} className="mb-2 text-[11.5px] leading-relaxed text-mist last:mb-0">{paragraph}</p>
                      ))}

                      {section.id === "metrics" && section.items?.length > 0 && (
                        <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                          {section.items.map((item) => (
                            <div key={item.label} className="rounded-md border border-line bg-shade/20 px-3 py-2">
                              <div className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{item.label}</div>
                              <div className="tnum mt-1 font-display text-[17px] text-ink">{item.value}</div>
                            </div>
                          ))}
                        </div>
                      )}

                      {section.id !== "metrics" && section.items?.length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-1.5">
                          {section.items.slice(0, 16).map((item) => (
                            <span key={item.name} className="chip">
                              {titleCase(String(item.name))}
                              {item.count !== undefined && <span className="ml-1 font-mono text-[8.5px] text-dim">{item.count}</span>}
                              {item.avg_risk !== undefined && <span className="ml-1 font-mono text-[8.5px] text-dim">· risk {Number(item.avg_risk).toFixed(1)}</span>}
                            </span>
                          ))}
                        </div>
                      )}

                      {section.columns?.length > 0 && (
                        <div className="table-shell mt-3 overflow-x-auto border-x-0 border-b-0">
                          {section.rows?.length ? (
                            <table className="w-full">
                              <thead>
                                <tr>
                                  {section.columns.map((column) => <th key={column}>{column}</th>)}
                                </tr>
                              </thead>
                              <tbody>
                                {section.rows.map((row, rowIndex) => (
                                  <tr key={rowIndex}>
                                    {row.map((cell, cellIndex) => (
                                      <td key={cellIndex} className={clsx("text-[10.5px]", cellIndex === 0 ? "font-mono text-ink" : "text-mist")}>
                                        {typeof cell === "object" ? JSON.stringify(cell) : String(cell ?? "—")}
                                      </td>
                                    ))}
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          ) : (
                            <div className="py-8 text-center text-[11px] text-dim">No rows for this section in the selected window.</div>
                          )}
                        </div>
                      )}
                    </div>
                  </Panel>
                ))}
              </div>

              <div className="panel mt-4 px-5 py-4">
                <div className="flex items-start gap-2.5">
                  <ClipboardCheck size={15} className="mt-0.5 shrink-0 text-low" />
                  <div>
                    <div className="panel-kicker mb-1">Provenance</div>
                    <p className="text-[10.5px] leading-relaxed text-mist">{report.provenance_note}</p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {(report.sources || []).map((source: any) => (
                        <span key={source.key} className="chip">
                          {source.name}
                          <span className="ml-1 font-mono text-[8px] text-dim">{Math.round(source.reliability || 0)}%</span>
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-line pt-3 font-mono text-[8px] uppercase tracking-[0.12em] text-dim">
                  <span className="inline-flex items-center gap-1"><ShieldCheck size={10} /> Generated from stored platform records</span>
                  <span className="no-print inline-flex items-center gap-1">CSV export available <ChevronRight size={10} /></span>
                </div>
              </div>
            </article>
          )}
        </div>
      </div>
    </>
  );
}
