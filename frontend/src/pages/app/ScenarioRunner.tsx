import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowRight,
  Beaker,
  CheckCircle2,
  ChevronRight,
  CircleDashed,
  Database,
  FlaskConical,
  History,
  Info,
  Loader2,
  Play,
  ShieldAlert,
  Sparkles,
  TriangleAlert,
} from "lucide-react";
import clsx from "clsx";
import { api } from "../../lib/api";
import { fmtNumber, relTime } from "../../lib/format";
import { useAuth } from "../../context/AuthContext";
import {
  InlineNotice,
  Kpi,
  LoadingBlock,
  PageHeader,
  Panel,
  PanelHead,
  ReadOnlyHint,
  useToast,
} from "../../components/ui";
import { SectionLabel } from "./shared";

const STEP_TONE: Record<string, { color: string; icon: ReactNode }> = {
  complete: { color: "text-low border-low/30 bg-low/[0.06]", icon: <CheckCircle2 size={12} /> },
  skipped: { color: "text-dim border-veil/10 bg-veil/[0.02]", icon: <CircleDashed size={12} /> },
  "no-alert": { color: "text-med border-med/30 bg-med/[0.06]", icon: <TriangleAlert size={12} /> },
  failed: { color: "text-crit border-crit/30 bg-crit/[0.06]", icon: <ShieldAlert size={12} /> },
};

const SCENARIO_ICON = [FlaskConical, Sparkles, ShieldAlert];

export default function ScenarioRunner() {
  const { can, user } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const [result, setResult] = useState<any>(null);
  const [runningKey, setRunningKey] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["threat-scenarios"],
    queryFn: () => api<any>("/scenarios"),
  });

  const run = useMutation({
    mutationFn: (key: string) => api<any>(`/scenarios/${key}/run`, { method: "POST" }),
    onMutate: (key) => setRunningKey(key),
    onSuccess: (data) => {
      setResult(data);
      push("success", "Scenario completed. New records are tagged to this scenario.");
      queryClient.invalidateQueries({ queryKey: ["threat-scenarios"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["analytics"] });
      queryClient.invalidateQueries({ queryKey: ["threats"] });
      queryClient.invalidateQueries({ queryKey: ["vulnerabilities"] });
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      queryClient.invalidateQueries({ queryKey: ["recommendations"] });
    },
    onError: (error: any) => push("error", error.message || "The scenario could not be completed."),
    onSettled: () => setRunningKey(null),
  });

  const scenarios = query.data?.scenarios || [];
  const mode = query.data?.record_counts;
  const recent = query.data?.recent_runs || [];

  return (
    <>
      <PageHeader
        title="Threat scenarios"
        description="Deterministic exercises that drive the full pipeline — ingestion, validation, correlation, scoring, early warning and recommendation — against the platform database. Each run writes records tagged to its scenario. Nothing here touches infrastructure."
        aside={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span>writes tagged records</span>
            <span>·</span>
            <span>no external calls</span>
            <span>·</span>
            <span>no containment actions</span>
            {user && <><span>·</span><ReadOnlyHint role={user.role} /></>}
          </div>
        }
      />

      <div className="mb-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Threat records" value={fmtNumber(mode?.threat_records)} detail="Intelligence in the database" icon={<Database size={15} />} tone="violet" />
        <Kpi label="Vulnerability records" value={fmtNumber(mode?.vulnerability_records)} detail="Advisories and CVE entries" icon={<Beaker size={15} />} tone="ion" />
        <Kpi label="Early warnings" value={fmtNumber(mode?.alert_records)} detail="Detections on record" icon={<ShieldAlert size={15} />} tone="med" />
        <Kpi label="Monitored assets" value={fmtNumber(mode?.asset_records)} detail="Inventory under assessment" icon={<FlaskConical size={15} />} tone="low" />
      </div>

      {query.isError ? (
        <Panel><div className="p-6 text-[11.5px] text-crit">Scenario catalogue unavailable. {(query.error as any)?.message}</div></Panel>
      ) : query.isLoading ? (
        <Panel><LoadingBlock rows={5} label="Loading scenarios" /></Panel>
      ) : (
        <div className="mb-4 grid gap-3 xl:grid-cols-3">
          {scenarios.map((scenario: any, index: number) => {
            const Icon = SCENARIO_ICON[index % SCENARIO_ICON.length];
            const isRunning = runningKey === scenario.key;
            return (
              <div key={scenario.key} className="panel flex flex-col">
                <div className="flex items-start justify-between gap-3 border-b border-line px-4 py-3">
                  <div className="flex items-center gap-2.5">
                    <span className="grid h-9 w-9 place-items-center rounded-lg border border-violet/25 bg-violet/[0.06] text-violet"><Icon size={16} /></span>
                    <div>
                      <div className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">Scenario {String(index + 1).padStart(2, "0")}</div>
                    </div>
                  </div>
                </div>
                <div className="flex-1 px-4 py-3">
                  <h3 className="text-[12px] font-semibold leading-snug text-ink">{scenario.title}</h3>
                  <p className="mt-2 text-[10.5px] leading-relaxed text-mist">{scenario.description}</p>
                </div>
                <div className="flex items-center justify-between gap-2 border-t border-line px-4 py-2.5">
                  <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{scenario.key}</span>
                  {can("analyst") ? (
                    <button className="btn btn-primary btn-sm" onClick={() => run.mutate(scenario.key)} disabled={Boolean(runningKey)}>
                      {isRunning ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />} Run scenario
                    </button>
                  ) : (
                    <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">analyst only</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {result && (
        <Panel className="mb-4">
          <PanelHead
            title={result.title}
            kicker="Scenario output"
            right={<span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{relTime(result.ran_at)}</span>}
          />
          <div className="grid gap-0 xl:grid-cols-[1.4fr_1fr]">
            <div className="border-b border-line xl:border-b-0 xl:border-r">
              <div className="px-4 py-3">
                <SectionLabel right={<span className="chip text-low">{result.steps?.filter((step: any) => step.status === "complete").length}/{result.steps?.length} complete</span>}>Pipeline steps</SectionLabel>
                <ol className="space-y-2">
                  {(result.steps || []).map((step: any, index: number) => {
                    const tone = STEP_TONE[step.status] || STEP_TONE.skipped;
                    return (
                      <li key={step.key || index} className="relative flex gap-2.5 rounded-md border border-line bg-shade/20 px-3 py-2.5">
                        <span className={clsx("mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded border", tone.color)}>{tone.icon}</span>
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-[10.5px] font-medium text-ink">{step.label}</span>
                            <span className={clsx("chip", step.status === "complete" ? "text-low" : step.status === "no-alert" ? "text-med" : "text-dim")}>{step.status}</span>
                          </div>
                          <p className="mt-0.5 text-[10px] leading-relaxed text-mist">{step.detail}</p>
                          {step.data && Object.keys(step.data).length > 0 && (
                            <details className="group mt-1.5">
                              <summary className="flex cursor-pointer items-center gap-1 font-mono text-[8px] uppercase tracking-[0.1em] text-dim marker:content-none">
                                <ChevronRight size={9} className="transition-transform group-open:rotate-90" /> step data
                              </summary>
                              <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded border border-line bg-shade/30 p-2 font-mono text-[8.5px] leading-relaxed text-dim">
                                {JSON.stringify(step.data, null, 2)}
                              </pre>
                            </details>
                          )}
                        </div>
                      </li>
                    );
                  })}
                </ol>
              </div>
            </div>
            <div className="px-4 py-3">
              <SectionLabel>Artifacts</SectionLabel>
              <div className="space-y-1.5">
                {Object.entries(result.artifacts || {}).map(([key, value]) => {
                  if (value === null || value === undefined) return null;
                  if (Array.isArray(value)) {
                    return (
                      <div key={key} className="rounded-md border border-line bg-shade/20 px-2.5 py-1.5">
                        <div className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{key.replace(/_/g, " ")}</div>
                        <div className="mt-0.5 flex flex-wrap gap-1">
                          {value.map((entry, index) => (
                            <Link key={`${entry}-${index}`} to={`/app/assets?focus=${entry}`} className="chip text-ion hover:border-ion/40">{String(entry)}</Link>
                          ))}
                        </div>
                      </div>
                    );
                  }
                  const link = artifactLink(key, String(value));
                  return (
                    <div key={key} className="flex items-center justify-between gap-2 rounded-md border border-line bg-shade/20 px-2.5 py-1.5">
                      <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{key.replace(/_/g, " ")}</span>
                      {link ? <Link to={link} className="font-mono text-[9.5px] text-ion hover:text-crystal">{String(value)}</Link> : <span className="font-mono text-[9.5px] text-ink">{String(value)}</span>}
                    </div>
                  );
                })}
              </div>
              <div className="mt-3 space-y-1.5 border-t border-line pt-3">
                <div className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">Caveats</div>
                {(result.caveats || []).map((caveat: string, index: number) => (
                  <p key={index} className="flex items-start gap-1.5 text-[9.5px] leading-relaxed text-mist"><Info size={9} className="mt-1 shrink-0 text-med" /> {caveat}</p>
                ))}
              </div>
            </div>
          </div>
        </Panel>
      )}

      <div className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
        <Panel>
          <PanelHead title="Recent scenario runs" kicker="Audit-confirmed" right={<History size={14} className="text-dim" />} />
          {recent.length ? (
            <div className="divide-y divide-veil/[0.05]">
              {recent.map((entry: any, index: number) => (
                <div key={index} className="flex items-start gap-3 px-4 py-2.5">
                  <span className="mt-0.5 grid h-6 w-6 place-items-center rounded border border-violet/25 bg-violet/[0.05] text-violet"><Beaker size={11} /></span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[9px] uppercase tracking-[0.1em] text-mist">{entry.scenario}</span>
                      <span className="font-mono text-[8px] text-dim">{relTime(entry.at)}</span>
                    </div>
                    <div className="mt-0.5 truncate text-[10px] text-dim">{entry.detail}</div>
                  </div>
                  <span className="shrink-0 font-mono text-[8px] text-dim">{entry.by}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-12 text-center text-[11px] text-dim">No scenario has been run yet.</div>
          )}
        </Panel>

        <Panel>
          <PanelHead title="What this exercises" kicker="Pipeline coverage" right={<Sparkles size={14} className="text-dim" />} />
          <div className="space-y-2.5 p-4">
            {[
              ["Ingestion & provenance", "Each record stores its source, retrieval timestamp and scenario tag."],
              ["Product/version validation", "Exposure requires a satisfied version range, not a loose text match."],
              ["Explainable risk", "The weighted model returns factor contributions, not a black-box score."],
              ["Early warning", "Rules attach evidence and distinguish observation from prediction."],
              ["Recommendation", "Advisory actions are queued for human approval only."],
            ].map(([title, detail]) => (
              <div key={title} className="flex items-start gap-2.5">
                <CheckCircle2 size={12} className="mt-0.5 shrink-0 text-low" />
                <div>
                  <div className="text-[10.5px] text-ink">{title}</div>
                  <p className="mt-0.5 text-[9.5px] leading-relaxed text-dim">{detail}</p>
                </div>
              </div>
            ))}
            <Link to="/app/analytics" className="mt-1 inline-flex items-center gap-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-ion hover:text-crystal">
              Inspect resulting analytics <ArrowRight size={10} />
            </Link>
          </div>
        </Panel>
      </div>
    </>
  );
}

function artifactLink(key: string, value: string) {
  if (key === "vulnerability" && value.startsWith("CVE")) return `/app/vulnerabilities?focus=${value}`;
  if (key === "alert_ref") return `/app/alerts?focus=${value}`;
  if (key === "recommendation_ref") return `/app/recommendations?focus=${value}`;
  if (key === "threat_ref") return `/app/threats?focus=${value}`;
  return null;
}
