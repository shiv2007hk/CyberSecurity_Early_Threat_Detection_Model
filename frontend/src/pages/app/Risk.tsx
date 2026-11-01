import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BarChart3,
  Calculator,
  Gauge,
  MessageSquareWarning,
  RefreshCw,
  Scale,
  Settings2,
  SlidersHorizontal,
  Sparkles,
} from "lucide-react";
import clsx from "clsx";
import { api, qs, type Assessment, type Paginated } from "../../lib/api";
import { fmtDate, fmtNumber, riskColor, titleCase } from "../../lib/format";
import { useAuth } from "../../context/AuthContext";
import {
  Drawer,
  EmptyState,
  ErrorState,
  InlineNotice,
  Kpi,
  LoadingBlock,
  Modal,
  PageHeader,
  Pagination,
  Panel,
  PanelHead,
  ProgressBar,
  RangeTabs,
  RiskMeter,
  SeverityBadge,
  StatusBadge,
  useToast,
} from "../../components/ui";
import { DistributionDonut, Sparkline } from "../../components/charts";
import { PriorityMatrix, RISK_HEX, ScatterPlot, Waterfall } from "../../components/analytics-charts";
import { DrawerSection, EvidenceList, FieldLabel, FilterSelect, ScoreChip, SectionLabel } from "./shared";

const FACTOR_LABELS: Record<string, string> = {
  severity: "Severity",
  exploitability: "Exploitability",
  exposure: "Exposure",
  asset_criticality: "Asset criticality",
  evidence_strength: "Evidence strength",
};

const FACTOR_SHORT: Record<string, string> = {
  severity: "Severity",
  exploitability: "Exploitability",
  exposure: "Exposure",
  asset_criticality: "Criticality",
  evidence_strength: "Evidence",
};

const VERDICTS = [
  { value: "agree", label: "Agree with score" },
  { value: "needs_review", label: "Needs review" },
  { value: "incorrect", label: "Incorrect inputs" },
];

const EXPLOITATION_ROWS: Array<[string, string]> = [
  ["confirmed-known-exploited", "Confirmed exploited"],
  ["likely", "Likely"],
  ["possible", "Possible"],
  ["not-confirmed", "Not confirmed"],
];
const RISK_BANDS = ["Critical", "High", "Medium", "Low"];

/** Unlike the paged endpoints, which return a facet map, /risk/assessments returns a flat band list. */
type AssessmentPage = Paginated<Assessment> & { facets?: Array<{ name: string; count: number }> };

// Revisions written in the same rescoring pass share a minute, so the ledger shows seconds.
function revisionStamp(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return `${date.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" })} · ${date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })}`;
}

export default function Risk() {
  const { can } = useAuth();
  const { push } = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();

  const [category, setCategory] = useState("all");
  const [range, setRange] = useState("90d");
  const [page, setPage] = useState(1);
  const [configOpen, setConfigOpen] = useState(false);
  const [draftWeights, setDraftWeights] = useState<Record<string, number>>({});
  const [draftThresholds, setDraftThresholds] = useState<Record<string, number>>({});
  const [verdict, setVerdict] = useState("agree");
  const [feedbackNote, setFeedbackNote] = useState("");
  const [waterfallId, setWaterfallId] = useState<number | null>(null);
  const [matrixFilter, setMatrixFilter] = useState<{ status: string; band: string } | null>(null);
  const [hoveredThreat, setHoveredThreat] = useState<number | null>(null);

  const focus = searchParams.get("assessment");
  useEffect(() => setPage(1), [category, range]);
  useEffect(() => {
    setMatrixFilter(null);
    setHoveredThreat(null);
  }, [range]);

  const summaryQuery = useQuery({ queryKey: ["risk-summary"], queryFn: () => api<any>("/risk/summary") });
  const configQuery = useQuery({ queryKey: ["risk-config"], queryFn: () => api<any>("/risk/config") });
  const feedbackQuery = useQuery({ queryKey: ["risk-feedback"], queryFn: () => api<any>("/risk/feedback") });
  const assessmentsQuery = useQuery({
    queryKey: ["risk-assessments", { category, range, page }],
    queryFn: () => api<AssessmentPage>(`/risk/assessments${qs({ category, range, page, size: 20 })}`),
  });
  const detailQuery = useQuery({
    queryKey: ["risk-assessment", focus],
    queryFn: () => api<any>(`/risk/assessments/${focus}`),
    enabled: Boolean(focus),
  });
  const threatScatterQuery = useQuery({
    queryKey: ["risk-threat-scatter", range],
    queryFn: () => api<Paginated<any>>(`/threats${qs({ range, size: 100, sort_by: "risk_score", order: "desc" })}`),
  });
  const analyticsQuery = useQuery({
    queryKey: ["risk-assessments-analytics", range],
    queryFn: () => api<Paginated<Assessment>>(`/risk/assessments${qs({ range, size: 100 })}`),
  });

  const summary = summaryQuery.data;
  const config = configQuery.data;
  const detail = detailQuery.data;
  const assessment: Assessment | undefined = detail || assessmentsQuery.data?.items.find((item) => String(item.id) === focus);

  useEffect(() => {
    if (focus) {
      setVerdict("agree");
      setFeedbackNote("");
    }
  }, [focus]);

  useEffect(() => {
    if (config) {
      setDraftWeights({ ...config.weights });
      setDraftThresholds({ ...config.thresholds });
    }
  }, [config]);

  const closeDrawer = () =>
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete("assessment");
      return next;
    });

  const saveConfig = useMutation({
    mutationFn: () =>
      api("/risk/config", {
        method: "PUT",
        body: JSON.stringify({ weights: draftWeights, thresholds: draftThresholds }),
      }),
    onSuccess: (result: any) => {
      push("success", result.message || "Model configuration saved and records rescored.");
      setConfigOpen(false);
      queryClient.invalidateQueries({ queryKey: ["risk-config"] });
      queryClient.invalidateQueries({ queryKey: ["risk-summary"] });
      queryClient.invalidateQueries({ queryKey: ["risk-assessments"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["threats"] });
      queryClient.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (error: any) => push("error", error.message || "The model configuration could not be saved."),
  });

  const recompute = useMutation({
    mutationFn: () => api<any>("/risk/recompute", { method: "POST" }),
    onSuccess: (result) => {
      push("success", `Rescored ${result.threats_updated} threats and ${result.assessments_updated} assessments.`);
      queryClient.invalidateQueries({ queryKey: ["risk-summary"] });
      queryClient.invalidateQueries({ queryKey: ["risk-assessments"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (error: any) => push("error", error.message || "Recompute failed."),
  });

  const submitFeedback = useMutation({
    mutationFn: () =>
      api("/risk/feedback", {
        method: "POST",
        body: JSON.stringify({ assessment_id: Number(focus), verdict, note: feedbackNote }),
      }),
    onSuccess: () => {
      push("success", "Feedback recorded for model review. Scores only change through administrator configuration.");
      setFeedbackNote("");
      queryClient.invalidateQueries({ queryKey: ["risk-feedback"] });
    },
    onError: (error: any) => push("error", error.message || "Feedback could not be recorded."),
  });

  const weightTotal = useMemo(
    () => Object.values(draftWeights).reduce((sum, value) => sum + (Number(value) || 0), 0),
    [draftWeights],
  );

  const categories: Array<{ name: string; count: number }> = assessmentsQuery.data?.facets || [];
  const assessments = assessmentsQuery.data?.items || [];
  const feedback: any[] = feedbackQuery.data?.items || [];
  const distribution = (summary?.distribution || []).map((entry: any) => ({ name: entry.name, value: entry.value }));

  const analyticsAssessments = analyticsQuery.data?.items || [];
  const threatPool = threatScatterQuery.data?.items || [];

  const matchesMatrix = (status?: string, band?: string) =>
    !matrixFilter || (status === matrixFilter.status && band === matrixFilter.band);

  // The matrix always counts the full window; the other panels narrow to the active cell.
  const scopedAssessments = useMemo(
    () => analyticsAssessments.filter((item) => matchesMatrix(item.exploitation_status, item.risk_category)),
    [analyticsAssessments, matrixFilter],
  );
  const scopedThreats = useMemo(
    () => threatPool.filter((threat: any) => matchesMatrix(threat.exploitation_status, threat.risk_category)),
    [threatPool, matrixFilter],
  );

  const sourceLabel = (threat: any) =>
    `${threat?.source || "source not recorded"}`;

  const epssPoints = useMemo(
    () =>
      scopedThreats
        .filter((threat: any) => threat.cvss_score !== null && threat.cvss_score !== undefined && threat.epss_score !== null && threat.epss_score !== undefined)
        .map((threat: any) => ({
          id: `t${threat.id}`,
          group: threat.id,
          x: Number(threat.cvss_score),
          y: Math.round(Number(threat.epss_score) * 1000) / 10,
          size: 2.6 + (Number(threat.risk_score ?? 0) / 100) * 5.4,
          color: RISK_HEX[titleCase(threat.severity)] || "#49b8ff",
          label: threat.cve_id || threat.ref,
          lines: [
            `${threat.cve_id || "No CVE"} · ${threat.ref}`,
            `CVSS ${Number(threat.cvss_score).toFixed(1)} · EPSS ${(Number(threat.epss_score) * 100).toFixed(1)}%`,
            `Risk ${Number(threat.risk_score ?? 0).toFixed(0)} · ${titleCase(threat.severity)}${threat.known_exploited ? " · known exploited" : ""}`,
            sourceLabel(threat),
          ],
        })),
    [scopedThreats],
  );

  const exposurePoints = useMemo(
    () =>
      scopedAssessments.map((item) => ({
        id: `a${item.id}`,
        group: (item as any).threat_id,
        x: Number(item.exposure ?? 0),
        y: Number(item.risk_score ?? 0),
        size: 2.6 + (Number(item.asset_criticality ?? 0) / 10) * 6,
        color: riskColor(item.risk_score),
        label: item.ref,
        lines: [
          `${(item as any).threat?.cve_id || "No CVE"} · ${item.ref}`,
          `${item.asset?.ref || "Generic profile"} · criticality ${Number(item.asset_criticality ?? 0).toFixed(0)}/10`,
          `Risk ${Number(item.risk_score ?? 0).toFixed(0)} · ${item.risk_category} · confidence ${Math.round(Number(item.evidence_confidence ?? 0))}%`,
          sourceLabel((item as any).threat),
        ],
      })),
    [scopedAssessments],
  );

  const exploitationMatrix = useMemo(() => {
    const values = EXPLOITATION_ROWS.map(([key]) =>
      RISK_BANDS.map((band) => analyticsAssessments.filter((item) => item.exploitation_status === key && item.risk_category === band).length),
    );
    return { rows: EXPLOITATION_ROWS.map(([, label]) => label), cols: RISK_BANDS, values };
  }, [analyticsAssessments]);

  const matrixSelected = useMemo(() => {
    if (!matrixFilter) return null;
    const row = EXPLOITATION_ROWS.findIndex(([key]) => key === matrixFilter.status);
    const col = RISK_BANDS.indexOf(matrixFilter.band);
    return row < 0 || col < 0 ? null : { row, col };
  }, [matrixFilter]);

  // Keep the chart-selected record in the dropdown even when it sits outside the top slice,
  // so the select and the scatter can never disagree about what is being inspected.
  const waterfallOptions = useMemo(() => {
    const sorted = [...scopedAssessments].sort((a, b) => Number(b.risk_score ?? 0) - Number(a.risk_score ?? 0)).slice(0, 14);
    const picked = scopedAssessments.find((item) => item.id === waterfallId);
    return picked && !sorted.some((item) => item.id === picked.id) ? [picked, ...sorted] : sorted;
  }, [scopedAssessments, waterfallId]);
  const waterfallAssessment = waterfallOptions.find((item) => item.id === waterfallId) || waterfallOptions[0];
  const waterfallItems = (waterfallAssessment?.factors || []).map((factor) => ({
    label: factor.label || FACTOR_LABELS[factor.key || ""] || titleCase(String(factor.key || "factor")),
    shortLabel: FACTOR_SHORT[factor.key || ""] || factor.label,
    value: Number(factor.contribution ?? 0),
    color: "#49b8ff",
    note: factor.note,
  }));

  const historyQuery = useQuery({
    queryKey: ["risk-history", assessment?.threat_id],
    queryFn: () => api<Paginated<Assessment>>(`/risk/assessments${qs({ threat: assessment?.threat_id, range: "all", size: 50 })}`),
    enabled: Boolean(focus && assessment?.threat_id),
  });

  // The API returns the strongest first; a trend has to read left to right in time.
  const scoreHistory = useMemo(
    () => [...(historyQuery.data?.items || [])].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()),
    [historyQuery.data],
  );
  const latestRevision = scoreHistory[scoreHistory.length - 1];
  const historyDelta = latestRevision && scoreHistory[0]
    ? Number(latestRevision.risk_score ?? 0) - Number(scoreHistory[0].risk_score ?? 0)
    : 0;

  const openAssessment = (id: number) => {
    setWaterfallId(id);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("assessment", String(id));
      return next;
    });
  };

  const openFromThreat = (threatId: number) => {
    const match = analyticsAssessments.find((item) => (item as any).threat_id === threatId);
    if (match) openAssessment(match.id);
    else navigate(`/app/threats?focus=${scopedThreats.find((threat: any) => threat.id === threatId)?.ref || ""}`);
  };

  const analyticsLoading = threatScatterQuery.isLoading || analyticsQuery.isLoading;

  return (
    <>
      <PageHeader
        title="AI risk assessment"
        kicker="Scoring · exposure · prioritisation"
        description="A deterministic, explainable model combines technical severity, exploitation evidence, asset exposure, business criticality and source corroboration. Scores prioritise attention; they are not probabilities of attack."
        aside={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span><span className="text-ink">{fmtNumber(summary?.assessments)}</span> assessments</span>
            <span><span className="text-ink">{fmtNumber(summary?.threats_scored)}</span> threats scored</span>
            <span>avg <span className="text-ink">{summary?.average_score ?? 0}</span>/100</span>
            <span>model <span className="text-ion">{summary?.config?.model_version || config?.model_version}</span></span>
          </div>
        }
        actions={
          <>
            <RangeTabs value={range} onChange={setRange} />
            {can("admin") && (
              <>
                <button className="btn btn-ghost btn-sm" onClick={() => setConfigOpen(true)}><Settings2 size={13} /> Model weights</button>
                <button className="btn btn-primary btn-sm" onClick={() => recompute.mutate()} disabled={recompute.isPending}>
                  <RefreshCw size={13} className={recompute.isPending ? "animate-spin" : undefined} /> {recompute.isPending ? "Rescoring…" : "Recompute all"}
                </button>
              </>
            )}
          </>
        }
      />

      <div className="mb-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Recorded assessments" value={fmtNumber(summary?.assessments)} detail="Each with a stored factor breakdown" icon={<Calculator size={15} />} tone="ion" />
        <Kpi label="Average composite risk" value={Number(summary?.average_score ?? 0).toFixed(1)} detail="Across all recorded assessments" icon={<Gauge size={15} />} tone="violet" />
        <Kpi label="Critical band" value={fmtNumber(summary?.distribution?.find((entry: any) => entry.name === "Critical")?.value)} detail="Assessments at or above the critical threshold" icon={<Scale size={15} />} tone="crit" />
        <Kpi label="Threats rescored" value={fmtNumber(summary?.threats_scored)} detail={`${summary?.exploitation_status?.length || 0} exploitation states observed`} icon={<BarChart3 size={15} />} tone="high" />
      </div>

      <Panel className="mb-4" ticks>
        <PanelHead
          title="Risk intelligence analytics"
          kicker={`${fmtNumber(threatPool.length)} threats · ${fmtNumber(analyticsAssessments.length)} assessments in range`}
          right={
            matrixFilter ? (
              <button
                type="button"
                onClick={() => setMatrixFilter(null)}
                className="chip border-ion/50 bg-ion/10 text-ion transition-colors hover:border-ion"
                title="Clear the matrix filter"
              >
                {titleCase(matrixFilter.status.replace(/-/g, " "))} × {matrixFilter.band} · {scopedAssessments.length} of {analyticsAssessments.length} · clear
              </button>
            ) : (
              <span className="chip">explainable · no probability claims</span>
            )
          }
        />
        {threatScatterQuery.isError || analyticsQuery.isError ? (
          <ErrorState
            compact
            message={(threatScatterQuery.error as any)?.message || (analyticsQuery.error as any)?.message}
            retry={() => {
              threatScatterQuery.refetch();
              analyticsQuery.refetch();
            }}
          />
        ) : analyticsLoading ? (
          <LoadingBlock rows={6} label="Loading risk analytics" />
        ) : (
          <div className="grid gap-px bg-line [&>*]:min-w-0 xl:grid-cols-2">
            <div className="min-w-0 bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{epssPoints.length} threats</span>}>
                CVSS severity × EPSS probability
              </SectionLabel>
              <ScatterPlot
                points={epssPoints}
                height={300}
                xLabel="CVSS"
                yLabel="EPSS %"
                xMax={10}
                yMax={100}
                quadrants={["Exploit first", "", "", "Watch"]}
                emptyLabel="No threats carry both CVSS and EPSS evidence."
                selected={assessment?.threat_id ? `t${assessment.threat_id}` : null}
                onSelect={(point) => openFromThreat(Number(point.group))}
                onHoverChange={(point) => setHoveredThreat(point ? Number(point.group) : null)}
                dim={(point) => hoveredThreat != null && point.group !== hoveredThreat}
                hint="click a point to inspect"
              />
              <p className="mt-1 text-[10px] leading-relaxed text-dim">
                Bubble size follows the composite risk score. EPSS is an observed probability of exploitation activity, not a forecast for this estate. Hover to read CVE, CVSS, EPSS and provenance; select to open the stored assessment.
              </p>
            </div>
            <div className="min-w-0 bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">stored assessments</span>}>
                Exploitation evidence × risk band
              </SectionLabel>
              <PriorityMatrix
                rows={exploitationMatrix.rows}
                cols={exploitationMatrix.cols}
                values={exploitationMatrix.values}
                height={186}
                selected={matrixSelected}
                unit="assessments"
                onSelect={(row, col) => {
                  const status = EXPLOITATION_ROWS.find(([, label]) => label === row)?.[0];
                  if (!status) return;
                  if (matrixFilter?.status === status && matrixFilter.band === col) {
                    setMatrixFilter(null);
                    return;
                  }
                  setMatrixFilter({ status, band: col });
                  // The list endpoint filters by band, not by exploitation evidence, so the
                  // dropdown follows the cell's band and the note under the table says so.
                  setCategory(col);
                }}
              />
              <p className="mt-2 text-[10px] leading-relaxed text-dim">
                Confirmed exploitation in the critical band is the highest-priority combination. Cell counts cover the whole active range; selecting a cell narrows the other panels to it.
              </p>
            </div>
            <div className="min-w-0 bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{exposurePoints.length} plotted</span>}>
                Exposure × composite risk bubble
              </SectionLabel>
              <ScatterPlot
                points={exposurePoints}
                height={296}
                xLabel="Exposure (0–10)"
                yLabel="Risk score"
                xMax={10}
                yMax={100}
                quadrants={["Contain first", "", "", "Baseline"]}
                emptyLabel="No assessments with exposure inputs in this range."
                selected={assessment?.id ? `a${assessment.id}` : null}
                onSelect={(point) => openAssessment(Number(String(point.id).slice(1)))}
                onHoverChange={(point) => setHoveredThreat(point ? Number(point.group) : null)}
                dim={(point) => hoveredThreat != null && point.group !== hoveredThreat}
                hint="click a point to inspect"
              />
              <p className="mt-1 text-[10px] leading-relaxed text-dim">
                Bubble size is recorded asset criticality. Generic profiles assume mid-range exposure, so their position is an assumption to validate against inventory. Hovering either chart highlights the same threat in the other.
              </p>
            </div>
            <div className="min-w-0 bg-surface p-4">
              <SectionLabel
                right={
                  waterfallOptions.length ? (
                    <select
                      className="field h-[26px] max-w-[190px] text-[9.5px]"
                      value={waterfallAssessment?.id ?? ""}
                      onChange={(event) => setWaterfallId(Number(event.target.value))}
                      aria-label="Waterfall assessment"
                    >
                      {waterfallOptions.map((item) => (
                        <option key={item.id} value={item.id}>{item.ref} · {Number(item.risk_score).toFixed(0)}</option>
                      ))}
                    </select>
                  ) : undefined
                }
              >
                Factor waterfall
              </SectionLabel>
              {waterfallAssessment ? (
                <>
                  <Waterfall items={waterfallItems} total={Number(waterfallAssessment.risk_score ?? 0)} height={214} unit="pts" />
                  <div className="mt-2 flex items-center gap-3 border-t border-line/60 pt-2">
                    <RiskMeter score={Number(waterfallAssessment.risk_score ?? 0)} size={64} />
                    <div className="min-w-0">
                      <div className="truncate text-[10.5px] text-ink">{waterfallAssessment.threat?.name || waterfallAssessment.vulnerability?.title || waterfallAssessment.ref}</div>
                    </div>
                  </div>
                  {/* The recorded rationale is the answer to "why this score", so it reads in
                      full instead of stopping mid-sentence in the meter column. */}
                  <p className="mt-2 text-[10px] leading-relaxed text-dim">{waterfallAssessment.explanation}</p>
                </>
              ) : (
                <p className="py-10 text-center text-[11px] text-dim">No stored assessment in this range, so there is no factor ledger to draw.</p>
              )}
            </div>
          </div>
        )}
      </Panel>

      <div className="mb-4 grid gap-4 xl:grid-cols-[1.25fr_1fr]">
        <Panel ticks>
          <PanelHead
            title="Scoring model"
            kicker={config?.model_version ? `Model ${config.model_version}` : "Factor ledger"}
            right={<span className="chip">thresholds {config?.thresholds?.medium}/{config?.thresholds?.high}/{config?.thresholds?.critical}</span>}
          />
          {configQuery.isLoading ? (
            <LoadingBlock rows={6} label="Loading model configuration" />
          ) : (
            <div className="p-4">
              <div className="mb-4 flex flex-wrap gap-1.5">
                {(config?.bands || []).map((band: any) => (
                  <span key={band.name} className="inline-flex items-center gap-1.5 rounded-md border border-line bg-shade/20 px-2 py-1 font-mono text-[8px] uppercase tracking-[0.1em] text-dim">
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: band.colour }} />
                    {band.name} {band.min}–{band.max}
                  </span>
                ))}
              </div>
              <div className="space-y-2.5">
                {(config?.factors || []).map((factor: any) => (
                  <div key={factor.key}>
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="text-[10.5px] text-ink">{factor.label}</span>
                      <span className="tnum font-mono text-[9px] text-dim">weight {Number(factor.weight).toFixed(2)}</span>
                    </div>
                    <div className="mt-1"><ProgressBar value={Number(factor.weight) * 100} color="#49b8ff" height={3} /></div>
                  </div>
                ))}
              </div>
              <div className="mt-4 rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                <div className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">Formula</div>
                <code className="mt-1 block break-words text-[10.5px] leading-relaxed text-ion/90">{config?.formula || "10 × Σ(weight × normalised factor)"}</code>
                {config?.notes && <p className="mt-1.5 text-[10px] leading-relaxed text-mist">{config.notes}</p>}
              </div>
            </div>
          )}
        </Panel>

        <Panel>
          <PanelHead title="Risk band distribution" kicker="Assessed records" />
          <div className="p-4">
            <DistributionDonut data={distribution} height={176} centerLabel="assessments" centerValue={summary?.assessments ?? 0} colors={["#ff4d5e", "#ff963d", "#ffd166", "#42c98a"]} />
            <div className="mt-4">
              <SectionLabel>Average factor input</SectionLabel>
              <div className="grid grid-cols-2 gap-x-4 gap-y-2">
                {Object.entries(summary?.average_components || {}).map(([key, value]) => (
                  <div key={key}>
                    <div className="flex items-baseline justify-between gap-2">
                      <span className="truncate text-[9.5px] text-mist">{FACTOR_LABELS[key] || titleCase(key)}</span>
                      <span className="tnum font-mono text-[9px] text-dim">{Number(value).toFixed(1)}</span>
                    </div>
                    <div className="mt-0.5"><ProgressBar value={Number(value) * 10} color="#64d8ff" height={2} /></div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Panel>
      </div>

      <Panel className="mb-4">
        <div className="grid gap-3 p-3.5 sm:grid-cols-3">
          <FilterSelect
            label="Risk band"
            value={category}
            onChange={setCategory}
            options={[
              { value: "all", label: "All bands" },
              ...["Critical", "High", "Medium", "Low"].map((name) => ({
                value: name,
                label: `${name} (${categories.find((entry) => entry.name === name)?.count ?? 0})`,
              })),
            ]}
          />
          <div className="flex items-end">
            <div className="rounded-md border border-line bg-shade/20 px-3 py-2 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
              {assessmentsQuery.data?.total ?? 0} assessments in range
            </div>
          </div>
          <div className="flex items-end justify-end">
            <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{summary?.disclaimer}</span>
          </div>
        </div>
      </Panel>

      <Panel>
        {matrixFilter && (
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 border-b border-line px-3.5 py-2 font-mono text-[8.5px] uppercase tracking-[0.09em] text-dim">
            <span className="text-ion">{titleCase(matrixFilter.status.replace(/-/g, " "))} × {matrixFilter.band}</span>
            <span>charts narrowed to this cell · the table follows the band dropdown</span>
            <button className="btn btn-ghost btn-sm ml-auto" onClick={() => setMatrixFilter(null)}>Clear</button>
          </div>
        )}
        {assessmentsQuery.isError ? (
          <ErrorState message={(assessmentsQuery.error as any)?.message} retry={() => assessmentsQuery.refetch()} />
        ) : assessmentsQuery.isLoading ? (
          <LoadingBlock rows={8} label="Loading assessments" />
        ) : !assessments.length ? (
          <EmptyState
            title="No assessments recorded in this range"
            detail="Assess a threat from the threat intelligence module, or create one directly against an asset exposure match."
            icon={<Calculator size={19} />}
            action={<Link to="/app/threats" className="btn btn-primary btn-sm">Open threat intelligence</Link>}
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-shell">
                <thead>
                  <tr>
                    <th>Assessment</th>
                    <th>Subject</th>
                    <th>Score</th>
                    <th>Band</th>
                    <th className="hidden lg:table-cell">Exploitation</th>
                    <th className="hidden md:table-cell">Urgency</th>
                    <th className="hidden sm:table-cell">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {assessments.map((item) => (
                    <tr
                      key={item.id}
                      onClick={() =>
                        setSearchParams((prev) => {
                          const next = new URLSearchParams(prev);
                          next.set("assessment", String(item.id));
                          return next;
                        })
                      }
                      className={focus === String(item.id) ? "bg-ion/[0.05]" : undefined}
                    >
                      <td>
                        <div className="font-mono text-[9px] text-dim">{item.ref}</div>
                        <div className="mt-0.5 font-mono text-[8px] uppercase tracking-[0.06em] text-dim">{item.model_version}</div>
                      </td>
                      <td className="max-w-[340px]">
                        <div className="truncate text-[11.5px] text-ink">{item.threat?.name || item.vulnerability?.title || "Generic assessment"}</div>
                        <div className="mt-0.5 font-mono text-[8px] uppercase tracking-[0.06em] text-dim">
                          {item.asset?.name ? `${item.asset.ref} · ${item.asset.name}` : "Generic asset profile"}
                          {item.vulnerability?.cve_id ? ` · ${item.vulnerability.cve_id}` : ""}
                        </div>
                      </td>
                      <td><ScoreChip score={item.risk_score} /></td>
                      <td>
                        <span className={clsx("font-mono text-[9px] uppercase tracking-[0.08em]")} style={{ color: riskColor(item.risk_score) }}>{item.risk_category}</span>
                      </td>
                      <td className="hidden lg:table-cell"><span className="font-mono text-[9px] text-mist">{titleCase(item.exploitation_status)}</span></td>
                      <td className="hidden md:table-cell"><StatusBadge status={item.urgency} /></td>
                      <td className="hidden sm:table-cell"><span className="font-mono text-[9px] text-dim">{fmtDate(item.created_at, true)}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={assessmentsQuery.data!.page} pages={assessmentsQuery.data!.pages} total={assessmentsQuery.data!.total} onPage={setPage} />
          </>
        )}
      </Panel>

      <Panel className="mt-4">
        <PanelHead title="Analyst feedback on the model" kicker="Human review queue" right={<span className="chip">{feedbackQuery.data?.count ?? 0} entries</span>} />
        {!feedback.length ? (
          <div className="px-4 py-6 text-center text-[11px] text-dim">
            No feedback recorded. Open an assessment and record whether the score matches your judgement; feedback does not silently alter weights.
          </div>
        ) : (
          <div className="divide-y divide-veil/[0.05]">
            {feedback.slice(0, 6).map((entry, index) => (
              <div key={`${entry.assessment_id}-${index}`} className="flex flex-wrap items-start justify-between gap-3 px-4 py-2.5">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[9px] text-info">{entry.assessment_ref}</span>
                    <span className="font-mono text-[8px] uppercase tracking-[0.08em] text-dim">{entry.user}</span>
                  </div>
                  <p className="mt-0.5 max-w-[70ch] text-[10.5px] leading-relaxed text-mist">{entry.note}</p>
                </div>
                <span className={clsx("font-mono text-[8.5px] uppercase tracking-[0.1em]", entry.verdict === "agree" ? "text-low" : entry.verdict === "incorrect" ? "text-crit" : "text-med")}>
                  {titleCase(entry.verdict)} · score {Number(entry.score).toFixed(1)}
                </span>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Drawer
        open={Boolean(focus)}
        onClose={closeDrawer}
        width="max-w-[720px]"
        title={
          assessment ? (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[14px] font-semibold text-ink">{assessment.threat?.name || assessment.vulnerability?.title || "Risk assessment"}</span>
              <span className="chip">{assessment.ref}</span>
            </div>
          ) : (
            <span>Risk assessment</span>
          )
        }
        subtitle={assessment && <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{assessment.asset ? `${assessment.asset.ref} · ${assessment.asset.name}` : "Generic asset profile"} · {fmtDate(assessment.created_at, true)}</span>}
        footer={
          can("analyst") && assessment ? (
            <>
              <span className="mr-auto font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">Feedback is advisory, not an automatic rescore</span>
              <button className="btn btn-primary btn-sm" disabled={feedbackNote.trim().length < 5 || submitFeedback.isPending} onClick={() => submitFeedback.mutate()}>
                <MessageSquareWarning size={12} /> {submitFeedback.isPending ? "Recording…" : "Record feedback"}
              </button>
            </>
          ) : (
            <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">Read-only — analysts can submit feedback</span>
          )
        }
      >
        {detailQuery.isError ? (
          <ErrorState message={(detailQuery.error as any)?.message} retry={() => detailQuery.refetch()} compact />
        ) : detailQuery.isLoading || !assessment ? (
          <LoadingBlock rows={7} label="Loading assessment" />
        ) : (
          <div>
            <div className="flex items-center justify-between gap-4 rounded-xl border border-line bg-shade/25 px-4 py-4">
              <div>
                <div className="panel-kicker">Composite risk</div>
                <div className="mt-1 font-display text-[22px] font-semibold" style={{ color: riskColor(assessment.risk_score) }}>{assessment.risk_category}</div>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <StatusBadge status={assessment.urgency} />
                  <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">{titleCase(assessment.exploitation_status)}</span>
                </div>
                <p className="mt-2 max-w-[44ch] text-[10.5px] leading-relaxed text-dim">{assessment.explanation}</p>
              </div>
              <div className="flex shrink-0 flex-col items-center gap-1">
                <RiskMeter score={assessment.risk_score} size={88} />
                <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">evidence {Math.round(assessment.evidence_confidence || 0)}%</span>
              </div>
            </div>

            <DrawerSection title="Score history" kicker="Stored revisions for this threat">
              {historyQuery.isLoading ? (
                <p className="text-[11px] text-dim">Loading stored revisions…</p>
              ) : historyQuery.isError ? (
                <div className="flex flex-wrap items-center gap-2 text-[11px] text-dim">
                  <span>Stored revisions could not be loaded.</span>
                  <button className="btn btn-ghost btn-sm" onClick={() => historyQuery.refetch()}>Retry</button>
                </div>
              ) : scoreHistory.length < 2 ? (
                <p className="max-w-[60ch] text-[11px] leading-relaxed text-dim">
                  Historical data unavailable — {scoreHistory.length ? "only one" : "no"} stored assessment exists for this threat, so there is no trend to plot. Rescoring the threat records a further revision.
                </p>
              ) : (
                <>
                  <div className="flex flex-wrap items-end justify-between gap-3 rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                    <div>
                      <div className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">{scoreHistory.length} stored revisions</div>
                      <div className="mt-1 flex flex-wrap items-baseline gap-2">
                        <span className="tnum font-display text-[18px] font-semibold" style={{ color: riskColor(Number(latestRevision.risk_score ?? 0)) }}>
                          {Number(latestRevision.risk_score ?? 0).toFixed(1)}
                        </span>
                        <span className={clsx("font-mono text-[9px]", historyDelta > 0 ? "text-crit" : historyDelta < 0 ? "text-low" : "text-dim")}>
                          {historyDelta > 0 ? "+" : ""}{historyDelta.toFixed(1)} since first stored
                        </span>
                      </div>
                    </div>
                    <Sparkline
                      values={scoreHistory.map((entry) => Number(entry.risk_score ?? 0))}
                      color={riskColor(Number(latestRevision.risk_score ?? 0))}
                      width={220}
                      height={44}
                    />
                  </div>
                  <div className="mt-2 space-y-1">
                    {[...scoreHistory].reverse().map((entry) => (
                      <button
                        key={entry.id}
                        type="button"
                        onClick={() => openAssessment(entry.id)}
                        className={clsx(
                          "flex w-full items-baseline justify-between gap-2 rounded-md border px-3 py-1.5 text-left transition-colors",
                          entry.id === assessment.id ? "border-ion/40 bg-ion/[0.06]" : "border-line/70 hover:border-ion/50",
                        )}
                      >
                        <span className="font-mono text-[9px] text-dim">{revisionStamp(entry.created_at)}</span>
                        <span className="flex items-baseline gap-2">
                          <span className="tnum font-mono text-[10px] text-ink">{Number(entry.risk_score ?? 0).toFixed(1)}</span>
                          <span className="font-mono text-[8px] uppercase tracking-[0.08em]" style={{ color: riskColor(Number(entry.risk_score ?? 0)) }}>{entry.risk_category}</span>
                        </span>
                      </button>
                    ))}
                  </div>
                  <p className="mt-2 text-[9.5px] leading-relaxed text-dim">
                    Only assessments already stored for this threat are plotted. Selecting a revision opens that record; nothing is interpolated.
                  </p>
                </>
              )}
            </DrawerSection>

            <DrawerSection title="Factor contributions" kicker="Transparent scoring ledger">
              {!assessment.factors?.length ? (
                <p className="text-[11px] text-dim">No factor breakdown was stored for this assessment.</p>
              ) : (
                <div className="space-y-2.5">
                  {assessment.factors.map((factor: any) => (
                    <div key={factor.key || factor.label}>
                      <div className="flex items-baseline justify-between gap-3">
                        <span className="text-[10.5px] text-ink">{factor.label || FACTOR_LABELS[factor.key] || factor.key}</span>
                        <span className="tnum font-mono text-[9px] text-dim">
                          {Number(factor.contribution ?? 0).toFixed(1)} pts · input {Number(factor.normalized ?? factor.value ?? 0).toFixed(1)}/10 · weight {Number(factor.weight ?? 0).toFixed(2)}
                        </span>
                      </div>
                      <div className="mt-1"><ProgressBar value={(Number(factor.normalized ?? factor.value ?? 0) / 10) * 100} color="#49b8ff" height={3} /></div>
                      {factor.note && <p className="mt-1 text-[9.5px] leading-relaxed text-dim">{factor.note}</p>}
                    </div>
                  ))}
                </div>
              )}
            </DrawerSection>

            <DrawerSection title="Evidence inputs" kicker="Where each factor comes from">
              {detail.evidence && typeof detail.evidence === "object" && !Array.isArray(detail.evidence) ? (
                <div className="space-y-1.5">
                  {Object.entries(detail.evidence).map(([key, value]: [string, any]) => (
                    <div key={key} className="flex flex-wrap items-baseline justify-between gap-2 rounded-md border border-line bg-shade/20 px-3 py-2">
                      <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{titleCase(key.replace(/_/g, " "))}</span>
                      <span className="text-[10.5px] text-ink">
                        {typeof value === "object" && value ? `${value.source}: ${typeof value.value === "number" ? value.value.toFixed(1) : value.value}` : String(value)}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <EvidenceList items={detail.evidence} />
              )}
            </DrawerSection>

            <DrawerSection title="Limitations" kicker="How to read this score">
              <ul className="space-y-1.5">
                {(detail.limitations || []).map((limitation: string) => (
                  <li key={limitation} className="flex gap-2 text-[10.5px] leading-relaxed text-mist">
                    <span className="mt-[6px] h-1 w-1 shrink-0 rounded-full bg-med" />{limitation}
                  </li>
                ))}
              </ul>
            </DrawerSection>

            {can("analyst") && (
              <DrawerSection title="Your review" kicker="Model feedback">
                <div className="grid gap-3 sm:grid-cols-2">
                  <FieldLabel label="Verdict">
                    <select className="field" value={verdict} onChange={(event) => setVerdict(event.target.value)}>
                      {VERDICTS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                    </select>
                  </FieldLabel>
                  <div className="flex items-end">
                    <p className="text-[9.5px] leading-relaxed text-dim">Feedback is logged in the audit trail and visible to administrators reviewing model configuration.</p>
                  </div>
                </div>
                <FieldLabel label="Review note" className="mt-3" hint="Minimum 5 characters. Reference which input you believe is wrong or under-weighted.">
                  <textarea className="field" rows={3} value={feedbackNote} onChange={(event) => setFeedbackNote(event.target.value)} maxLength={2000} />
                </FieldLabel>
              </DrawerSection>
            )}

            <div className="mt-3 flex flex-wrap gap-2">
              {assessment.threat && <Link to={`/app/threats?focus=${assessment.threat.ref}`} className="btn btn-ghost btn-sm">Open threat record</Link>}
              {assessment.asset && <Link to={`/app/assets?focus=${assessment.asset.ref}`} className="btn btn-ghost btn-sm">Open asset</Link>}
              {assessment.vulnerability && <Link to={`/app/vulnerabilities?focus=${assessment.vulnerability.cve_id}`} className="btn btn-ghost btn-sm">Open advisory</Link>}
            </div>
          </div>
        )}
      </Drawer>

      <Modal
        open={configOpen}
        onClose={() => setConfigOpen(false)}
        title="Model configuration"
        description="Weights must sum to 1.00. Saving rescoring every threat and stored assessment, and is recorded in the audit trail."
        className="max-w-[640px]"
        footer={
          <>
            <button className="btn btn-ghost" onClick={() => setConfigOpen(false)}>Cancel</button>
            <button className="btn btn-primary" disabled={saveConfig.isPending || Math.abs(weightTotal - 1) > 0.01} onClick={() => saveConfig.mutate()}>
              {saveConfig.isPending ? "Saving & rescoring…" : "Save and rescore"}
            </button>
          </>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2">
          {Object.keys(draftWeights).map((key) => (
            <FieldLabel key={key} label={FACTOR_LABELS[key] || titleCase(key)}>
              <input
                className="field font-mono"
                type="number"
                min={0}
                max={1}
                step={0.01}
                value={draftWeights[key]}
                onChange={(event) => setDraftWeights({ ...draftWeights, [key]: Number(event.target.value) })}
              />
            </FieldLabel>
          ))}
        </div>
        <div className={clsx("mt-2 flex items-center justify-between rounded-md border px-3 py-2 font-mono text-[9px] uppercase tracking-[0.1em]", Math.abs(weightTotal - 1) > 0.01 ? "border-crit/30 bg-crit/[0.06] text-crit" : "border-low/25 bg-low/[0.04] text-low")}>
          <span>Weight total</span><span className="tnum">{weightTotal.toFixed(2)} / 1.00</span>
        </div>
        <div className="mt-4">
          <SectionLabel>Band thresholds</SectionLabel>
          <div className="grid gap-3 sm:grid-cols-3">
            {["medium", "high", "critical"].map((key) => (
              <FieldLabel key={key} label={`${titleCase(key)} band starts at`}>
                <input
                  className="field font-mono"
                  type="number"
                  min={0}
                  max={100}
                  step={0.5}
                  value={draftThresholds[key]}
                  onChange={(event) => setDraftThresholds({ ...draftThresholds, [key]: Number(event.target.value) })}
                />
              </FieldLabel>
            ))}
          </div>
        </div>
        <InlineNotice tone="med" className="mt-4">
          Changing weights changes rankings, not underlying evidence. The platform recomputes stored scores immediately and records who made the change.
        </InlineNotice>
      </Modal>
    </>
  );
}
