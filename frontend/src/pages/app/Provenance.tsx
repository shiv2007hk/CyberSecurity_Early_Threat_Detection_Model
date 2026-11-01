import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowRight,
  Boxes,
  GitFork,
  Link2,
  Microscope,
  Route,
  ShieldCheck,
  Waypoints,
} from "lucide-react";
import clsx from "clsx";
import { api, qs } from "../../lib/api";
import { SEVERITY, fmtDate, fmtNumber, relTime, riskColor, titleCase } from "../../lib/format";
import {
  EmptyState,
  ErrorState,
  InlineNotice,
  LoadingBlock,
  PageHeader,
  Panel,
  PanelHead,
  SeverityBadge,
  StatusBadge,
} from "../../components/ui";
import { Waterfall, useChartBox } from "../../components/analytics-charts";
import { EvidenceList, FilterSelect, MiniBar, SectionLabel } from "./shared";
import { tone as themeTone } from "../../lib/theme";

const NODE_COLORS: Record<string, string> = {
  source: "#9a8cff",
  evidence: "#6f8aa4",
  threat: "#ff963d",
  vulnerability: "#ffd166",
  rule: "#64d8ff",
  alert: "#ff4d5e",
  asset: "#49b8ff",
  recommendation: "#42c98a",
};

interface GNode {
  id: string;
  column: number;
  kind: keyof typeof NODE_COLORS;
  label: string;
  sublabel: string;
  color: string;
  link?: string;
  meta?: Array<{ label: string; value: string }>;
}

function EvidenceGraph({
  nodes,
  edges,
  selected,
  onSelect,
}: {
  nodes: GNode[];
  edges: Array<{ from: string; to: string }>;
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const [hover, setHover] = useState<string | null>(null);
  const [boxRef, box] = useChartBox(1000, 400);
  const nodeW = 148;
  const nodeH = 58;
  /* Five 148px columns need more canvas than a 720px card holds — below this width the
     nodes overlapped each other, so the chain scrolls instead of colliding. */
  const minWidth = nodeW * 5 + 14 * 4 + 44;
  /* A 1000-unit chain squeezed into a 720px column rendered every label at 72%, so the
     layout is drawn against the width on screen and grows taller when a column is busy. */
  const W = Math.max(minWidth, box.w);
  const columns = useMemo(() => {
    const map = new Map<number, GNode[]>();
    nodes.forEach((node) => {
      map.set(node.column, [...(map.get(node.column) || []), node]);
    });
    return map;
  }, [nodes]);
  const busiest = Math.max(1, ...Array.from(columns.values()).map((list) => list.length));
  const H = Math.max(300, busiest * (nodeH + 20) + 44);
  const positions = useMemo(() => {
    const map = new Map<string, { x: number; y: number }>();
    const columnCount = Math.max(1, ...Array.from(columns.keys())) + 1;
    const left = 22;
    const usable = W - left * 2 - nodeW;
    columns.forEach((list, column) => {
      const x = left + (usable / Math.max(1, columnCount - 1)) * column;
      const gap = H / (list.length + 1);
      list.forEach((node, index) => {
        map.set(node.id, { x, y: gap * (index + 1) - nodeH / 2 });
      });
    });
    return map;
  }, [columns, W, H]);

  if (!nodes.length) {
    return <div className="py-16 text-center text-[11px] text-dim">This alert has no recorded relationships to graph.</div>;
  }

  const activeId = selected || hover;

  return (
    <div className="overflow-x-auto">
      <div ref={boxRef} style={{ height: H, minWidth }}>
        <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full" role="img" aria-label="Recorded evidence and decision chain for the selected alert">
          <defs>
            <marker id="provArrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" orient="auto">
              <path d="M0,0 L8,4 L0,8 Z" fill="rgb(var(--ion-rgb) / 0.7)" />
            </marker>
          </defs>
          {[0, 1, 2, 3, 4].map((column) => (
            <text key={column} x={22 + ((W - 44 - nodeW) / 4) * column} y={16} fill="var(--chart-axis)" fontSize="7.5" fontFamily="JetBrains Mono, monospace" letterSpacing="1.4">
              {["RECORDED BY", "INTELLIGENCE", "RULE", "WARNING", "INVENTORY & RESPONSE"][column]}
            </text>
          ))}
          <line x1="22" x2={W - 22} y1="24" y2="24" stroke="var(--chart-grid)" />
          {edges.map((edge, index) => {
            const from = positions.get(edge.from);
            const to = positions.get(edge.to);
            if (!from || !to) return null;
            const active = activeId === edge.from || activeId === edge.to;
            const x1 = from.x + nodeW;
            const y1 = from.y + nodeH / 2;
            const x2 = to.x;
            const y2 = to.y + nodeH / 2;
            const mid = (x1 + x2) / 2;
            return (
              <path
                key={`${edge.from}-${edge.to}-${index}`}
                d={`M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2 - 3} ${y2}`}
                fill="none"
                stroke={active ? "rgb(var(--ion-rgb) / 0.55)" : "rgb(var(--mist-rgb) / 0.35)"}
                strokeWidth={active ? 1.3 : 0.8}
                markerEnd={active ? "url(#provArrow)" : undefined}
              />
            );
          })}
          {nodes.map((node) => {
            const pos = positions.get(node.id);
            if (!pos) return null;
            const isActive = selected === node.id;
            const connected = hover === node.id || selected === node.id;
            const accent = themeTone(node.color);
            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                onMouseEnter={() => setHover(node.id)}
                onMouseLeave={() => setHover(null)}
                onClick={() => onSelect(node.id)}
                className="cursor-pointer"
                opacity={activeId && !connected && !edges.some((edge) => (edge.from === node.id || edge.to === node.id) && (edge.from === activeId || edge.to === activeId)) ? 0.55 : 1}
              >
                <rect
                  width={nodeW}
                  height={nodeH}
                  rx="7"
                  fill="var(--trough)"
                  stroke={isActive ? accent : "var(--chart-grid)"}
                  strokeWidth={isActive ? 1.3 : 0.8}
                />
                {isActive && <rect width={nodeW} height={nodeH} rx="7" fill={accent} opacity={0.14} />}
                <rect width="2.5" height={nodeH} rx="1.2" fill={accent} opacity={isActive ? 1 : 0.65} />
                <text x="11" y="17" fill="var(--ink)" fontSize="9" fontFamily="JetBrains Mono, monospace">
                  {node.label.length > 21 ? `${node.label.slice(0, 20)}…` : node.label}
                </text>
                <text x="11" y="30" fill="var(--mist)" fontSize="7.3" fontFamily="JetBrains Mono, monospace">
                  {node.sublabel.length > 27 ? `${node.sublabel.slice(0, 26)}…` : node.sublabel}
                </text>
                <text x={nodeW - 7} y="46" textAnchor="end" fill={accent} fontSize="6.5" fontFamily="JetBrains Mono, monospace" letterSpacing="0.6">
                  {node.kind.toUpperCase()}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

function Timeline({ events }: { events: Array<{ at: string; label: string; detail?: string; tone: string }> }) {
  if (!events.length) return <div className="py-10 text-center text-[11px] text-dim">No decision events recorded.</div>;
  return (
    <ol className="relative ml-2 space-y-3 border-l border-line pl-4">
      {events.map((event, index) => (
        <li key={`${event.at}-${index}`} className="relative">
          <span
            className="absolute -left-[21px] top-1 h-2 w-2 rounded-full border-2 border-sunken"
            style={{ background: themeTone(event.tone) }}
          />
          <div className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">{fmtDate(event.at, true)} · {relTime(event.at)}</div>
          <div className="mt-0.5 text-[11.5px] leading-snug text-ink">{event.label}</div>
          {event.detail && <div className="mt-0.5 text-[10px] leading-relaxed text-dim">{event.detail}</div>}
        </li>
      ))}
    </ol>
  );
}

export default function Provenance() {
  const [alertRef, setAlertRef] = useState<string | null>(null);
  const [severity, setSeverity] = useState("all");
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const alertsQuery = useQuery({
    queryKey: ["prov-alerts", severity],
    queryFn: () => api<any>(`/alerts${qs({ size: 100, range: "365d", sort_by: "risk_score", order: "desc", severity: severity === "all" ? undefined : severity })}`),
  });
  const sourcesQuery = useQuery({
    queryKey: ["prov-sources"],
    queryFn: () => api<any>("/sources"),
    staleTime: 120_000,
  });

  const alerts = (alertsQuery.data?.items || []) as any[];
  const activeRef = alertRef || alerts[0]?.ref || "";
  const detailQuery = useQuery({
    queryKey: ["prov-alert", activeRef],
    enabled: !!activeRef,
    queryFn: () => api<any>(`/alerts/${activeRef}`),
  });
  const detail = detailQuery.data;

  const threatId = detail?.threat?.id;
  const assessmentsQuery = useQuery({
    queryKey: ["prov-assessments", threatId],
    enabled: !!threatId,
    queryFn: () => api<any>(`/risk/assessments${qs({ threat: threatId, size: 5, range: "365d" })}`),
    staleTime: 60_000,
  });
  const assessment = assessmentsQuery.data?.items?.[0] || null;
  const threatRefForBreakdown = detail?.threat?.ref;
  const breakdownQuery = useQuery({
    queryKey: ["prov-breakdown", threatRefForBreakdown],
    enabled: !!threatRefForBreakdown && assessmentsQuery.isSuccess && !assessment,
    queryFn: () => api<any>(`/threats/${threatRefForBreakdown}`),
    staleTime: 60_000,
  });
  const breakdown = breakdownQuery.data?.risk_breakdown || null;

  const sources = (sourcesQuery.data?.items || []) as any[];

  const graph = useMemo(() => {
    if (!detail) return { nodes: [] as GNode[], edges: [] as Array<{ from: string; to: string }> };
    const alert = detail.alert;
    const nodes: GNode[] = [];
    const edges: Array<{ from: string; to: string }> = [];
    const sourceNames = String(alert.source || "")
      .split(",")
      .map((entry: string) => entry.trim())
      .filter(Boolean)
      .slice(0, 2);
    sourceNames.forEach((name: string, index: number) => {
      const id = `source-${index}`;
      const record = sources.find((source) => source.name === name || source.key === name);
      nodes.push({
        id,
        column: 0,
        kind: "source",
        label: name,
        sublabel: record ? `${titleCase(record.status)} · reliability ${(record.reliability * 100).toFixed(0)}%` : "Recorded source string",
        color: NODE_COLORS.source,
        link: "/app/sources",
        meta: [
          { label: "Name", value: name },
          { label: "Status", value: record ? titleCase(record.status) : "Not registered" },
          { label: "Reliability", value: record ? `${(record.reliability * 100).toFixed(0)}%` : "—" },
          { label: "Items ingested", value: record ? fmtNumber(record.items_ingested) : "—" },
        ],
      });
    });
    const evidence = (alert.evidence || []).slice(0, 4);
    evidence.forEach((item: any, index: number) => {
      const id = `evidence-${index}`;
      nodes.push({
        id,
        column: 0,
        kind: "evidence",
        label: String(item.label || `Evidence ${index + 1}`),
        sublabel: String(item.value || "—"),
        color: NODE_COLORS.evidence,
        meta: [
          { label: "Evidence field", value: String(item.label || "—") },
          { label: "Recorded value", value: String(item.value ?? "—") },
        ],
      });
    });
    let threatNode: string | null = null;
    if (detail.threat) {
      threatNode = "threat";
      nodes.push({
        id: threatNode,
        column: 1,
        kind: "threat",
        label: detail.threat.ref,
        sublabel: detail.threat.name,
        color: riskColor(detail.threat.risk_score),
        link: `/app/threats?focus=${detail.threat.ref}`,
        meta: [
          { label: "Record", value: detail.threat.ref },
          { label: "Name", value: detail.threat.name },
          { label: "Severity", value: titleCase(detail.threat.severity) },
          { label: "Risk", value: `${Number(detail.threat.risk_score ?? 0).toFixed(1)} / 100` },
          { label: "Source", value: detail.threat.source || "—" },
          { label: "Published", value: fmtDate(detail.threat.published_at, true) },
        ],
      });
    }
    let vulnNode: string | null = null;
    if (detail.vulnerability) {
      vulnNode = "vulnerability";
      nodes.push({
        id: vulnNode,
        column: 1,
        kind: "vulnerability",
        label: detail.vulnerability.cve_id,
        sublabel: detail.vulnerability.title,
        color: NODE_COLORS.vulnerability,
        link: `/app/vulnerabilities?focus=${detail.vulnerability.cve_id}`,
        meta: [
          { label: "CVE", value: detail.vulnerability.cve_id },
          { label: "CVSS", value: String(detail.vulnerability.cvss ?? "—") },
          { label: "EPSS", value: detail.vulnerability.epss != null ? `${(Number(detail.vulnerability.epss) * 100).toFixed(1)}%` : "—" },
          { label: "Known exploited", value: detail.vulnerability.known_exploited ? "Yes" : "No" },
        ],
      });
    }
    nodes.push({
      id: "rule",
      column: 2,
      kind: "rule",
      label: detail.rule?.name || titleCase(alert.rule_key),
      sublabel: detail.rule?.key || alert.rule_key,
      color: NODE_COLORS.rule,
      link: "/app/alerts",
      meta: [
        { label: "Rule", value: detail.rule?.name || alert.rule_key },
        { label: "Logic", value: detail.rule?.logic || "Deterministic rule recorded on the alert." },
        { label: "Reported severity", value: detail.rule?.severity || titleCase(alert.severity) },
      ],
    });
    nodes.push({
      id: "alert",
      column: 3,
      kind: "alert",
      label: alert.ref,
      sublabel: `${titleCase(alert.severity)} · ${titleCase(alert.status)}`,
      color: SEVERITY[(alert.severity || "unknown").toLowerCase()]?.hex || NODE_COLORS.alert,
      link: `/app/alerts?focus=${alert.ref}`,
      meta: [
        { label: "Alert", value: alert.ref },
        { label: "Title", value: alert.title },
        { label: "Detected", value: fmtDate(alert.detected_at, true) },
        { label: "Risk score", value: `${Number(alert.risk_score ?? 0).toFixed(1)} / 100` },
        { label: "Confidence", value: alert.confidence != null ? `${Number(alert.confidence).toFixed(0)}%` : "—" },
        { label: "Trigger", value: alert.trigger_reason || "—" },
      ],
    });
    (detail.assets || []).slice(0, 3).forEach((asset: any) => {
      nodes.push({
        id: `asset-${asset.id}`,
        column: 4,
        kind: "asset",
        label: asset.ref,
        sublabel: asset.name,
        color: NODE_COLORS.asset,
        link: `/app/assets?focus=${asset.ref}`,
        meta: [
          { label: "Asset", value: asset.ref },
          { label: "Name", value: asset.name },
          { label: "Category", value: titleCase(asset.category) },
          { label: "Exposure", value: titleCase(asset.exposure) },
          { label: "Criticality", value: `${asset.criticality}/5` },
        ],
      });
    });
    const recommendation = (detail.recommendations || [])[0];
    if (recommendation) {
      nodes.push({
        id: "recommendation",
        column: 4,
        kind: "recommendation",
        label: recommendation.ref,
        sublabel: recommendation.title,
        color: NODE_COLORS.recommendation,
        link: "/app/recommendations",
        meta: [
          { label: "Recommendation", value: recommendation.ref },
          { label: "Action", value: recommendation.action },
          { label: "Priority", value: titleCase(recommendation.priority) },
          { label: "Status", value: titleCase(recommendation.status) },
          { label: "Due", value: fmtDate(recommendation.due_at, true) },
        ],
      });
    }
    sourceNames.forEach((_: string, index: number) => edges.push({ from: `source-${index}`, to: threatNode || "rule" }));
    evidence.forEach((_: any, index: number) => edges.push({ from: `evidence-${index}`, to: threatNode || (vulnNode ? vulnNode : "rule") }));
    if (threatNode) edges.push({ from: threatNode, to: "rule" });
    if (vulnNode) edges.push({ from: vulnNode, to: "rule" });
    edges.push({ from: "rule", to: "alert" });
    (detail.assets || []).slice(0, 3).forEach((asset: any) => edges.push({ from: "alert", to: `asset-${asset.id}` }));
    if (recommendation) edges.push({ from: "alert", to: "recommendation" });
    return { nodes, edges };
  }, [detail, sources]);

  const selected = graph.nodes.find((node) => node.id === selectedNode) || null;

  const timeline = useMemo(() => {
    if (!detail) return [] as Array<{ at: string; label: string; detail?: string; tone: string }>;
    const alert = detail.alert;
    const list: Array<{ at: string; label: string; detail?: string; tone: string }> = [];
    if (detail.threat?.published_at) {
      list.push({
        at: detail.threat.published_at,
        label: `Source record published · ${detail.threat.source}`,
        detail: detail.threat.name,
        tone: NODE_COLORS.source,
      });
    }
    if (alert.detected_at) {
      list.push({
        at: alert.detected_at,
        label: `Rule fired · ${detail.rule?.name || alert.rule_key}`,
        detail: alert.trigger_reason,
        tone: NODE_COLORS.rule,
      });
    }
    (detail.notes || []).forEach((note: any) => {
      list.push({
        at: note.created_at,
        label: `Analyst note · ${note.author?.full_name || "unknown"}`,
        detail: note.body,
        tone: "#78b7ff",
      });
    });
    if (alert.acknowledged_at) list.push({ at: alert.acknowledged_at, label: "Alert acknowledged", tone: "#ffd166" });
    (detail.recommendations || []).forEach((rec: any) => {
      list.push({
        at: rec.created_at,
        label: `Recommendation drafted · ${rec.ref}`,
        detail: rec.title,
        tone: NODE_COLORS.recommendation,
      });
    });
    if (alert.resolved_at) list.push({ at: alert.resolved_at, label: "Alert resolved", tone: "#42c98a" });
    return list.filter((entry) => entry.at).sort((a, b) => new Date(a.at).getTime() - new Date(b.at).getTime());
  }, [detail]);

  const factors = assessment?.factors?.length ? assessment.factors : breakdown?.factors || [];
  const riskTotal = assessment?.risk_score ?? breakdown?.risk_score ?? 0;
  const chainSourceText = `${detail?.alert?.source || ""} ${detail?.threat?.source || ""}`.toLowerCase();

  const loading = alertsQuery.isLoading;
  const failed = alertsQuery.isError;

  return (
    <>
      <PageHeader
        kicker="Provenance surface · recorded links only"
        title="Evidence & threat provenance"
        description="Trace one warning from the source string recorded on it, through the deterministic rule that fired, to the inventory it touches and the response it recommends. Every node comes from stored fields; no relationship is inferred or drawn for effect."
        aside={
          detail && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">
              <span className="text-ion/85">{detail.alert.ref}</span>
              <span>·</span>
              <span>{graph.nodes.length} nodes</span>
              <span>·</span>
              <span>{graph.edges.length} recorded edges</span>
              <span>·</span>
              <span>{timeline.length} decision events</span>
            </div>
          )
        }
        actions={
          <>
            <FilterSelect
              label="Severity"
              value={severity}
              onChange={setSeverity}
              options={[
                { value: "all", label: "All severities" },
                ...((alertsQuery.data?.facets?.severities || []) as Array<{ name: string; count: number }>).map((entry) => ({
                  value: entry.name,
                  label: `${titleCase(entry.name)} (${entry.count})`,
                })),
              ]}
              className="w-[168px]"
            />
            <FilterSelect
              label="Warning"
              value={activeRef}
              onChange={(value) => {
                setAlertRef(value);
                setSelectedNode(null);
              }}
              options={alerts.map((alert) => ({
                value: alert.ref,
                label: `${alert.ref} · ${String(alert.title).slice(0, 46)}`,
              }))}
              className="w-[300px]"
            />
            <Link to="/app/alerts" className="btn btn-ghost btn-sm">
              Alert centre <ArrowRight size={12} />
            </Link>
          </>
        }
      />

      {loading && (
        <Panel>
          <LoadingBlock rows={5} label="Loading evidence chain" />
        </Panel>
      )}

      {failed && !loading && (
        <Panel>
          <ErrorState message={(alertsQuery.error as Error)?.message} retry={() => alertsQuery.refetch()} />
        </Panel>
      )}

      {!loading && !failed && !alerts.length && (
        <Panel>
          <EmptyState
            icon={<Microscope size={18} />}
            title="No alerts in this filter"
            detail="Provenance needs a recorded alert. Widen the severity filter or run detection from the alert centre."
            action={<Link to="/app/alerts" className="btn btn-primary btn-sm">Open alert centre</Link>}
          />
        </Panel>
      )}

      {!loading && !failed && alerts.length > 0 && detailQuery.isLoading && (
        <Panel>
          <LoadingBlock rows={4} label="Loading selected alert" />
        </Panel>
      )}

      {!loading && !failed && detailQuery.isError && (
        <Panel>
          <ErrorState
            message={(detailQuery.error as Error)?.message}
            retry={() => detailQuery.refetch()}
          />
        </Panel>
      )}

      {detail && (
        <div className="space-y-4">
          <div className="grid gap-4 xl:grid-cols-12">
            <Panel ticks className="xl:col-span-8">
              <PanelHead
                title="Evidence chain"
                kicker="Source → intelligence → rule → warning → inventory"
                right={
                  <div className="flex items-center gap-2">
                    <span className="chip">click a node</span>
                  </div>
                }
              />
              <div className="px-3 pb-3 pt-2">
                <EvidenceGraph nodes={graph.nodes} edges={graph.edges} selected={selectedNode} onSelect={(id) => setSelectedNode((current) => (current === id ? null : id))} />
                <div className="mt-2 flex flex-wrap items-center justify-between gap-2 border-t border-line/70 px-1 pt-2.5">
                  <p className="max-w-[76ch] text-[10px] leading-relaxed text-dim">
                    Edges represent stored foreign keys and recorded evidence strings. Source strings are shown as published on the alert, even when the connector is not currently registered.
                  </p>
                  <span className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">
                    {graph.edges.length} links · {graph.nodes.length} records
                  </span>
                </div>
              </div>
            </Panel>

            <div className="space-y-4 xl:col-span-4">
              <Panel>
                <PanelHead
                  title={selected ? titleCase(selected.kind) : detail.alert.ref}
                  kicker={selected ? "Node inspector" : "Selected warning"}
                  right={
                    selected ? (
                      <button className="btn btn-quiet btn-sm" onClick={() => setSelectedNode(null)}>Clear</button>
                    ) : (
                      <SeverityBadge severity={detail.alert.severity} />
                    )
                  }
                />
                <div className="px-4 pb-4 pt-1">
                  {selected ? (
                    <>
                      <div className="mb-2 text-[13px] font-medium text-ink">{selected.label}</div>
                      <div className="mb-3 text-[10.5px] leading-relaxed text-mist">{selected.sublabel}</div>
                      <dl className="divide-y divide-veil/[0.05]">
                        {(selected.meta || []).map((row) => (
                          <div key={row.label} className="grid grid-cols-[92px_1fr] gap-2 py-1.5">
                            <dt className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{row.label}</dt>
                            <dd className="min-w-0 break-words text-[10.5px] leading-relaxed text-ink">{row.value}</dd>
                          </div>
                        ))}
                      </dl>
                      {selected.link && (
                        <Link to={selected.link} className="mt-3 inline-flex items-center gap-1 font-mono text-[8.5px] uppercase tracking-[0.12em] text-ion hover:text-crystal">
                          Open record <ArrowRight size={10} />
                        </Link>
                      )}
                    </>
                  ) : (
                    <>
                      <div className="mb-2 text-[13px] font-medium leading-snug text-ink">{detail.alert.title}</div>
                      <div className="flex flex-wrap items-center gap-1.5">
                        <SeverityBadge severity={detail.alert.severity} />
                        <StatusBadge status={detail.alert.status} />
                      </div>
                      <div className="mt-3 grid grid-cols-2 gap-2">
                        <div className="rounded-lg border border-line bg-shade/20 px-2.5 py-2">
                          <div className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">Risk</div>
                          <div className="tnum mt-1 font-display text-[20px] font-semibold" style={{ color: riskColor(detail.alert.risk_score) }}>
                            {Number(detail.alert.risk_score ?? 0).toFixed(1)}
                          </div>
                        </div>
                        <div className="rounded-lg border border-line bg-shade/20 px-2.5 py-2">
                          <div className="font-mono text-[8px] uppercase tracking-[0.12em] text-dim">Confidence</div>
                          <div className="tnum mt-1 font-display text-[20px] font-semibold text-ink">
                            {detail.alert.confidence != null ? `${Number(detail.alert.confidence).toFixed(0)}%` : "—"}
                          </div>
                        </div>
                      </div>
                      <p className="mt-3 text-[10.5px] leading-relaxed text-mist">{detail.alert.trigger_reason}</p>
                      <div className="mt-3">
                        <SectionLabel>Recorded evidence</SectionLabel>
                        <EvidenceList items={detail.alert.evidence} empty="No structured evidence was attached." />
                      </div>
                    </>
                  )}
                </div>
              </Panel>

              <Panel>
                <PanelHead title="Rule provenance" kicker="Deterministic detection" right={<ShieldCheck size={14} className="text-dim" />} />
                <div className="px-4 pb-4 pt-1">
                  <div className="text-[11.5px] text-ink">{detail.rule?.name || titleCase(detail.alert.rule_key)}</div>
                  <div className="mt-0.5 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{detail.rule?.key || detail.alert.rule_key}</div>
                  <p className="mt-2 text-[10.5px] leading-relaxed text-mist">{detail.rule?.logic || "Logic is recorded with the deterministic rule engine."}</p>
                  <div className="mt-2.5 flex items-center justify-between rounded-md border border-line bg-shade/20 px-2.5 py-1.5 font-mono text-[8px] uppercase tracking-[0.08em] text-dim">
                    <span>Severity policy</span>
                    <span className="text-ink">{detail.rule?.severity || titleCase(detail.alert.severity)}</span>
                  </div>
                </div>
              </Panel>
            </div>
          </div>

          <div className="grid gap-4 xl:grid-cols-12">
            <Panel className="xl:col-span-5">
              <PanelHead title="Decision timeline" kicker="Publication, detection, analyst action" right={<Route size={14} className="text-dim" />} />
              <div className="px-4 pb-4 pt-2">
                <Timeline events={timeline} />
              </div>
            </Panel>

            <Panel className="xl:col-span-7">
              <PanelHead
                title="Source coverage matrix"
                kicker="Registered connectors against this chain"
                right={<span className="chip">{sources.filter((source) => `${detail.alert.source || ""} ${detail.threat?.source || ""}`.toLowerCase().includes(String(source.name).toLowerCase())).length} in chain</span>}
              />
              <div className="overflow-x-auto px-3 pb-3">
                {!sources.length ? (
                  <EmptyState icon={<Link2 size={18} />} title="No connectors registered" detail="Provenance still renders the recorded alert evidence and rule." />
                ) : (
                  <table className="table-shell min-w-[460px]">
                    <thead>
                      <tr>
                        <th>Connector</th>
                        <th>Status</th>
                        <th>Reliability</th>
                        <th className="text-right">Items</th>
                        <th className="text-right">In chain</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sources.map((source) => {
                        const used = chainSourceText.includes(String(source.name).toLowerCase()) || chainSourceText.includes(String(source.key).toLowerCase());
                        return (
                          <tr key={source.key} className={used ? "bg-ion/[0.03]" : undefined}>
                            <td className="max-w-[180px]">
                              <div className="truncate text-[11px] text-ink">{source.name}</div>
                              <div className="font-mono text-[8px] uppercase tracking-[0.08em] text-dim">{source.category}</div>
                            </td>
                            <td><StatusBadge status={source.status} /></td>
                            <td>
                              <div className="flex items-center gap-2">
                                <MiniBar value={source.reliability * 100} color={source.reliability >= 0.8 ? "#42c98a" : source.reliability >= 0.6 ? "#ffd166" : "#ff963d"} />
                                <span className="tnum font-mono text-[9px] text-dim">{(source.reliability * 100).toFixed(0)}%</span>
                              </div>
                            </td>
                            <td className="tnum text-right font-mono text-[9.5px] text-mist">{fmtNumber(source.items_ingested)}</td>
                            <td className="text-right">
                              <span className={clsx("inline-flex h-[18px] items-center rounded-[4px] border px-1.5 font-mono text-[8px] uppercase tracking-[0.1em]", used ? "border-ion/30 bg-ion/10 text-ion" : "border-veil/10 bg-veil/[0.03] text-dim")}>
                                {used ? "yes" : "no"}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
                <p className="mt-2 px-1 text-[9.5px] leading-relaxed text-dim">
                  Coverage marks whether the connector name appears in the source strings recorded on the selected alert and threat. It does not claim the connector currently retrieves from a live endpoint.
                </p>
                <div className="mt-2 flex justify-end">
                  <Link to="/app/sources" className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-ion">Sources &amp; ingestion →</Link>
                </div>
              </div>
            </Panel>
          </div>

          <div className="grid gap-4 xl:grid-cols-12">
            <Panel className="xl:col-span-7">
              <PanelHead
                title="Risk factor provenance"
                kicker={assessment ? `${assessment.ref} · stored assessment` : breakdown ? "Live engine breakdown · no stored assessment" : "No risk record"}
                right={<span className="chip">{[...new Set(factors.map((factor: any) => factor.model_version).filter(Boolean))][0] || assessment?.model_version || breakdown?.model_version || "—"}</span>}
              />
              <div className="px-3 pb-3 pt-2">
                {factors.length ? (
                  <>
                    <Waterfall
                      items={factors.map((factor: any, index: number) => ({
                        label: factor.label || factor.key,
                        value: Number(factor.contribution ?? 0),
                        color: ["#ff963d", "#ff4d5e", "#9a8cff", "#49b8ff", "#64d8ff"][index % 5],
                        note: factor.note,
                      }))}
                      total={Number(riskTotal)}
                      height={280}
                    />
                    <div className="mt-2 flex flex-wrap items-center justify-between gap-2 px-1">
                      <span className="text-[9.5px] leading-relaxed text-dim">
                        Contributions are weight × normalised factor × 10. {assessment ? "This assessment is stored with the record." : "The selected alert has no stored assessment; the live breakdown reflects the current configured weights."}
                      </span>
                      <Link to="/app/risk" className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-ion">Risk model →</Link>
                    </div>
                  </>
                ) : (
                  <EmptyState
                    icon={<Waypoints size={18} />}
                    title="No factor record for this chain"
                    detail="The alert is not linked to a scored threat, so there is no risk breakdown to attribute."
                  />
                )}
              </div>
            </Panel>

            <div className="space-y-4 xl:col-span-5">
              <Panel>
                <PanelHead title="Linked recommendation" kicker="Human-controlled response" right={<Boxes size={14} className="text-dim" />} />
                <div className="px-4 pb-4 pt-1">
                  {detail.recommendations?.length ? (
                    <div className="space-y-2">
                      {detail.recommendations.slice(0, 2).map((rec: any) => (
                        <div key={rec.id} className="rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono text-[9px] uppercase tracking-[0.08em] text-dim">{rec.ref}</span>
                            <StatusBadge status={rec.status} />
                          </div>
                          <div className="mt-1 text-[11.5px] text-ink">{rec.title}</div>
                          <p className="mt-1 text-[10px] leading-relaxed text-mist">{rec.action}</p>
                          <div className="mt-2 flex items-center gap-3 font-mono text-[8px] uppercase tracking-[0.08em] text-dim">
                            <span>Priority <span className="text-ink">{titleCase(rec.priority)}</span></span>
                            <span>Due <span className="text-ink">{fmtDate(rec.due_at)}</span></span>
                          </div>
                        </div>
                      ))}
                      <Link to="/app/recommendations" className="inline-flex items-center gap-1 font-mono text-[8.5px] uppercase tracking-[0.12em] text-ion">
                        Open recommendations <ArrowRight size={10} />
                      </Link>
                    </div>
                  ) : (
                    <p className="text-[10.5px] leading-relaxed text-mist">No recommendation is linked to this alert. Detection never dispatches containment on its own.</p>
                  )}
                </div>
              </Panel>

              <InlineNotice tone="violet" title="Provenance, not attribution">
                A chain shows how this deployment reached a warning, using records it stored. It does not attribute activity to a person, organisation or state, and it does not upgrade a text match into confirmed exploitation.
                <span className="mt-2 flex items-center gap-1.5 font-mono text-[8px] uppercase tracking-[0.1em] text-violet/80">
                  <GitFork size={10} /> {riskTotal ? `risk ${Number(riskTotal).toFixed(1)} / 100` : "no risk record"} · {detail.alert.source || "source not recorded"}
                </span>
              </InlineNotice>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
