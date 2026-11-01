import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Boxes,
  Eye,
  EyeOff,
  GitFork,
  Layers,
  Link2,
  Maximize2,
  Minimize2,
  Network,
  PanelRightClose,
  PanelRightOpen,
  RefreshCw,
  Route,
  Search,
  X,
} from "lucide-react";
import clsx from "clsx";
import { api, qs } from "../../lib/api";
import { fmtDate, fmtNumber, fmtPct, relTime, riskColor } from "../../lib/format";
import { useAuth } from "../../context/AuthContext";
import {
  EmptyState,
  ErrorState,
  InlineNotice,
  Kpi,
  LoadingBlock,
  PageHeader,
  Panel,
  RangeTabs,
  SeverityBadge,
  useToast,
} from "../../components/ui";
import { CorrelationGraph } from "../../components/charts";
import { ScoreChip } from "./shared";

type Node = {
  id: string;
  ref?: string;
  name: string;
  severity?: string;
  risk?: number;
  degree?: number;
  category?: string;
  technology?: string;
  published_at?: string;
  saved?: boolean;
  [key: string]: any;
};

type Edge = {
  id?: string;
  source: string;
  target: string;
  score: number;
  reasons?: Array<{ type?: string; label: string; weight?: number }>;
};

function shortestPath(nodes: Node[], edges: Edge[], from: string | null, to: string | null) {
  if (!from || !to || from === to) return null;
  const valid = new Set(nodes.map((node) => node.ref || node.id));
  if (!valid.has(from) || !valid.has(to)) return null;
  const adjacency = new Map<string, Array<{ id: string; edge: Edge }>>();
  edges.forEach((edge) => {
    if (!valid.has(edge.source) || !valid.has(edge.target)) return;
    if (!adjacency.has(edge.source)) adjacency.set(edge.source, []);
    if (!adjacency.has(edge.target)) adjacency.set(edge.target, []);
    adjacency.get(edge.source)!.push({ id: edge.target, edge });
    adjacency.get(edge.target)!.push({ id: edge.source, edge });
  });
  const queue = [from];
  const previous = new Map<string, { id: string; edge: Edge } | null>([[from, null]]);
  while (queue.length) {
    const current = queue.shift()!;
    if (current === to) break;
    for (const next of adjacency.get(current) || []) {
      if (previous.has(next.id)) continue;
      previous.set(next.id, { id: current, edge: next.edge });
      queue.push(next.id);
    }
  }
  if (!previous.has(to)) return { ids: [] as string[], edges: [] as Edge[], found: false };
  const ids: string[] = [];
  const pathEdges: Edge[] = [];
  let cursor: string | null = to;
  while (cursor) {
    ids.unshift(cursor);
    const entry = previous.get(cursor);
    if (!entry) break;
    pathEdges.unshift(entry.edge);
    cursor = entry.id;
  }
  return { ids, edges: pathEdges, found: true };
}

export default function Correlations() {
  const { can } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const [days, setDays] = useState("90");
  const [minScore, setMinScore] = useState("0.45");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [compareId, setCompareId] = useState<string>("");
  const [search, setSearch] = useState("");
  const [labels, setLabels] = useState(false);
  const [hideIsolated, setHideIsolated] = useState(false);
  const [inspectorOpen, setInspectorOpen] = useState(true);
  const [expanded, setExpanded] = useState(false);

  const params = { days, min_score: minScore };
  const query = useQuery({
    queryKey: ["correlation", params],
    queryFn: () => api<any>(`/analytics/correlation${qs(params)}`),
  });

  const data = query.data;
  const nodes: Node[] = data?.nodes || [];
  const edges: Edge[] = data?.edges || [];
  const clusters: any[] = data?.clusters || [];
  const stats = data?.stats || {};

  const selected = nodes.find((node) => (node.ref || node.id) === selectedId) || null;
  const connected = useMemo(
    () =>
      edges
        .filter((edge) => edge.source === selectedId || edge.target === selectedId)
        .map((edge) => {
          const otherId = edge.source === selectedId ? edge.target : edge.source;
          const other = nodes.find((node) => (node.ref || node.id) === otherId);
          return { ...edge, other };
        })
        .sort((a, b) => b.score - a.score),
    [edges, nodes, selectedId],
  );

  const path = useMemo(() => shortestPath(nodes, edges, selectedId, compareId || null), [nodes, edges, selectedId, compareId]);

  useEffect(() => {
    setCompareId("");
  }, [selectedId]);

  useEffect(() => {
    if (!expanded) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setExpanded(false);
    };
    window.addEventListener("keydown", onKey);
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = previous;
    };
  }, [expanded]);

  const rebuild = useMutation({
    mutationFn: () => api<any>("/analytics/correlation/rebuild?days=180", { method: "POST" }),
    onSuccess: (result) => {
      push("success", `Correlation graph rebuilt: ${fmtNumber(result.pairs ?? result.edges)} pair(s) across ${fmtNumber(result.threats ?? result.nodes)} records.`);
      queryClient.invalidateQueries({ queryKey: ["correlation"] });
    },
    onError: (error: any) => push("error", error.message || "The correlation rebuild could not complete."),
  });

  const selectNode = (node: Node) => setSelectedId(node.ref || node.id);
  const nodeLabel = (node: Node) => node.ref || node.name;

  return (
    <>
      <PageHeader
        title="Correlation network"
        kicker="Investigation workspace · shared-entity overlap"
        description="Weighted similarity across shared entities, indicators, affected products and publication proximity. An edge is a statistical observation about report overlap, not proof that incidents are connected."
        aside={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span><span className="text-ink">{fmtNumber(stats.nodes)}</span> nodes</span>
            <span><span className="text-ink">{fmtNumber(stats.edges)}</span> edges</span>
            <span><span className="text-ink">{fmtNumber(stats.clusters)}</span> clusters</span>
            <span>avg <span className="text-ink">{fmtPct(stats.avg_score, 0)}</span></span>
          </div>
        }
        actions={
          <>
            <RangeTabs
              value={days}
              onChange={setDays}
              options={[{ value: "30", label: "30D" }, { value: "90", label: "90D" }, { value: "180", label: "180D" }, { value: "365", label: "1Y" }]}
            />
            <select className="field h-[34px] w-[142px] text-[11px]" value={minScore} onChange={(event) => setMinScore(event.target.value)} aria-label="Minimum correlation score">
              <option value="0.3">Min score 0.30</option>
              <option value="0.45">Min score 0.45</option>
              <option value="0.6">Min score 0.60</option>
              <option value="0.75">Min score 0.75</option>
            </select>
            {can("analyst") && (
              <button className="btn btn-primary btn-sm" onClick={() => rebuild.mutate()} disabled={rebuild.isPending}>
                <RefreshCw size={13} className={rebuild.isPending ? "animate-spin" : undefined} /> {rebuild.isPending ? "Rebuilding…" : "Rebuild graph"}
              </button>
            )}
          </>
        }
      />

      <div className="mb-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Threat nodes" value={fmtNumber(stats.nodes)} detail={`${fmtNumber(stats.isolated_nodes)} with no qualifying link`} icon={<Network size={15} />} tone="ion" />
        <Kpi label="Correlated edges" value={fmtNumber(stats.edges)} detail={`minimum similarity ${fmtPct(Number(minScore), 0)}`} icon={<Link2 size={15} />} tone="violet" />
        <Kpi label="Clusters" value={fmtNumber(stats.clusters)} detail="Connected components at this threshold" icon={<Boxes size={15} />} tone="high" />
        <Kpi label="Average similarity" value={fmtPct(stats.avg_score, 1)} detail="Across retained edges" icon={<GitFork size={15} />} tone="low" />
      </div>

      {expanded && <div className="fixed inset-0 z-[80] bg-sunken/80 backdrop-blur-sm" onClick={() => setExpanded(false)} aria-hidden="true" />}

      <Panel
        ticks
        className={clsx(
          "overflow-hidden",
          expanded && "fixed inset-2 z-[90] flex h-[calc(100dvh-1rem)] min-h-0 flex-col border-line-strong bg-surface/95 shadow-[0_40px_120px_-40px_rgba(0,0,0,0.95)]",
        )}
      >
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2.5 sm:px-4">
          <div className="flex items-center gap-2">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ion opacity-50 motion-reduce:animate-none" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-ion" />
            </span>
            <span className="font-mono text-[9px] uppercase tracking-[0.16em] text-mist">Investigation graph</span>
            <span className="hidden font-mono text-[8px] uppercase tracking-[0.1em] text-dim sm:inline">force layout · {fmtNumber(nodes.length)} records</span>
          </div>

          <div className="ml-auto flex flex-wrap items-center gap-1.5">
            <label className="relative flex h-[31px] items-center">
              <Search size={12} className="pointer-events-none absolute left-2.5 text-dim" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key !== "Enter") return;
                  const needle = search.trim().toLowerCase();
                  const hit = nodes.find((node) => `${node.ref || ""} ${node.name || ""}`.toLowerCase().includes(needle));
                  if (hit) selectNode(hit);
                }}
                placeholder="Find record or entity"
                aria-label="Search entities in the correlation graph"
                className="field h-[31px] w-[168px] rounded-lg pl-7 pr-7 text-[11px]"
              />
              {search && (
                <button
                  type="button"
                  onClick={() => setSearch("")}
                  aria-label="Clear entity search"
                  className="absolute right-1.5 grid h-5 w-5 place-items-center rounded text-dim hover:text-ink"
                >
                  <X size={11} />
                </button>
              )}
            </label>

            <button
              type="button"
              aria-pressed={labels}
              onClick={() => setLabels((value) => !value)}
              className={clsx("btn btn-sm btn-ghost h-[31px] gap-1.5 px-2.5 font-mono text-[8.5px] uppercase tracking-[0.1em]", labels && "border-ion/30 text-ion")}
            >
              {labels ? <Eye size={12} /> : <EyeOff size={12} />}
              Labels
            </button>
            <button
              type="button"
              aria-pressed={hideIsolated}
              onClick={() => setHideIsolated((value) => !value)}
              className={clsx("btn btn-sm btn-ghost hidden h-[31px] gap-1.5 px-2.5 font-mono text-[8.5px] uppercase tracking-[0.1em] sm:inline-flex", hideIsolated && "border-ion/30 text-ion")}
            >
              <Layers size={12} />
              Isolated
            </button>
            {!expanded && (
              <button
                type="button"
                onClick={() => setInspectorOpen((value) => !value)}
                aria-pressed={inspectorOpen}
                aria-label={inspectorOpen ? "Hide inspector" : "Show inspector"}
                className={clsx("btn btn-sm btn-ghost h-[31px] px-2.5", inspectorOpen && "border-ion/30 text-ion")}
              >
                {inspectorOpen ? <PanelRightClose size={13} /> : <PanelRightOpen size={13} />}
                <span className="hidden lg:inline">Inspector</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => setExpanded((value) => !value)}
              className="btn btn-sm btn-ghost h-[31px] gap-1.5 px-2.5"
              aria-label={expanded ? "Exit full-screen graph" : "Expand graph to full screen"}
            >
              {expanded ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
              <span className="hidden sm:inline">{expanded ? "Exit" : "Expand"}</span>
            </button>
          </div>
        </div>

        <div className={clsx("flex min-h-0 flex-1 flex-col", ((!expanded && inspectorOpen) || (expanded && selectedId)) && "xl:flex-row")}>
          <div className={clsx("relative min-w-0 flex-1", expanded && "flex-1")}>
            {query.isError ? (
              <div className="p-4">
                <ErrorState message={(query.error as any)?.message} retry={() => query.refetch()} />
              </div>
            ) : query.isLoading ? (
              <div className="p-4">
                <LoadingBlock rows={9} label="Computing correlation graph" />
              </div>
            ) : !nodes.length ? (
              <EmptyState
                title="No correlations at this threshold"
                detail="Lower the minimum similarity or widen the observation window. No link is better than a fabricated one."
                icon={<GitFork size={19} />}
              />
            ) : (
              <CorrelationGraph
                nodes={nodes}
                edges={edges}
                height={expanded ? "100%" : "clamp(540px, calc(100vh - 330px), 860px)"}
                maxNodes={140}
                selectedId={selectedId}
                onSelect={selectNode}
                labels={labels}
                hideIsolated={hideIsolated}
                query={search}
                path={path?.ids || []}
                className={expanded ? "absolute inset-0" : undefined}
              />
            )}

            <div className="pointer-events-none absolute left-3 top-3 hidden flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-line/70 bg-sunken/55 px-2.5 py-1.5 font-mono text-[8px] uppercase tracking-[0.1em] text-dim backdrop-blur-md sm:flex">
              <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-low" /> low</span>
              <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-med" /> medium</span>
              <span className="flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-crit" /> critical</span>
              <span className="text-dim">node = stored record</span>
            </div>

            {search && (
              <div className="pointer-events-none absolute right-3 top-3 rounded-md border border-ion/25 bg-sunken/75 px-2 py-1 font-mono text-[8px] uppercase tracking-[0.12em] text-ion backdrop-blur-md">
                searching “{search.slice(0, 22)}”
              </div>
            )}
          </div>

          {((!expanded && inspectorOpen) || (expanded && selectedId)) && (
            <aside className="max-h-[46%] w-full shrink-0 overflow-y-auto border-t border-line xl:max-h-none xl:w-[352px] xl:border-l xl:border-t-0">
              {!selected ? (
                <div className="px-4 py-10 text-center">
                  <span className="mx-auto grid h-10 w-10 place-items-center rounded-full border border-line bg-shade/25 text-dim">
                    <Network size={16} />
                  </span>
                  <p className="mx-auto mt-3 max-w-[40ch] text-[10.5px] leading-relaxed text-dim">
                    Select a node to inspect its composite risk, degree and the evidence paths connecting it to other reports.
                    The graph renders stored records only.
                  </p>
                </div>
              ) : (
                <div>
                  <div className="border-b border-line px-4 py-3.5">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-ion">{selected.ref}</div>
                        <h2 className="mt-1 text-[13px] font-semibold leading-snug text-ink">{selected.name}</h2>
                        <div className="mt-1 font-mono text-[8px] uppercase tracking-[0.08em] text-dim">
                          {selected.category || "record"} · {selected.technology || "technology not stated"}
                        </div>
                      </div>
                      <SeverityBadge severity={selected.severity} />
                    </div>
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      <ScoreChip score={selected.risk} />
                      <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">{selected.degree} connection(s)</span>
                      {selected.saved && <span className="chip text-ion">saved</span>}
                      <span className="font-mono text-[8.5px] text-dim">published {fmtDate(selected.published_at)}</span>
                    </div>
                    <div className="mt-3 flex items-center gap-2">
                      <Link to={`/app/threats?focus=${selected.ref}`} className="btn btn-ghost btn-sm">Open record</Link>
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedId(null);
                          setCompareId("");
                        }}
                        className="btn btn-quiet btn-sm"
                      >
                        Clear
                      </button>
                    </div>
                  </div>

                  <div className="border-b border-line px-4 py-3.5">
                    <div className="flex items-center gap-1.5 font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">
                      <Route size={11} /> Trace a path
                    </div>
                    <p className="mt-1.5 text-[10px] leading-relaxed text-dim">
                      Shortest chain through retained edges only. No path is invented when the graph has none.
                    </p>
                    <select
                      value={compareId}
                      onChange={(event) => setCompareId(event.target.value)}
                      aria-label="Select a target record to trace a path"
                      className="field mt-2 h-[32px] text-[11px]"
                    >
                      <option value="">Select a target record…</option>
                      {nodes
                        .filter((node) => (node.ref || node.id) !== selectedId)
                        .slice(0, 200)
                        .map((node) => (
                          <option key={node.ref || node.id} value={node.ref || node.id}>
                            {node.ref || node.id} — {node.name?.slice(0, 48)}
                          </option>
                        ))}
                    </select>

                    {compareId && path && (
                      <div className="mt-2.5 rounded-lg border border-line bg-shade/20 p-2.5">
                        {!path.found ? (
                          <p className="text-[10px] leading-relaxed text-high">
                            No direct or indirect path exists between these records at the current threshold. They are not connected in this graph.
                          </p>
                        ) : (
                          <>
                            <div className="flex items-center justify-between gap-2 font-mono text-[8px] uppercase tracking-[0.1em] text-dim">
                              <span>{path.ids.length} nodes · {path.edges.length} step(s)</span>
                              <span className="text-ion">highlighted</span>
                            </div>
                            <ol className="mt-2 space-y-1">
                              {path.ids.map((id, index) => {
                                const node = nodes.find((entry) => (entry.ref || entry.id) === id);
                                const stepEdge = path.edges[index - 1];
                                return (
                                  <li key={id}>
                                    {index > 0 && (
                                      <div className="flex items-center gap-1 py-0.5 pl-1 font-mono text-[7.5px] uppercase tracking-[0.08em] text-dim">
                                        <span className="h-3 w-px bg-ion/35" />
                                        similarity {fmtPct(stepEdge?.score, 0)}
                                      </div>
                                    )}
                                    <button
                                      type="button"
                                      onClick={() => {
                                        setSelectedId(id);
                                        setCompareId("");
                                      }}
                                      className="flex w-full items-center gap-1.5 rounded px-1 py-0.5 text-left hover:bg-veil/[0.04]"
                                    >
                                      <span className="font-mono text-[8.5px] text-ion">{id}</span>
                                      <span className="truncate text-[10px] text-mist">{node?.name}</span>
                                    </button>
                                  </li>
                                );
                              })}
                            </ol>
                          </>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="px-4 py-3.5">
                    <div className="flex items-center justify-between">
                      <div className="font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">Connected evidence</div>
                      <span className="chip">{connected.length}</span>
                    </div>
                    {!connected.length ? (
                      <p className="mt-2 text-[10.5px] leading-relaxed text-dim">This node has no retained edges at the current threshold.</p>
                    ) : (
                      <div className="mt-2 max-h-[320px] space-y-1.5 overflow-y-auto pr-1">
                        {connected.map((edge) => (
                          <button
                            key={edge.id || `${edge.source}-${edge.target}`}
                            onClick={() => setSelectedId(edge.other?.ref || null)}
                            className="w-full rounded-md border border-line bg-shade/20 px-2.5 py-2 text-left transition-colors hover:border-ion/30 hover:bg-veil/[0.03]"
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span className="truncate font-mono text-[9px] text-ion">{edge.other?.ref}</span>
                              <span className="tnum shrink-0 font-mono text-[9px]" style={{ color: riskColor(edge.score * 100) }}>{fmtPct(edge.score, 0)}</span>
                            </div>
                            <div className="mt-0.5 truncate text-[10px] text-mist">{edge.other?.name}</div>
                            {!!edge.reasons?.length && (
                              <div className="mt-1 flex flex-wrap gap-1">
                                {edge.reasons.slice(0, 3).map((reason, index) => (
                                  <span key={index} className="chip h-fit py-[1px] text-[7.5px]">{reason.label}</span>
                                ))}
                              </div>
                            )}
                          </button>
                        ))}
                      </div>
                    )}
                    <p className="mt-3 border-t border-line pt-2.5 font-mono text-[7.5px] uppercase leading-relaxed tracking-[0.1em] text-dim">
                      Evidence from stored records · weighted Jaccard overlap · not attribution
                    </p>
                  </div>
                </div>
              )}
            </aside>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-4 py-2 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
          <span>{data?.generated_at ? `generated ${relTime(data.generated_at)}` : "graph generation pending"}</span>
          <span className="hidden sm:inline">scroll to zoom · drag to pan · double-click to fit</span>
          <span className="sm:hidden">+ and − zoom the graph · tap a node for detail</span>
          <span>edge weight = weighted Jaccard similarity</span>
        </div>
      </Panel>

      <div className="mt-4">
        <Panel>
          <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
            <div>
              <div className="panel-kicker">Connected components</div>
              <div className="panel-title mt-1">Clusters</div>
            </div>
            <span className="chip">{clusters.length}</span>
          </div>
          {!clusters.length ? (
            <p className="px-4 py-5 text-[11px] text-dim">No multi-record clusters qualify at this threshold.</p>
          ) : (
            <div className="flex snap-x gap-2.5 overflow-x-auto px-4 py-3 [scrollbar-width:thin]">
              {clusters.map((cluster) => (
                <button
                  key={cluster.id}
                  type="button"
                  onClick={() => setSelectedId(cluster.threat_refs?.[0] || null)}
                  className="w-[268px] shrink-0 snap-start rounded-xl border border-line bg-shade/20 p-3 text-left transition-colors hover:border-ion/30 hover:bg-veil/[0.03]"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="truncate text-[11px] text-ink">{cluster.label}</div>
                      <div className="mt-0.5 font-mono text-[8px] uppercase tracking-[0.08em] text-dim">
                        {cluster.size} records · {cluster.shared_cves || 0} shared CVE(s) · {cluster.shared_indicators || 0} indicators
                      </div>
                    </div>
                    <SeverityBadge severity={String(cluster.max_severity || "").toLowerCase()} />
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-1.5">
                    {(cluster.threat_refs || []).slice(0, 3).map((ref: string) => (
                      <span key={ref} className="chip">{ref}</span>
                    ))}
                    {(cluster.threat_refs || []).length > 3 && <span className="font-mono text-[8px] text-dim">+{(cluster.threat_refs || []).length - 3}</span>}
                  </div>
                </button>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <InlineNotice tone="ion" className="mt-4" title="Interpretation">
        Shared entities and indicators can occur for benign reasons such as a widely used library or a common hosting provider. Correlation supports investigation; it does not establish a common actor, campaign or confirmed incident.
      </InlineNotice>
    </>
  );
}
