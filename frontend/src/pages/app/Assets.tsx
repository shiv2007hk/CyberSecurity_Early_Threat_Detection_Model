import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Boxes,
  Download,
  FileUp,
  Globe2,
  Layers3,
  Network,
  Pencil,
  Plus,
  Server,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import clsx from "clsx";
import { api, downloadFile, qs, type Asset, type Paginated } from "../../lib/api";
import { fmtDate, fmtNumber, riskColor, titleCase } from "../../lib/format";
import { useAuth } from "../../context/AuthContext";
import {
  ConfirmDialog,
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
  RiskMeter,
  SearchField,
  SeverityBadge,
  StatusBadge,
  useToast,
} from "../../components/ui";
import { CorrelationGraph, DistributionDonut } from "../../components/charts";
import { PriorityMatrix, ScatterPlot, Treemap } from "../../components/analytics-charts";
import { DrawerSection, EvidenceList, FieldLabel, FilterSelect, ScoreChip, SectionLabel } from "./shared";

const CRITICALITY_LABELS = ["", "Minimal", "Low", "Moderate", "High", "Mission-critical"];

interface AssetFormState {
  name: string;
  category: string;
  organisation_id: string;
  identifier: string;
  software: string;
  software_version: string;
  os: string;
  exposure: string;
  criticality: number;
  business_importance: string;
  owner: string;
  notes: string;
}

const EMPTY_FORM: AssetFormState = {
  name: "",
  category: "Server",
  organisation_id: "",
  identifier: "",
  software: "",
  software_version: "",
  os: "",
  exposure: "internal",
  criticality: 3,
  business_importance: "standard",
  owner: "",
  notes: "",
};

function toForm(asset?: Asset | null): AssetFormState {
  if (!asset) return { ...EMPTY_FORM };
  return {
    name: asset.name || "",
    category: asset.category || "Server",
    organisation_id: asset.organisation_id ? String(asset.organisation_id) : "",
    identifier: asset.identifier || "",
    software: asset.software || "",
    software_version: asset.software_version || "",
    os: asset.os || "",
    exposure: asset.exposure || "internal",
    criticality: asset.criticality || 3,
    business_importance: asset.business_importance || "standard",
    owner: asset.owner || "",
    notes: asset.notes || "",
  };
}

function CriticalityPips({ value }: { value?: number }) {
  const level = Number(value || 0);
  return (
    <span className="inline-flex items-center gap-1" title={`Criticality ${level} of 5 — ${CRITICALITY_LABELS[level] || "unset"}`}>
      {[1, 2, 3, 4, 5].map((pip) => (
        <span
          key={pip}
          className={clsx(
            "h-[3px] w-3 rounded-full",
            pip <= level ? (level >= 4 ? "bg-high" : level === 3 ? "bg-med" : "bg-low") : "bg-veil/10",
          )}
        />
      ))}
    </span>
  );
}

export default function Assets() {
  const { can, user } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();

  const [q, setQ] = useState("");
  const [category, setCategory] = useState("all");
  const [exposureFilter, setExposureFilter] = useState("all");
  const [criticality, setCriticality] = useState("all");
  const [sortBy, setSortBy] = useState("risk_score");
  const [page, setPage] = useState(1);
  const [showGraph, setShowGraph] = useState(false);
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Asset | null>(null);
  const [form, setForm] = useState<AssetFormState>({ ...EMPTY_FORM });
  const [importOpen, setImportOpen] = useState(false);
  const [csvText, setCsvText] = useState("name,category,software,software_version,exposure,criticality,owner\n");
  const [deleteTarget, setDeleteTarget] = useState<Asset | null>(null);

  const focus = searchParams.get("focus");
  useEffect(() => setPage(1), [q, category, exposureFilter, criticality, sortBy]);

  const params = {
    q,
    category,
    exposure: exposureFilter,
    criticality,
    sort_by: sortBy,
    order: "desc",
    page,
    size: 20,
  };
  const listQuery = useQuery({
    queryKey: ["assets", params],
    queryFn: () => api<Paginated<Asset>>(`/assets${qs(params)}`),
  });
  const optionsQuery = useQuery({
    queryKey: ["asset-options"],
    queryFn: () => api<any>("/assets/options"),
    staleTime: 120_000,
  });
  const graphQuery = useQuery({
    queryKey: ["asset-graph"],
    queryFn: () => api<any>("/assets/graph"),
    enabled: showGraph,
  });
  const detailQuery = useQuery({
    queryKey: ["asset-detail", focus],
    queryFn: () => api<any>(`/assets/${focus}`),
    enabled: Boolean(focus),
  });
  const analyticsQuery = useQuery({
    queryKey: ["asset-analytics"],
    queryFn: () => api<Paginated<Asset>>(`/assets${qs({ size: 100, sort_by: "risk_score", order: "desc" })}`),
  });

  const data = listQuery.data;
  const detail = detailQuery.data;
  const asset: Asset | undefined = detail?.asset;
  const options = optionsQuery.data;

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
    queryClient.invalidateQueries({ queryKey: ["assets"] });
    queryClient.invalidateQueries({ queryKey: ["asset-graph"] });
    queryClient.invalidateQueries({ queryKey: ["asset-options"] });
    queryClient.invalidateQueries({ queryKey: ["exposure"] });
    queryClient.invalidateQueries({ queryKey: ["exposure-summary"] });
    queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  };

  const saveAsset = useMutation({
    mutationFn: () => {
      const payload = {
        ...form,
        organisation_id: form.organisation_id ? Number(form.organisation_id) : null,
        criticality: Number(form.criticality),
      };
      if (editing) return api<any>(`/assets/${editing.ref}`, { method: "PATCH", body: JSON.stringify(payload) });
      return api<any>("/assets", { method: "POST", body: JSON.stringify(payload) });
    },
    onSuccess: (result) => {
      push("success", editing ? "Asset record updated and rescanned." : `Asset ${result.asset?.ref || ""} added and rescanned.`);
      setFormOpen(false);
      setEditing(null);
      invalidate();
      queryClient.invalidateQueries({ queryKey: ["asset-detail", focus] });
    },
    onError: (error: any) => push("error", error.message || "The asset could not be saved."),
  });

  const removeAsset = useMutation({
    mutationFn: () => api(`/assets/${deleteTarget?.ref}`, { method: "DELETE" }),
    onSuccess: () => {
      push("success", "Asset removed from inventory.");
      setDeleteTarget(null);
      closeDrawer();
      invalidate();
    },
    onError: (error: any) => push("error", error.message || "The asset could not be deleted."),
  });

  const importAssets = useMutation({
    mutationFn: () => api<any>("/assets/import", { method: "POST", body: JSON.stringify({ csv_text: csvText }) }),
    onSuccess: (result) => {
      push("success", `${result.created} asset(s) imported${result.skipped?.length ? `, ${result.skipped.length} skipped` : ""}.`);
      if (result.skipped?.length) push("info", result.skipped.slice(0, 3).join(" · "));
      setImportOpen(false);
      invalidate();
    },
    onError: (error: any) => push("error", error.message || "Import failed. Check the header row and required columns."),
  });

  const exportCsv = async () => {
    try {
      await downloadFile(`/assets/export.csv${qs({ ...params, page: undefined, size: undefined })}`, "assets.csv");
      push("success", "Inventory export downloaded.");
    } catch (error: any) {
      push("error", error.message || "Export failed.");
    }
  };

  const stats = data?.stats || {};
  const facets = data?.facets || {};
  const categories: Array<{ name: string; count: number }> = facets.categories || [];
  const exposures: Array<{ name: string; count: number }> = facets.exposures || [];

  const inventoryAssets: Asset[] = analyticsQuery.data?.items || [];

  const exposureRiskMatrix = useMemo(() => {
    const rows: Array<[string, string]> = [
      ["internet-facing", "Internet-facing"],
      ["internal", "Internal"],
      ["air-gapped", "Air-gapped"],
    ];
    const bands = ["Critical", "High", "Medium", "Low"];
    const values = rows.map(([key]) =>
      bands.map((band) =>
        inventoryAssets.filter((item) => {
          const exposureKey = item.exposure || (item.internet_facing ? "internet-facing" : "internal");
          return exposureKey === key && item.risk?.risk_category === band;
        }).length,
      ),
    );
    return { rows: rows.map(([, label]) => label), cols: bands, values };
  }, [inventoryAssets]);

  const bubblePoints = useMemo(
    () =>
      inventoryAssets.map((item) => ({
        x: Number(item.criticality ?? 0),
        y: Number(item.risk?.risk_score ?? 0),
        size: 2.6 + Math.min(6, Number(item.risk?.validated_vulnerabilities ?? 0) * 1.3),
        color: riskColor(item.risk?.risk_score),
        label: item.ref,
        detail: `${item.name} · ${titleCase(item.exposure || "internal")} · ${Number(item.risk?.validated_vulnerabilities ?? 0)} validated match(es)`,
      })),
    [inventoryAssets],
  );

  const categoryTreemap = useMemo(() => {
    const grouped = new Map<string, { count: number; maxRisk: number; topCriticality: number }>();
    inventoryAssets.forEach((item) => {
      const entry = grouped.get(item.category) || { count: 0, maxRisk: 0, topCriticality: 0 };
      entry.count += 1;
      entry.maxRisk = Math.max(entry.maxRisk, Number(item.risk?.risk_score ?? 0));
      entry.topCriticality = Math.max(entry.topCriticality, Number(item.criticality ?? 0));
      grouped.set(item.category, entry);
    });
    return [...grouped.entries()].map(([name, entry]) => ({
      name,
      value: entry.count,
      color: riskColor(entry.maxRisk),
      detail: `${entry.count} asset(s) · highest risk ${entry.maxRisk.toFixed(0)} · top criticality ${entry.topCriticality}/5`,
      meta: `${entry.count} · risk ${entry.maxRisk.toFixed(0)}`,
    }));
  }, [inventoryAssets]);

  const exposureSplit = (facets.exposures || []).map((entry) => ({ name: titleCase(entry.name), value: entry.count }));

  const graphNodes = useMemo(() => {
    const rawNodes: any[] = graphQuery.data?.nodes || [];
    const rawEdges: any[] = graphQuery.data?.edges || [];
    const degree: Record<string, number> = {};
    rawEdges.forEach((edge) => {
      degree[edge.source] = (degree[edge.source] || 0) + 1;
      degree[edge.target] = (degree[edge.target] || 0) + 1;
    });
    return rawNodes.map((node) => ({
      ...node,
      id: node.id || node.ref,
      ref: node.ref,
      risk: node.risk_score,
      degree: degree[node.ref] || 0,
    }));
  }, [graphQuery.data]);
  const graphEdges = useMemo(
    () =>
      (graphQuery.data?.edges || []).map((edge: any) => ({
        source: edge.source,
        target: edge.target,
        score: 0.7,
        reasons: [{ label: edge.relation }],
      })),
    [graphQuery.data],
  );

  const matches: any[] = detail?.matches || [];

  return (
    <>
      <PageHeader
        title="Asset inventory & exposure"
        kicker="Inventory · exposure · criticality"
        description="Every registered asset, its software version and operator-assigned business criticality. Exposure is counted only when a product and version check validates a vulnerability against the asset."
        aside={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span><span className="text-ink">{fmtNumber(stats.total)}</span> assets</span>
            <span><span className="text-ink">{fmtNumber(stats.internet_facing)}</span> internet-facing</span>
            <span><span className="text-high">{fmtNumber(stats.validated_exposed)}</span> validated exposure</span>
            <span><span className="text-crit">{fmtNumber(stats.critical_assets)}</span> high criticality</span>
          </div>
        }
        actions={
          <>
            <button className={clsx("btn btn-sm", showGraph ? "btn-primary" : "btn-ghost")} onClick={() => setShowGraph((value) => !value)}>
              <Network size={13} /> Inventory map
            </button>
            <button className="btn btn-ghost btn-sm" onClick={exportCsv}><Download size={13} /> Export</button>
            {can("analyst") && (
              <>
                <button className="btn btn-ghost btn-sm" onClick={() => setImportOpen(true)}><FileUp size={13} /> Import CSV</button>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => { setEditing(null); setForm({ ...EMPTY_FORM }); setFormOpen(true); }}
                >
                  <Plus size={13} /> Add asset
                </button>
              </>
            )}
          </>
        }
      />

      <div className="mb-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Registered assets" value={fmtNumber(stats.total)} detail={`${fmtNumber(stats.internet_facing)} reachable from the internet`} icon={<Boxes size={15} />} tone="ion" />
        <Kpi label="Validated exposure" value={fmtNumber(stats.validated_exposed)} detail="Assets with product and version matches" icon={<ShieldAlert size={15} />} tone="high" />
        <Kpi label="High criticality" value={fmtNumber(stats.critical_assets)} detail="Criticality 4 or 5 of 5" icon={<Layers3 size={15} />} tone="crit" />
        <Kpi label="Recorded in range" value={fmtNumber(data?.total)} detail="Matches the current filter set" icon={<Server size={15} />} tone="violet" />
      </div>

      <Panel className="mb-4" ticks>
        <PanelHead
          title="Estate exposure analytics"
          kicker={`${fmtNumber(inventoryAssets.length)} assets · whole inventory`}
          right={<span className="chip">validated matches only</span>}
        />
        {analyticsQuery.isError ? (
          <ErrorState compact message={(analyticsQuery.error as any)?.message} retry={() => analyticsQuery.refetch()} />
        ) : analyticsQuery.isLoading ? (
          <LoadingBlock rows={6} label="Loading estate analytics" />
        ) : (
          <div className="grid gap-px bg-line [&>*]:min-w-0 xl:grid-cols-2">
            <div className="bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">highest validated risk</span>}>
                Exposure × risk band matrix
              </SectionLabel>
              <PriorityMatrix rows={exposureRiskMatrix.rows} cols={exposureRiskMatrix.cols} values={exposureRiskMatrix.values} height={150} />
              <p className="mt-2 text-[10px] leading-relaxed text-dim">
                Assets are placed by recorded exposure and the highest risk validated against them. Empty cells mean no asset currently occupies that combination.
              </p>
            </div>
            <div className="bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{exposureSplit.length} classes</span>}>
                Public vs internal placement
              </SectionLabel>
              <DistributionDonut
                data={exposureSplit}
                height={158}
                centerLabel="assets"
                centerValue={inventoryAssets.length}
                colors={["#49b8ff", "#ff963d", "#9a8cff"]}
              />
              <p className="mt-2 text-[10px] leading-relaxed text-dim">
                Exposure is an operator-recorded property of the asset, not an inference from scan traffic. Internet-facing assets carry the higher exposure factor in scoring.
              </p>
            </div>
            <div className="bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{bubblePoints.length} plotted</span>}>
                Criticality × risk bubble
              </SectionLabel>
              <ScatterPlot
                points={bubblePoints}
                height={244}
                xLabel="Criticality (1–5)"
                yLabel="Risk score"
                xMax={5}
                yMax={100}
                quadrants={["Contain first", "", "", "Baseline"]}
                emptyLabel="No inventory assets to plot."
              />
              <p className="mt-1 text-[10px] leading-relaxed text-dim">
                Bubble size is the number of validated vulnerable products on the asset. Position combines business weight with the strongest validated risk.
              </p>
            </div>
            <div className="bg-surface p-4">
              <SectionLabel right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">tile = asset count</span>}>
                Category treemap · highest risk colour
              </SectionLabel>
              <Treemap items={categoryTreemap} height={244} emptyLabel="No assets registered." />
              <p className="mt-1 text-[10px] leading-relaxed text-dim">
                Tile area is the number of assets in each category; colour marks the highest validated risk found inside that category.
              </p>
            </div>
          </div>
        )}
      </Panel>

      {showGraph && (
        <Panel className="mb-4">
          <PanelHead
            title="Inventory relationship map"
            kicker="Shared software and organisational grouping"
            right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">select a node to open the asset</span>}
          />
          {graphQuery.isError ? (
            <ErrorState message={(graphQuery.error as any)?.message} retry={() => graphQuery.refetch()} compact />
          ) : graphQuery.isLoading ? (
            <LoadingBlock rows={5} label="Building inventory map" />
          ) : (
            <>
              <CorrelationGraph nodes={graphNodes} edges={graphEdges} height={380} maxNodes={60} selectedId={focus || undefined} onSelect={(node) => node.ref && openDrawer(node.ref)} />
              <div className="border-t border-line px-4 py-2 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{graphQuery.data?.note}</div>
            </>
          )}
        </Panel>
      )}

      <Panel className="mb-4">
        <div className="grid gap-3 p-3.5 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-[minmax(230px,1.5fr)_repeat(3,minmax(130px,0.8fr))_minmax(130px,0.7fr)]">
          <div>
            <span className="field-label">Search</span>
            <SearchField value={q} onChange={setQ} placeholder="Asset, identifier, software, owner…" />
          </div>
          <FilterSelect
            label="Category"
            value={category}
            onChange={setCategory}
            options={[{ value: "all", label: `All categories (${fmtNumber(stats.total)})` }, ...categories.map((item) => ({ value: item.name, label: `${item.name} (${item.count})` }))]}
          />
          <FilterSelect
            label="Exposure"
            value={exposureFilter}
            onChange={setExposureFilter}
            options={[{ value: "all", label: "Any exposure" }, ...exposures.map((item) => ({ value: item.name, label: `${titleCase(item.name)} (${item.count})` }))]}
          />
          <FilterSelect
            label="Criticality"
            value={criticality}
            onChange={setCriticality}
            options={[
              { value: "all", label: "Any criticality" },
              { value: "4,5", label: "High & mission-critical" },
              { value: "3", label: "Moderate" },
              { value: "1,2", label: "Low & minimal" },
            ]}
          />
          <FilterSelect
            label="Sort"
            value={sortBy}
            onChange={setSortBy}
            options={[
              { value: "risk_score", label: "Risk score" },
              { value: "name", label: "Name" },
              { value: "criticality", label: "Criticality" },
              { value: "software", label: "Software" },
              { value: "created_at", label: "Recently added" },
            ]}
          />
        </div>
      </Panel>

      <Panel>
        {listQuery.isError ? (
          <ErrorState message={(listQuery.error as any)?.message} retry={() => listQuery.refetch()} />
        ) : listQuery.isLoading ? (
          <LoadingBlock rows={9} label="Loading asset inventory" />
        ) : !data?.items.length ? (
          <EmptyState
            title="No assets match this view"
            detail="Register assets with their software and version so exposure matching can validate vulnerabilities against real inventory rather than assumptions."
            icon={<Boxes size={19} />}
            action={can("analyst") ? <button className="btn btn-primary btn-sm" onClick={() => setFormOpen(true)}><Plus size={12} /> Add the first asset</button> : undefined}
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table-shell">
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th className="hidden lg:table-cell">Running software</th>
                    <th>Exposure</th>
                    <th>Criticality</th>
                    <th className="hidden xl:table-cell">Validated</th>
                    <th>Risk</th>
                    <th className="hidden md:table-cell">Owner</th>
                    <th className="hidden sm:table-cell">Last assessed</th>
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
                              <span className="truncate text-[12px] text-ink">{item.name}</span>
                            </div>
                            <div className="mt-0.5 truncate font-mono text-[8px] uppercase tracking-[0.06em] text-dim">
                              {item.category}{item.organisation?.name ? ` · ${item.organisation.name}` : ""}{item.identifier ? ` · ${item.identifier}` : ""}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="hidden lg:table-cell">
                        <div className="text-[11px] text-ink">{item.software || "—"}</div>
                        <div className="mt-0.5 font-mono text-[8.5px] text-dim">{item.software_version || "version unknown"}{item.os ? ` · ${item.os}` : ""}</div>
                      </td>
                      <td>
                        <span className={clsx("font-mono text-[9px] uppercase tracking-[0.08em]", item.internet_facing ? "text-high" : "text-dim")}>
                          {item.internet_facing ? <Globe2 size={10} className="mr-1 inline" /> : null}
                          {titleCase(item.exposure)}
                        </span>
                      </td>
                      <td><CriticalityPips value={item.criticality} /></td>
                      <td className="hidden xl:table-cell">
                        <div className="flex items-center gap-2 font-mono text-[9px] text-dim">
                          <span className="text-ink">{item.risk?.validated_vulnerabilities ?? 0}</span> validated
                          {!!item.risk?.needs_verification && <span className="text-med">· {item.risk.needs_verification} verify</span>}
                          {!!item.risk?.known_exploited && <span className="text-high">· KEV</span>}
                        </div>
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <span className="tnum font-mono text-[11.5px]" style={{ color: riskColor(item.risk?.risk_score) }}>{Number(item.risk?.risk_score ?? 0).toFixed(0)}</span>
                          <div className="w-10"><ProgressBar value={Number(item.risk?.risk_score ?? 0)} color={riskColor(item.risk?.risk_score)} height={3} /></div>
                        </div>
                        <div className="mt-0.5 font-mono text-[8px] uppercase tracking-[0.06em] text-dim">{item.risk?.risk_category || "No validated exposure"}</div>
                      </td>
                      <td className="hidden md:table-cell"><span className="text-[10.5px] text-mist">{item.owner || "Unassigned"}</span></td>
                      <td className="hidden sm:table-cell"><span className="font-mono text-[9px] text-dim">{fmtDate(item.last_assessed_at)}</span></td>
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
            <span className="text-[15px] font-semibold text-ink">{asset?.name || focus}</span>
            {asset && <span className="chip">{asset.ref}</span>}
          </div>
        }
        subtitle={
          asset && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
              <span>{asset.category}</span><span>·</span>
              <span>{titleCase(asset.exposure)}</span><span>·</span>
              <span>criticality {asset.criticality}/5</span>
              {asset.organisation?.name && <><span>·</span><span>{asset.organisation.name}</span></>}
            </div>
          )
        }
        footer={
          can("analyst") && asset ? (
            <>
              {can("admin") && (
                <button className="btn btn-danger btn-sm mr-auto" onClick={() => setDeleteTarget(asset)}>
                  <Trash2 size={12} /> Remove
                </button>
              )}
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => { setEditing(asset); setForm(toForm(asset)); setFormOpen(true); }}
              >
                <Pencil size={12} /> Edit inventory record
              </button>
            </>
          ) : (
            <span className="mr-auto font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">Read-only — analysts can edit inventory</span>
          )
        }
      >
        {detailQuery.isError ? (
          <ErrorState message={(detailQuery.error as any)?.message} retry={() => detailQuery.refetch()} compact />
        ) : detailQuery.isLoading || !asset ? (
          <LoadingBlock rows={8} label="Loading asset record" />
        ) : (
          <div>
            <div className="mb-4 flex items-center justify-between gap-4 rounded-xl border border-line bg-shade/25 px-4 py-3.5">
              <div>
                <div className="panel-kicker">Explainable asset risk</div>
                <div className="mt-1 font-display text-[20px] font-semibold text-ink">{asset.risk?.risk_category || "No validated exposure"}</div>
                <p className="mt-1 max-w-[42ch] text-[10.5px] leading-relaxed text-dim">
                  Highest version-validated vulnerability score across the inventory. Unverified name matches are excluded.
                </p>
              </div>
              <RiskMeter score={asset.risk?.risk_score} size={76} />
            </div>

            <div className="grid gap-2 sm:grid-cols-3">
              <div className="rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                <div className="panel-kicker">Validated matches</div>
                <div className="tnum mt-1 font-display text-[20px] font-semibold text-ink">{asset.risk?.validated_vulnerabilities ?? 0}</div>
              </div>
              <div className="rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                <div className="panel-kicker">Awaiting verification</div>
                <div className="tnum mt-1 font-display text-[20px] font-semibold text-med">{asset.risk?.needs_verification ?? 0}</div>
              </div>
              <div className="rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                <div className="panel-kicker">Known-exploited matches</div>
                <div className="tnum mt-1 font-display text-[20px] font-semibold text-high">{asset.risk?.known_exploited ?? 0}</div>
              </div>
            </div>

            <DrawerSection title="Inventory attributes" kicker="Operator-supplied context">
              <dl className="grid gap-x-4 gap-y-2 sm:grid-cols-2">
                {[
                  ["Software", `${asset.software || "—"} ${asset.software_version || ""}`.trim()],
                  ["Operating system", asset.os || "—"],
                  ["Identifier", asset.identifier || "—"],
                  ["Business importance", titleCase(asset.business_importance)],
                  ["Owner", asset.owner || "Unassigned"],
                  ["Organisation", asset.organisation?.name || "—"],
                  ["Exposure", titleCase(asset.exposure)],
                  ["Last assessed", fmtDate(asset.last_assessed_at)],
                ].map(([label, value]) => (
                  <div key={label} className="border-b border-veil/[0.05] pb-1.5">
                    <dt className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{label}</dt>
                    <dd className="mt-0.5 break-words text-[11.5px] text-ink">{value}</dd>
                  </div>
                ))}
              </dl>
              {asset.notes && <p className="mt-3 whitespace-pre-line rounded-md border border-line bg-shade/20 px-3 py-2 text-[11px] leading-relaxed text-mist">{asset.notes}</p>}
            </DrawerSection>

            <DrawerSection title="Validated exposure matches" kicker="Product and version checks passed" right={<span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{matches.length} row(s)</span>}>
              {!matches.length ? (
                <p className="text-[11px] text-dim">No vulnerability currently validates against this exact software version.</p>
              ) : (
                <div className="space-y-1.5">
                  {matches.map((match) => (
                    <div key={match.id} className="rounded-md border border-line bg-shade/20 px-3 py-2.5">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex min-w-0 items-center gap-2">
                          <Link to={`/app/vulnerabilities?focus=${match.vulnerability.cve_id}`} className="font-mono text-[10px] text-info hover:text-ion">
                            {match.vulnerability.cve_id}
                          </Link>
                          <span className="truncate text-[11px] text-ink">{match.vulnerability.title}</span>
                        </div>
                        <div className="flex shrink-0 items-center gap-2">
                          <SeverityBadge severity={match.vulnerability.cvss_severity} />
                          <StatusBadge status={match.status} />
                        </div>
                      </div>
                      <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">
                        <span>CVSS {match.vulnerability.cvss ?? "—"}</span>
                        <span>EPSS {match.vulnerability.epss != null ? `${(match.vulnerability.epss * 100).toFixed(0)}%` : "—"}</span>
                        <span>confidence {Math.round(match.confidence || 0)}%</span>
                        {match.vulnerability.known_exploited && <span className="text-high">known exploited</span>}
                      </div>
                      <p className="mt-1 text-[10.5px] leading-relaxed text-dim">{match.reason}</p>
                    </div>
                  ))}
                </div>
              )}
            </DrawerSection>

            <DrawerSection title="Remediation recommendations" kicker="Advisory actions" right={<Link to="/app/recommendations" className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-ion">Open workflow</Link>}>
              {!detail.recommendations?.length ? (
                <p className="text-[11px] text-dim">No recommendation is attached to this asset.</p>
              ) : (
                <div className="space-y-1.5">
                  {detail.recommendations.map((rec: any) => (
                    <div key={rec.id} className="flex items-center justify-between gap-3 rounded-md border border-line bg-shade/20 px-3 py-2">
                      <div className="min-w-0">
                        <div className="font-mono text-[8px] text-dim">{rec.ref}</div>
                        <div className="truncate text-[11px] text-ink">{rec.title}</div>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <SeverityBadge severity={rec.priority} />
                        <StatusBadge status={rec.status} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </DrawerSection>

            {!!detail.alerts?.length && (
              <DrawerSection title="Related early warnings" kicker="Alert history">
                <div className="space-y-1.5">
                  {detail.alerts.map((alert: any) => (
                    <Link key={alert.id} to={`/app/alerts?focus=${alert.ref}`} className="flex items-center justify-between gap-3 rounded-md border border-line bg-shade/20 px-3 py-2 hover:border-ion/30">
                      <div className="min-w-0">
                        <div className="font-mono text-[8px] text-dim">{alert.ref}</div>
                        <div className="truncate text-[11px] text-ink">{alert.title}</div>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <SeverityBadge severity={alert.severity} />
                        <StatusBadge status={alert.status} />
                      </div>
                    </Link>
                  ))}
                </div>
              </DrawerSection>
            )}

            {!!detail.assessments?.length && (
              <DrawerSection title="Assessment history" kicker="Explainable scoring">
                <div className="space-y-1.5">
                  {detail.assessments.map((assessment: any) => (
                    <Link key={assessment.id} to={`/app/risk?assessment=${assessment.id}`} className="flex items-center justify-between gap-3 rounded-md border border-line bg-shade/20 px-3 py-2 hover:border-ion/30">
                      <div className="min-w-0">
                        <div className="font-mono text-[8px] text-dim">{assessment.ref} · {fmtDate(assessment.created_at)}</div>
                        <div className="truncate text-[11px] text-ink">{assessment.threat?.name || assessment.explanation?.slice(0, 90) || "Assessment"}</div>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <StatusBadge status={assessment.urgency} />
                        <ScoreChip score={assessment.risk_score} />
                      </div>
                    </Link>
                  ))}
                </div>
              </DrawerSection>
            )}

            {!!detail.notes?.length && (
              <DrawerSection title="Analyst notes" kicker="Investigation record">
                <div className="space-y-1.5">
                  {detail.notes.map((note: any) => (
                    <div key={note.id} className="rounded-md border border-line bg-shade/20 px-3 py-2">
                      <div className="font-mono text-[8px] uppercase tracking-[0.08em] text-dim">
                        {note.author?.full_name || "Analyst"} · {fmtDate(note.created_at, true)}
                      </div>
                      <p className="mt-1 whitespace-pre-line text-[11px] leading-relaxed text-mist">{note.body}</p>
                    </div>
                  ))}
                </div>
              </DrawerSection>
            )}

            {!!detail.related_assets?.length && (
              <DrawerSection title="Assets sharing this software" kicker="Potential common-mode exposure">
                <div className="grid gap-1.5 sm:grid-cols-2">
                  {detail.related_assets.map((peer: any) => (
                    <button key={peer.ref} onClick={() => openDrawer(peer.ref)} className="rounded-md border border-line bg-shade/20 px-3 py-2 text-left hover:border-ion/30">
                      <div className="font-mono text-[8px] text-dim">{peer.ref}</div>
                      <div className="truncate text-[11px] text-ink">{peer.name}</div>
                      <div className="mt-0.5 font-mono text-[8.5px] text-dim">{peer.software} {peer.software_version}</div>
                    </button>
                  ))}
                </div>
              </DrawerSection>
            )}

            <InlineNotice tone="ion" className="mt-3" title="Matching methodology">{detail.methodology}</InlineNotice>
          </div>
        )}
      </Drawer>

      <Modal
        open={formOpen}
        onClose={() => { setFormOpen(false); setEditing(null); }}
        title={editing ? `Edit ${editing.ref}` : "Register an asset"}
        description="Software and version are used by exposure matching. Business criticality is an operator judgement, not a technical measurement."
        className="max-w-[720px]"
        footer={
          <>
            <button className="btn btn-ghost" onClick={() => { setFormOpen(false); setEditing(null); }}>Cancel</button>
            <button
              className="btn btn-primary"
              disabled={saveAsset.isPending || form.name.trim().length < 2 || !form.software.trim()}
              onClick={() => saveAsset.mutate()}
            >
              {saveAsset.isPending ? "Saving…" : editing ? "Save changes" : "Add to inventory"}
            </button>
          </>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <FieldLabel label="Asset name" className="sm:col-span-2">
            <input className="field" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="e.g. Billing application server" maxLength={160} />
          </FieldLabel>
          <FieldLabel label="Category">
            <select className="field" value={form.category} onChange={(event) => setForm({ ...form, category: event.target.value })}>
              {(options?.categories || ["Server"]).map((value: string) => <option key={value} value={value}>{value}</option>)}
            </select>
          </FieldLabel>
          <FieldLabel label="Organisation">
            <select className="field" value={form.organisation_id} onChange={(event) => setForm({ ...form, organisation_id: event.target.value })}>
              <option value="">Default organisation</option>
              {(options?.organisations || []).map((org: any) => <option key={org.id} value={org.id}>{org.name}</option>)}
            </select>
          </FieldLabel>
          <FieldLabel label="Asset identifier" hint="Hostname, serial or inventory tag">
            <input className="field" value={form.identifier} onChange={(event) => setForm({ ...form, identifier: event.target.value })} maxLength={120} />
          </FieldLabel>
          <FieldLabel label="Owner">
            <input className="field" value={form.owner} onChange={(event) => setForm({ ...form, owner: event.target.value })} maxLength={120} placeholder="Team or accountable owner" />
          </FieldLabel>
          <FieldLabel label="Software" hint="Product identity used for matching">
            <input className="field" value={form.software} onChange={(event) => setForm({ ...form, software: event.target.value })} maxLength={120} placeholder="e.g. nginx" />
          </FieldLabel>
          <FieldLabel label="Installed version" hint="Required to verify affected ranges">
            <input className="field" value={form.software_version} onChange={(event) => setForm({ ...form, software_version: event.target.value })} maxLength={60} placeholder="e.g. 1.24.0" />
          </FieldLabel>
          <FieldLabel label="Operating system">
            <input className="field" value={form.os} onChange={(event) => setForm({ ...form, os: event.target.value })} maxLength={100} placeholder="e.g. Ubuntu 24.04" />
          </FieldLabel>
          <FieldLabel label="Exposure">
            <select className="field" value={form.exposure} onChange={(event) => setForm({ ...form, exposure: event.target.value })}>
              {(options?.exposures || ["air-gapped", "internal", "internet-facing"]).map((value: string) => <option key={value} value={value}>{titleCase(value)}</option>)}
            </select>
          </FieldLabel>
          <FieldLabel label="Business criticality">
            <select className="field" value={form.criticality} onChange={(event) => setForm({ ...form, criticality: Number(event.target.value) })}>
              {(options?.criticality_scale || []).map((item: any) => <option key={item.value} value={item.value}>{item.value} — {item.label}</option>)}
            </select>
          </FieldLabel>
          <FieldLabel label="Business importance">
            <select className="field" value={form.business_importance} onChange={(event) => setForm({ ...form, business_importance: event.target.value })}>
              {(options?.business_importance || ["standard", "important", "critical", "safety-critical"]).map((value: string) => <option key={value} value={value}>{titleCase(value)}</option>)}
            </select>
          </FieldLabel>
          <FieldLabel label="Notes" className="sm:col-span-2" hint="Free-text context visible to analysts">
            <textarea className="field" rows={3} value={form.notes} onChange={(event) => setForm({ ...form, notes: event.target.value })} maxLength={2000} />
          </FieldLabel>
        </div>
      </Modal>

      <Modal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        title="Import inventory from CSV"
        description="Maximum 500 rows. Required columns: name, software. Optional: category, organisation, identifier, software_version, os, exposure, criticality, owner, business_importance, notes."
        className="max-w-[720px]"
        footer={
          <>
            <button className="btn btn-ghost" onClick={() => setImportOpen(false)}>Cancel</button>
            <button className="btn btn-primary" disabled={importAssets.isPending || csvText.trim().length < 5} onClick={() => importAssets.mutate()}>
              <FileUp size={13} /> {importAssets.isPending ? "Importing…" : "Import and rescan"}
            </button>
          </>
        }
      >
        <textarea
          className="field font-mono text-[10.5px]"
          rows={12}
          value={csvText}
          onChange={(event) => setCsvText(event.target.value)}
          spellCheck={false}
          aria-label="Asset CSV content"
        />
        <InlineNotice tone="med" className="mt-3">
          Imported rows are treated as operator-authorised inventory. Every row is rescanned after import; exposure still requires product and version validation and never runs automated actions.
        </InlineNotice>
      </Modal>

      <ConfirmDialog
        open={Boolean(deleteTarget)}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => removeAsset.mutate()}
        title="Remove this asset from inventory?"
        body={`${deleteTarget?.ref || ""} ${deleteTarget?.name || ""} and its exposure matches, notes and assessments will be deleted. Audit history is retained. This cannot be undone.`}
        confirmLabel="Remove asset"
        danger
        busy={removeAsset.isPending}
      />
    </>
  );
}
