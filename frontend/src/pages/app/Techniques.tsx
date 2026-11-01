import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  ChevronDown,
  Crosshair,
  Database,
  Flame,
  Layers3,
  ListFilter,
  Search,
  ShieldAlert,
  Siren,
  X,
} from "lucide-react";
import clsx from "clsx";
import { type Threat } from "../../lib/api";
import { fmtNumber, relTime, titleCase } from "../../lib/format";
import { ATTACK_CLASS_NOTES, ATTACK_TACTICS, ATTACK_TECHNIQUES } from "../../lib/attack-techniques";
import { countBy, countTechniques, useThreatWindow, type ThreatIndicator } from "../../lib/threat-window";
import {
  EmptyState,
  ErrorState,
  InlineNotice,
  Kpi,
  LoadingBlock,
  PageHeader,
  Panel,
  PanelHead,
  RangeTabs,
  RiskMeter,
  SeverityBadge,
} from "../../components/ui";
import { DistributionDonut, HBarList, Heatmap } from "../../components/charts";
import { ScoreChip, SectionLabel } from "./shared";

type SelectOption = {
  value: string;
  label: string;
  meta: string;
  group: string;
  count: number;
};

const RANGES = [
  { value: "7d", label: "7D" },
  { value: "30d", label: "30D" },
  { value: "90d", label: "90D" },
];

const SEVERITY_COLORS = ["#ff4d5e", "#ff963d", "#ffd166", "#42c98a", "#78b7ff"];

function shortLabel(value: string, length = 16) {
  return value.length > length ? `${value.slice(0, length - 1)}…` : value;
}

function TechniqueSelect({
  options,
  value,
  onChange,
}: {
  options: SelectOption[];
  value: string;
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const selected = options.find((option) => option.value === value);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return options;
    return options.filter((option) =>
      `${option.label} ${option.meta} ${option.value} ${option.group}`.toLowerCase().includes(needle),
    );
  }, [options, query]);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    const index = options.findIndex((option) => option.value === value);
    setActive(index >= 0 ? index : 0);
    const timer = window.setTimeout(() => inputRef.current?.focus(), 10);
    return () => window.clearTimeout(timer);
  }, [open, options, value]);

  useEffect(() => {
    if (!open) return;
    const node = listRef.current?.querySelector<HTMLElement>(`[data-index="${active}"]`);
    node?.scrollIntoView({ block: "nearest" });
  }, [active, open]);

  const choose = (next: SelectOption) => {
    onChange(next.value);
    setOpen(false);
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (!open) {
      if (event.key === "ArrowDown" || event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        setOpen(true);
      }
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((index) => Math.min(filtered.length - 1, index + 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((index) => Math.max(0, index - 1));
    } else if (event.key === "Enter") {
      event.preventDefault();
      const option = filtered[active];
      if (option) choose(option);
    }
  };

  return (
    <div ref={rootRef} className="relative" onKeyDown={handleKeyDown}>
      <button
        type="button"
        onClick={() => setOpen((current) => !current)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="group flex w-full items-center gap-3 rounded-xl border border-line-strong bg-[linear-gradient(120deg,rgb(var(--deck-rgb)/0.62),rgb(var(--surface-rgb)/0.92))] px-3.5 py-3 text-left transition-colors hover:border-ion/45"
      >
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-ion/25 bg-ion/[0.07] text-ion">
          <Crosshair size={15} />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block font-mono text-[8px] uppercase tracking-[0.16em] text-ion/80">
            {selected?.group || "Technique index"}
          </span>
          <span className="mt-0.5 block truncate text-[13px] font-semibold text-ink">
            {selected?.label || "Select an attack class or technique"}
          </span>
          <span className="mt-0.5 block truncate text-[10px] text-dim">
            {selected?.meta || "Search the catalogue to inspect stored evidence."}
          </span>
        </span>
        <span className={clsx("chip hidden sm:inline-flex", selected?.count ? "text-low" : "text-dim")}>
          {selected?.count ?? 0} observed
        </span>
        <ChevronDown size={15} className={clsx("shrink-0 text-dim transition-transform", open && "rotate-180")} />
      </button>

      {open && (
        <div className="absolute inset-x-0 top-[calc(100%+6px)] z-40 overflow-hidden rounded-xl border border-line-strong bg-tooltip/95 shadow-lift backdrop-blur">
          <div className="flex items-center gap-2 border-b border-line px-3 py-2">
            <Search size={13} className="shrink-0 text-dim" />
            <input
              ref={inputRef}
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setActive(0);
              }}
              role="combobox"
              aria-expanded={open}
              aria-controls="technique-listbox"
              aria-autocomplete="list"
              aria-activedescendant={filtered[active] ? `technique-option-${active}` : undefined}
              placeholder="Filter by name, class, tactic or ATT&CK ID…"
              aria-label="Filter techniques"
              className="h-7 w-full bg-transparent text-[11px] text-ink placeholder:text-dim focus:outline-none"
            />
            {query && (
              <button type="button" onClick={() => setQuery("")} aria-label="Clear filter" className="text-dim hover:text-ink">
                <X size={12} />
              </button>
            )}
          </div>
          <div ref={listRef} id="technique-listbox" role="listbox" aria-label="Attack techniques" className="max-h-[304px] overflow-y-auto p-1.5">
            {filtered.length ? (
              filtered.map((option, index) => {
                const showGroup = index === 0 || filtered[index - 1].group !== option.group;
                return (
                  <div key={option.value}>
                    {showGroup && (
                      <div className="px-2 pb-1 pt-2.5 font-mono text-[7.8px] uppercase tracking-[0.16em] text-dim first:pt-1">
                        {option.group}
                      </div>
                    )}
                    <button
                      type="button"
                      role="option"
                      id={`technique-option-${index}`}
                      aria-selected={option.value === value}
                      data-index={index}
                      onMouseEnter={() => setActive(index)}
                      onClick={() => choose(option)}
                      className={clsx(
                        "flex w-full items-start justify-between gap-3 rounded-md px-2.5 py-2 text-left transition-colors",
                        index === active ? "bg-ion/[0.07] text-ink" : "text-mist hover:bg-veil/[0.03]",
                      )}
                    >
                      <span className="min-w-0">
                        <span className="block truncate text-[11.5px] text-ink">{option.label}</span>
                        <span className="mt-0.5 block truncate font-mono text-[8.5px] uppercase tracking-[0.06em] text-dim">
                          {option.meta}
                        </span>
                      </span>
                      <span
                        className={clsx(
                          "mt-0.5 shrink-0 rounded border px-1.5 py-[1px] font-mono text-[8px] uppercase tracking-[0.08em]",
                          option.count
                            ? "border-low/25 bg-low/[0.06] text-low"
                            : "border-veil/10 bg-veil/[0.03] text-dim",
                        )}
                      >
                        {option.count ? `${option.count} obs` : "reference"}
                      </span>
                    </button>
                  </div>
                );
              })
            ) : (
              <div className="px-3 py-8 text-center text-[10.5px] text-dim">No technique matches “{query}”.</div>
            )}
          </div>
          <div className="flex items-center justify-between border-t border-line px-3 py-1.5 font-mono text-[8px] uppercase tracking-[0.1em] text-dim">
            <span>↑↓ navigate · enter select · esc close</span>
            <span>{filtered.length} options</span>
          </div>
        </div>
      )}
    </div>
  );
}

function StatTile({ label, value, detail }: { label: string; value: React.ReactNode; detail?: string }) {
  return (
    <div className="rounded-lg border border-line bg-shade/25 px-3 py-2.5">
      <div className="font-mono text-[7.8px] uppercase tracking-[0.14em] text-dim">{label}</div>
      <div className="tnum mt-1.5 font-display text-[19px] font-semibold leading-none text-ink">{value}</div>
      {detail && <div className="mt-1.5 text-[9.5px] leading-snug text-dim">{detail}</div>}
    </div>
  );
}

export default function Techniques() {
  const [range, setRange] = useState("90d");
  const [selection, setSelection] = useState("");
  const [touched, setTouched] = useState(false);
  const window = useThreatWindow(range);
  const items = window.items;

  const classes = useMemo(
    () => (window.facets.categories || []).filter((entry: any) => entry.count > 0).sort((a: any, b: any) => b.count - a.count),
    [window.facets],
  );
  const observedTechniques = useMemo(() => countTechniques(items), [items]);
  const observedMap = useMemo(() => new Map(observedTechniques.map((entry) => [entry.code, entry.count])), [observedTechniques]);

  const options = useMemo<SelectOption[]>(() => {
    const classOptions: SelectOption[] = classes.map((entry: any) => ({
      value: `class:${entry.name}`,
      label: entry.name,
      meta: `${fmtNumber(entry.count)} report(s) in window · ${ATTACK_CLASS_NOTES[entry.name] ? "stored category" : "category from source"}`,
      group: "Attack classes in this window",
      count: entry.count,
    }));
    const techniqueOptions: SelectOption[] = Object.entries(ATTACK_TECHNIQUES)
      .map(([code, technique]) => ({
        value: `technique:${code}`,
        label: `${code} · ${technique.name}`,
        meta: `${technique.tactic} · ${observedMap.get(code) ? `${observedMap.get(code)} stored indicator(s)` : "public reference only"}`,
        group: "MITRE ATT&CK techniques",
        count: observedMap.get(code) || 0,
      }))
      .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
    return [...classOptions, ...techniqueOptions];
  }, [classes, observedMap]);

  useEffect(() => {
    if (touched && selection && options.some((option) => option.value === selection)) return;
    const fallback = options.find((option) => option.value.startsWith("class:")) || options[0];
    if (fallback && fallback.value !== selection) setSelection(fallback.value);
  }, [options, selection, touched]);

  const parsed = useMemo(() => {
    const separator = selection.indexOf(":");
    return {
      kind: (separator >= 0 ? selection.slice(0, separator) : "class") as "class" | "technique",
      id: separator >= 0 ? selection.slice(separator + 1) : selection,
    };
  }, [selection]);

  const scoped = useMemo(() => {
    if (!parsed.id) return [] as Threat[];
    if (parsed.kind === "class") return items.filter((threat) => threat.category === parsed.id);
    return items.filter((threat) =>
      (threat.indicators as ThreatIndicator[] | undefined)?.some(
        (indicator) => indicator.type === "mitre" && indicator.value === parsed.id,
      ),
    );
  }, [items, parsed]);

  const stats = useMemo(() => {
    const critical = scoped.filter((threat) => threat.severity === "critical").length;
    const high = scoped.filter((threat) => threat.severity === "high").length;
    const kev = scoped.filter((threat) => threat.known_exploited).length;
    const risks = scoped.map((threat) => Number(threat.risk_score || 0));
    const avgRisk = risks.length ? risks.reduce((sum, value) => sum + value, 0) / risks.length : 0;
    const maxCvss = scoped.reduce((max, threat) => Math.max(max, Number(threat.cvss_score || 0)), 0);
    const cveMap = new Map<string, number>();
    scoped.forEach((threat) => {
      if (!threat.cve_id) return;
      cveMap.set(threat.cve_id, Math.max(cveMap.get(threat.cve_id) || 0, Number(threat.risk_score || 0)));
    });
    return {
      critical,
      high,
      kev,
      avgRisk,
      maxCvss,
      cves: [...cveMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8),
      severity: [
        { name: "Critical", value: critical },
        { name: "High", value: high },
        { name: "Medium", value: scoped.filter((threat) => threat.severity === "medium").length },
        { name: "Low", value: scoped.filter((threat) => threat.severity === "low").length },
        { name: "Informational", value: scoped.filter((threat) => threat.severity === "informational").length },
      ].filter((entry) => entry.value > 0),
      techniques: countTechniques(scoped),
      actions: countBy(scoped, "recommended_action").slice(0, 5),
      sources: countBy(scoped, "source").slice(0, 6),
      records: [...scoped].sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0)).slice(0, 6),
    };
  }, [scoped]);

  const reference = parsed.kind === "technique" ? ATTACK_TECHNIQUES[parsed.id] : undefined;
  const classTotal = parsed.kind === "class" ? classes.find((entry: any) => entry.name === parsed.id)?.count ?? scoped.length : scoped.length;
  const observed = parsed.kind === "class" ? scoped.length > 0 : (observedMap.get(parsed.id) || 0) > 0;
  const title = reference
    ? `${parsed.id} · ${reference.name}`
    : parsed.id || "Attack techniques";
  const note = reference
    ? reference.note
    : ATTACK_CLASS_NOTES[parsed.id] || "Records grouped by the category recorded by the source advisory.";
  const tacticCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    stats.techniques.forEach(({ code, count }) => {
      const tactic = ATTACK_TECHNIQUES[code]?.tactic;
      if (tactic) counts[tactic] = (counts[tactic] || 0) + count;
    });
    return counts;
  }, [stats.techniques]);

  const coverage = useMemo(
    () =>
      classes.map((entry: any) => {
        const classThreats = items.filter((threat) => threat.category === entry.name);
        const techniques = countTechniques(classThreats);
        return {
          class: shortLabel(entry.name, 15),
          values: ATTACK_TACTICS.map((tactic) =>
            techniques.reduce(
              (sum, { code, count }) => (ATTACK_TECHNIQUES[code]?.tactic === tactic ? sum + count : sum),
              0,
            ),
          ),
        };
      }),
    [classes, items],
  );

  const selectionIndex = options.findIndex((option) => option.value === selection);
  const atDetail = stats.records.length > 0;

  return (
    <>
      <PageHeader
        title="Attack technique library"
        kicker="Technique index · ATT&CK mapping · stored evidence"
        description="One index over every attack class recorded in the selected window and a public MITRE ATT&CK reference set. Counts are stored record or indicator occurrences; an unobserved technique is shown as a reference entry, never as a claim about your estate."
        aside={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span><span className="text-ink">{classes.length}</span> attack classes observed</span>
            <span>·</span>
            <span><span className="text-ion">{observedTechniques.length}</span> ATT&CK codes observed</span>
            <span>·</span>
            <span><span className="text-ink">{fmtNumber(items.length)}</span> records scanned</span>
          </div>
        }
        actions={<RangeTabs value={range} onChange={setRange} options={RANGES} />}
      />

      <Panel className="mb-4" ticks>
        <div className="grid grid-cols-1 gap-4 p-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
          <div className="min-w-0">
            <div className="flex items-center gap-2 font-mono text-[8px] uppercase tracking-[0.18em] text-ion/80">
              <ListFilter size={11} /> Technique index
            </div>
            <h2 className="mt-1.5 font-display text-[19px] font-semibold leading-tight text-ink">
              Select any attack class or ATT&CK technique
            </h2>
            <p className="mt-1.5 max-w-[62ch] text-[10.5px] leading-relaxed text-mist">
              The list merges every class present in stored reports with the public technique reference. Observed counts
              update when you change the time window.
            </p>
            <div className="mt-3">
              <TechniqueSelect
                options={options}
                value={selection}
                onChange={(next) => {
                  setTouched(true);
                  setSelection(next);
                }}
              />
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-2 font-mono text-[8px] uppercase tracking-[0.1em] text-dim">
              <span>{selectionIndex + 1}/{options.length} entries</span>
              <span>·</span>
              <span>reference rows never imply observation</span>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2 self-end">
            <StatTile label="Classes in window" value={fmtNumber(classes.length)} detail="Recorded attack categories" />
            <StatTile label="Codes observed" value={fmtNumber(observedTechniques.length)} detail="ATT&CK indicators attached" />
            <StatTile label="Reports scanned" value={fmtNumber(items.length)} detail={window.total > items.length ? `Of ${fmtNumber(window.total)} in range` : "Full window covered"} />
            <StatTile label="Known exploited" value={fmtNumber(items.filter((threat) => threat.known_exploited).length)} detail="KEV-listed records in view" />
          </div>
        </div>
      </Panel>

      <div className="mb-4 grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi
          label={parsed.kind === "class" ? "Class volume" : "Technique occurrences"}
          value={fmtNumber(parsed.kind === "class" ? classTotal : stats.techniques.find((entry) => entry.code === parsed.id)?.count || 0)}
          detail={parsed.kind === "class" ? "Reports recorded in this window" : "Stored indicator occurrences"}
          icon={<Layers3 size={15} />}
          tone="ion"
        />
        <Kpi label="Known exploited" value={fmtNumber(stats.kev)} detail="Records carrying a KEV listing" icon={<Flame size={15} />} tone="crit" />
        <Kpi label="Average risk" value={stats.avgRisk ? stats.avgRisk.toFixed(1) : "—"} detail="Composite score of matching records" icon={<Activity size={15} />} tone="violet" />
        <Kpi label="Max CVSS" value={stats.maxCvss ? stats.maxCvss.toFixed(1) : "—"} detail="Technical severity where published" icon={<ShieldAlert size={15} />} tone="high" />
      </div>

      <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.45fr)_minmax(0,1fr)]">
        <Panel>
          <PanelHead
            title={
              <span className="flex flex-wrap items-center gap-2">
                <span className="truncate">{title}</span>
                <span className="chip">{parsed.kind === "class" ? "attack class" : "ATT&CK technique"}</span>
                {observed ? <span className="chip text-low">observed</span> : <span className="chip text-dim">reference only</span>}
              </span>
            }
            kicker={reference ? `Primary tactic · ${reference.tactic}` : "Stored report category"}
          />
          <div className="p-4">
            <p className="max-w-[78ch] text-[11.5px] leading-relaxed text-ink">{note}</p>

            <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 border-y border-line py-3">
              <RiskMeter score={Math.round(stats.avgRisk || 0)} size={58} />
              <div className="min-w-0">
                <div className="font-mono text-[8px] uppercase tracking-[0.14em] text-dim">Average composite risk</div>
                <div className="mt-1 text-[11px] text-mist">
                  {stats.records.length
                    ? `${fmtNumber(scoped.length)} matching record(s) in the selected window`
                    : "No stored record matches this reference entry."}
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  <span className="chip">{stats.critical} critical</span>
                  <span className="chip">{stats.high} high</span>
                  <span className="chip">{stats.kev} KEV</span>
                  <span className="chip">{stats.cves.length} linked CVE(s)</span>
                </div>
              </div>
            </div>

            <div className="mt-4">
              <SectionLabel
                right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">observed technique indicators</span>}
              >
                Attack chain position
              </SectionLabel>
              <div className="overflow-x-auto pb-1">
                <div className="flex min-w-[560px] gap-1">
                  {ATTACK_TACTICS.map((tactic) => {
                    const count = tacticCounts[tactic] || 0;
                    return (
                      <div
                        key={tactic}
                        className={clsx(
                          "flex-1 rounded-md border px-1.5 py-2",
                          count
                            ? "border-ion/30 bg-ion/[0.06]"
                            : "border-veil/[0.06] bg-shade/20",
                        )}
                        title={`${tactic}: ${count} technique indicator(s)`}
                      >
                        <div className={clsx("font-mono text-[6.8px] uppercase leading-tight tracking-[0.04em]", count ? "text-ion" : "text-dim")}>
                          {tactic}
                        </div>
                        <div className={clsx("tnum mt-1.5 font-mono text-[10px]", count ? "text-ink" : "text-dim")}>{count || "—"}</div>
                      </div>
                    );
                  })}
                </div>
              </div>
              <p className="mt-2 text-[9.5px] leading-relaxed text-dim">
                Tactic position is a static public ATT&CK mapping applied to observed technique IDs. An empty stage means no
                stored technique was recorded there — not that the stage is impossible.
              </p>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <SectionLabel>Severity mix</SectionLabel>
                {stats.severity.length ? (
                  <DistributionDonut
                    data={stats.severity}
                    height={146}
                    centerValue={scoped.length}
                    centerLabel="records"
                    colors={SEVERITY_COLORS}
                  />
                ) : (
                  <p className="py-6 text-center text-[10.5px] text-dim">No severity records for this selection.</p>
                )}
              </div>
              <div>
                <SectionLabel right={<span className="chip">{stats.techniques.length}</span>}>
                  {parsed.kind === "class" ? "Techniques in this class" : "Classes using this technique"}
                </SectionLabel>
                {parsed.kind === "class" ? (
                  stats.techniques.length ? (
                    <HBarList
                      data={stats.techniques.map(({ code, count }) => ({
                        name: `${code} · ${ATTACK_TECHNIQUES[code]?.name || code}`,
                        value: count,
                      }))}
                      color="#49b8ff"
                    />
                  ) : (
                    <p className="py-6 text-center text-[10.5px] text-dim">No ATT&CK technique indicators are attached to this class.</p>
                  )
                ) : (
                  <HBarList data={countBy(scoped, "category")} color="#9a8cff" />
                )}
              </div>
            </div>
          </div>
        </Panel>

        <div className="space-y-4">
          <Panel>
            <PanelHead title="Response actions on record" kicker="Author recommendations stored with matching records" right={<Siren size={14} className="text-dim" />} />
            <div className="px-4 py-3">
              {stats.actions.length ? (
                <ol className="space-y-2.5">
                  {stats.actions.map((action) => (
                    <li key={action.name} className="flex gap-2.5">
                      <span className="mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded-full border border-ion/25 bg-ion/[0.06] font-mono text-[7.5px] text-ion">
                        {action.value}
                      </span>
                      <span className="text-[10.5px] leading-relaxed text-mist">{titleCase(action.name)}</span>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="py-5 text-center text-[10.5px] text-dim">No recommendation is recorded for this selection.</p>
              )}
              <div className="mt-3 border-t border-line pt-2.5">
                <SectionLabel>Sources in this selection</SectionLabel>
                {stats.sources.length ? (
                  <div className="flex flex-wrap gap-1.5">
                    {stats.sources.map((source) => (
                      <span key={source.name} className="chip">
                        {source.name} <span className="ml-1 text-dim">{source.value}</span>
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-[10px] text-dim">No source attribution.</p>
                )}
              </div>
              {stats.cves.length > 0 && (
                <div className="mt-3">
                  <SectionLabel>Related CVEs</SectionLabel>
                  <div className="flex flex-wrap gap-1.5">
                    {stats.cves.map(([cve, risk]) => (
                      <Link key={cve} to={`/app/vulnerabilities?focus=${cve}`} className="chip text-info hover:border-info/40">
                        {cve} <span className="ml-1 text-dim">{risk.toFixed(0)}</span>
                      </Link>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Panel>

          <Panel>
            <PanelHead
              title="Matching records"
              kicker={`${fmtNumber(scoped.length)} record(s) in the current sample`}
              right={<span className="chip">{stats.records.length} shown</span>}
            />
            {atDetail ? (
              <div className="divide-y divide-veil/[0.05]">
                {stats.records.map((threat) => (
                  <Link
                    key={threat.id}
                    to={`/app/threats?focus=${encodeURIComponent(threat.ref)}`}
                    className="flex items-start justify-between gap-3 px-4 py-2.5 transition-colors hover:bg-veil/[0.025]"
                  >
                    <div className="min-w-0">
                      <div className="flex min-w-0 items-center gap-1.5">
                        <span className="truncate text-[11px] text-ink">{threat.name}</span>
                      </div>
                      <div className="mt-0.5 flex flex-wrap items-center gap-x-2 font-mono text-[8px] uppercase tracking-[0.06em] text-dim">
                        {threat.cve_id && <span className="text-info">{threat.cve_id}</span>}
                        <span>{threat.source}</span>
                        <span>·</span>
                        <span>{relTime(threat.published_at)}</span>
                      </div>
                    </div>
                    <div className="shrink-0 text-right">
                      <ScoreChip score={threat.risk_score} />
                      <div className="mt-1"><SeverityBadge severity={threat.severity} /></div>
                    </div>
                  </Link>
                ))}
              </div>
            ) : (
              <div className="px-4 py-8 text-center text-[10.5px] leading-relaxed text-dim">
                No stored record references this entry in the selected window. The reference description remains available,
                but the platform will not invent observations to fill the panel.
              </div>
            )}
          </Panel>
        </div>
      </div>

      <Panel className="mb-4" ticks>
        <PanelHead
          title="Class coverage matrix"
          kicker="Observed ATT&CK technique indicators by class and tactic"
          right={<span className="chip">{classes.length} classes × {ATTACK_TACTICS.length} tactics</span>}
        />
        {window.isError ? (
          <ErrorState compact message={(window.error as any)?.message} retry={() => window.refetch()} />
        ) : window.isLoading ? (
          <LoadingBlock rows={6} label="Loading technique coverage" />
        ) : classes.length ? (
          <div className="grid grid-cols-1 gap-4 p-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
            <div className="min-w-0">
              <Heatmap rows={coverage.map((row) => row.class)} cols={ATTACK_TACTICS} data={coverage} height={Math.max(240, classes.length * 26 + 26)} rowLabel="class" />
              <p className="mt-2 text-[9.5px] leading-relaxed text-dim">
                Counts are ATT&CK technique indicators attached to stored records. Empty cells mean the combination was not
                observed; the matrix does not predict attacker behaviour.
              </p>
            </div>
            <div className="min-w-0">
              <SectionLabel right={<span className="chip">{observedTechniques.length}</span>}>Most-recorded techniques</SectionLabel>
              {observedTechniques.length ? (
                <HBarList
                  data={observedTechniques.map(({ code, count }) => ({
                    name: `${code} · ${ATTACK_TECHNIQUES[code]?.name || code}`,
                    value: count,
                  }))}
                  color="#64d8ff"
                />
              ) : (
                <p className="py-8 text-center text-[10.5px] text-dim">No ATT&CK technique indicators in this window.</p>
              )}
              <div className="mt-4 rounded-lg border border-line bg-shade/20 px-3 py-2.5">
                <div className="font-mono text-[8px] uppercase tracking-[0.14em] text-dim">Data quality</div>
                <p className="mt-1 text-[10px] leading-relaxed text-mist">
                  {window.total > items.length
                    ? `${fmtNumber(items.length)} of ${fmtNumber(window.total)} reports in this window were scanned (200-record ceiling). Counts are a sample, not a total.`
                    : `All ${fmtNumber(items.length)} reports in this window were scanned.`}
                </p>
              </div>
            </div>
          </div>
        ) : (
          <EmptyState
            title="No attack classes in this window"
            detail="Widen the time range. An empty catalogue does not mean the estate is unaffected — it means no stored record was available."
            icon={<Database size={19} />}
          />
        )}
      </Panel>

      <InlineNotice tone="violet" title="What this page does not claim">
        Attack classes are the category recorded by the source advisory; technique codes are structured indicators attached
        to records. A technique shown here is a presentation reference or an observed indicator, not a confirmed adversary
        behaviour, a forecast, or a measure of your defences. Empty selections remain empty.
      </InlineNotice>
    </>
  );
}
