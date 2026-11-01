import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowRight,
  Boxes,
  BrainCircuit,
  Crosshair,
  Database,
  Fingerprint,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Swords,
  Target,
  Wrench,
} from "lucide-react";
import clsx from "clsx";
import { api, qs } from "../../lib/api";
import { fmtDate, fmtNumber, fmtPct, riskColor, titleCase } from "../../lib/format";
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
  SeverityBadge,
} from "../../components/ui";
import { HBarList, DistributionDonut } from "../../components/charts";
import { Treemap, PriorityMatrix } from "../../components/analytics-charts";
import { SectionLabel } from "./shared";

/* Public ATT&CK tactic mapping for the technique IDs that appear in stored records.
   This is a presentation reference, not a model output or an inferred attack prediction. */
const ATTACK_TECHNIQUES: Record<string, { name: string; tactic: string; note: string }> = {
  T1190: { name: "Exploit Public-Facing Application", tactic: "Initial Access", note: "Exploitation of an internet-reachable service." },
  "T1059.001": { name: "PowerShell", tactic: "Execution", note: "Command execution through PowerShell." },
  T1078: { name: "Valid Accounts", tactic: "Initial Access", note: "Use of legitimate credentials; also seen in persistence and privilege escalation." },
  "T1552.001": { name: "Credentials In Files", tactic: "Credential Access", note: "Credentials recovered from files or configuration stores." },
  "T1071.001": { name: "Web Protocols", tactic: "Command and Control", note: "Application-layer web protocols used for command and control." },
  T1486: { name: "Data Encrypted for Impact", tactic: "Impact", note: "Encryption of data to disrupt operations." },
  T1498: { name: "Network Denial of Service", tactic: "Impact", note: "Exhaustion of network capacity or service state." },
};

const TACTICS = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

const CATEGORY_NOTES: Record<string, string> = {
  "Remote Code Execution": "Execution of attacker-controlled code through a vulnerable service or library.",
  "Software Vulnerability": "A published weakness with severity and exploitation evidence attached.",
  "Data Breach": "Unauthorised access to or disclosure of protected data.",
  "Credential Compromise": "Credential theft, reuse or exposure that enables account access.",
  "Denial of Service": "Disruption of availability through traffic exhaustion or resource abuse.",
  Phishing: "Deceptive messaging that attempts to obtain access or deliver a payload.",
  Ransomware: "Encryption or extortion activity affecting operational data.",
  Malware: "Malicious code or tooling observed in reporting.",
  "Supply Chain Compromise": "Compromise introduced through a supplier, dependency or update channel.",
  "Suspicious Network Activity": "Network behaviour recorded as anomalous or indicative of intrusion.",
};

function isoDaysAgo(days: number) {
  return new Date(Date.now() - days * 86400000).toISOString();
}

function windowLabel(days: number) {
  return days === 30 ? "30D" : days === 90 ? "90D" : days === 180 ? "180D" : "1Y";
}

export default function AttackLab() {
  const navigate = useNavigate();
  const [days, setDays] = useState("90");
  const [category, setCategory] = useState<string | null>(null);
  const rangeDays = Number(days);

  const categoriesQuery = useQuery({
    queryKey: ["attack-categories", days],
    queryFn: () => api<any>(`/threats${qs({ range: `${rangeDays}d`, size: 1, sort_by: "risk_score" })}`),
  });

  const categories: Array<{ name: string; count: number }> = useMemo(
    () => (categoriesQuery.data?.facets?.categories || []).filter((entry: any) => entry.count > 0),
    [categoriesQuery.data],
  );

  useEffect(() => {
    if (!category && categories.length) setCategory(categories[0].name);
    if (category && categories.length && !categories.some((entry) => entry.name === category)) setCategory(categories[0].name);
  }, [categories, category]);

  const threatQuery = useQuery({
    queryKey: ["attack-profile", category, days],
    enabled: Boolean(category),
    queryFn: () =>
      api<any>(
        `/threats${qs({
          range: `${rangeDays}d`,
          size: 100,
          category,
          sort_by: "risk_score",
          order: "desc",
        })}`,
      ),
  });

  const previousQuery = useQuery({
    queryKey: ["attack-previous", category, days],
    enabled: Boolean(category),
    queryFn: () =>
      api<any>(
        `/threats${qs({
          size: 1,
          category,
          from: isoDaysAgo(rangeDays * 2),
          end: isoDaysAgo(rangeDays),
        })}`,
      ),
  });

  const exposureQuery = useQuery({
    queryKey: ["attack-exposure"],
    queryFn: () => api<any>(`/exposure${qs({ size: 100, status: "potentially_exposed" })}`),
  });

  const recommendationQuery = useQuery({
    queryKey: ["attack-recommendations"],
    queryFn: () => api<any>(`/recommendations${qs({ size: 100, range: "365d" })}`),
  });

  const alertsQuery = useQuery({
    queryKey: ["attack-alerts"],
    queryFn: () => api<any>(`/alerts${qs({ size: 100, range: "365d" })}`),
  });

  const threats: any[] = threatQuery.data?.items || [];
  const total = categories.find((entry) => entry.name === category)?.count ?? threats.length;
  const previousTotal = Number(previousQuery.data?.total || 0);
  const delta = previousTotal > 0 ? Math.round(((total - previousTotal) / previousTotal) * 100) : null;

  const stats = useMemo(() => {
    const critical = threats.filter((threat) => threat.severity === "critical").length;
    const high = threats.filter((threat) => threat.severity === "high").length;
    const knownExploited = threats.filter((threat) => threat.known_exploited).length;
    const risks = threats.map((threat) => Number(threat.risk_score || 0));
    const avgRisk = risks.length ? risks.reduce((sum, value) => sum + value, 0) / risks.length : 0;
    const maxRisk = risks.length ? Math.max(...risks) : 0;
    const techniques = new Map<string, number>();
    threats.forEach((threat) => {
      (threat.indicators || []).forEach((indicator: any) => {
        if (indicator.type === "mitre" && ATTACK_TECHNIQUES[indicator.value]) {
          techniques.set(indicator.value, (techniques.get(indicator.value) || 0) + 1);
        }
      });
    });
    const technologies = new Map<string, { count: number; risk: number[] }>();
    threats.forEach((threat) => {
      if (!threat.affected_technology) return;
      const entry = technologies.get(threat.affected_technology) || { count: 0, risk: [] };
      entry.count += 1;
      entry.risk.push(Number(threat.risk_score || 0));
      technologies.set(threat.affected_technology, entry);
    });
    const sources = [...new Set(threats.map((threat) => threat.source).filter(Boolean))];
    return {
      critical,
      high,
      knownExploited,
      avgRisk,
      maxRisk,
      techniques: [...techniques.entries()].sort((a, b) => b[1] - a[1]),
      technologies: [...technologies.entries()]
        .map(([name, entry]) => ({
          name,
          count: entry.count,
          avgRisk: Math.round(entry.risk.reduce((sum, value) => sum + value, 0) / entry.risk.length),
        }))
        .sort((a, b) => b.count - a.count),
      sources,
      severity: [
        { name: "Critical", value: critical },
        { name: "High", value: high },
        { name: "Medium", value: threats.filter((threat) => threat.severity === "medium").length },
        { name: "Low", value: threats.filter((threat) => threat.severity === "low").length },
      ].filter((entry) => entry.value > 0),
    };
  }, [threats]);

  const cveSet = useMemo(() => new Set(threats.map((threat) => threat.cve_id).filter(Boolean)), [threats]);
  const threatRefSet = useMemo(() => new Set(threats.map((threat) => threat.ref)), [threats]);

  const exposures = useMemo(
    () => (exposureQuery.data?.items || []).filter((row: any) => cveSet.has(row.vulnerability?.cve_id)),
    [exposureQuery.data, cveSet],
  );
  const recommendations = useMemo(
    () =>
      (recommendationQuery.data?.items || []).filter(
        (rec: any) => cveSet.has(rec.vulnerability?.cve_id) || threatRefSet.has(rec.threat?.ref),
      ),
    [recommendationQuery.data, cveSet, threatRefSet],
  );
  const alerts = useMemo(
    () => (alertsQuery.data?.items || []).filter((alert: any) => alert.category === category),
    [alertsQuery.data, category],
  );

  const lifecycle = [
    { key: "reported", label: "Reported", value: total, icon: Database, note: "records in window" },
    { key: "classified", label: "Classified", value: threats.filter((threat) => threat.ai_category || threat.ai_confidence != null).length, icon: BrainCircuit, note: "with a model or heuristic label" },
    { key: "exploited", label: "Exploit evidence", value: threats.filter((threat) => threat.known_exploited || (threat.epss_score || 0) >= 0.5).length, icon: Swords, note: "KEV or EPSS ≥ 50%" },
    { key: "validated", label: "Exposure validated", value: exposures.length, icon: ShieldCheck, note: "version-validated inventory matches" },
    { key: "warned", label: "Warned", value: alerts.length, icon: Siren, note: "rule-generated alerts" },
    { key: "mitigation", label: "Mitigation drafted", value: recommendations.length, icon: Wrench, note: "advisory recommendations" },
  ];

  const techniqueMatrix = TACTICS.map((tactic) => ({
    tactic,
    cells: stats.techniques
      .filter(([code]) => ATTACK_TECHNIQUES[code].tactic === tactic)
      .map(([code, count]) => ({ code, count, ...ATTACK_TECHNIQUES[code] })),
  }));
  const observedTechniques = stats.techniques.length;

  return (
    <>
      <PageHeader
        title="Attack profiles"
        description="Explore one attack class at a time: what was reported, what evidence exists, which public ATT&CK techniques appear in the record set, which inventory is exposed and which mitigations were drafted. Profiles are descriptive, not forecasts."
        actions={
          <>
            <RangeTabs
              value={days}
              onChange={setDays}
              options={[
                { value: "30", label: "30D" },
                { value: "90", label: "90D" },
                { value: "180", label: "180D" },
                { value: "365", label: "1Y" },
              ]}
            />
            <Link to="/app/threats" className="btn btn-ghost btn-sm">
              Open threat ledger <ArrowRight size={12} />
            </Link>
          </>
        }
      />

      {categoriesQuery.isError ? (
        <Panel><ErrorState message={(categoriesQuery.error as any)?.message} retry={() => categoriesQuery.refetch()} /></Panel>
      ) : categoriesQuery.isLoading ? (
        <Panel><LoadingBlock rows={6} label="Loading attack classes" /></Panel>
      ) : !categories.length ? (
        <Panel><EmptyState title="No attack classes in this window" detail="No stored threat records carry a category in the selected range." icon={<Radar size={19} />} /></Panel>
      ) : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6" role="listbox" aria-label="Attack classes">
            {categories.slice(0, 10).map((entry) => {
              const active = entry.name === category;
              return (
                <button
                  key={entry.name}
                  type="button"
                  role="option"
                  aria-selected={active}
                  onClick={() => setCategory(entry.name)}
                  className={clsx(
                    "group relative overflow-hidden rounded-[10px] border px-3 py-2.5 text-left transition-all",
                    active
                      ? "border-ion/45 bg-[linear-gradient(135deg,rgb(var(--ion-rgb)/0.14),rgb(var(--deck-rgb)/0.34))] shadow-[0_0_0_1px_rgb(var(--ion-rgb)/0.12),0_18px_40px_-28px_rgb(var(--ion-rgb)/0.5)]"
                      : "border-line bg-surface/70 hover:border-line-strong hover:bg-hull",
                  )}
                >
                  <span className={clsx("absolute inset-y-0 left-0 w-[2px]", active ? "bg-ion" : "bg-transparent")} />
                  <span className={clsx("block truncate font-mono text-[8px] uppercase tracking-[0.1em]", active ? "text-ion" : "text-dim")}>
                    {entry.count} record{entry.count === 1 ? "" : "s"}
                  </span>
                  <span className={clsx("mt-1 block text-[11px] font-medium leading-tight", active ? "text-ink" : "text-mist group-hover:text-ink")}>
                    {entry.name}
                  </span>
                </button>
              );
            })}
          </div>

          {threatQuery.isError ? (
            <Panel><ErrorState message={(threatQuery.error as any)?.message} retry={() => threatQuery.refetch()} /></Panel>
          ) : threatQuery.isLoading ? (
            <Panel><LoadingBlock rows={8} label="Assembling attack profile" /></Panel>
          ) : (
            <>
              <Panel ticks className="mb-4 overflow-hidden">
                <div className="grid gap-0 lg:grid-cols-[1.5fr_1fr_1fr]">
                  <div className="relative border-b border-line p-5 lg:border-b-0 lg:border-r">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="chip border-ion/30 bg-ion/[0.08] text-ion">attack class</span>
                    </div>
                    <h2 className="mt-3 max-w-[22ch] font-display text-[clamp(1.6rem,2.6vw,2.4rem)] font-medium leading-[1.02] tracking-[-0.04em] text-ink">
                      {category}
                    </h2>
                    <p className="mt-2 max-w-[48ch] text-[11.5px] leading-relaxed text-mist">
                      {CATEGORY_NOTES[category || ""] || "Stored reporting grouped under this category. The profile summarizes records; it does not assert an active campaign."}
                    </p>
                    <div className="mt-4 flex flex-wrap items-end gap-x-6 gap-y-3">
                      <div>
                        <div className="font-mono text-[8px] uppercase tracking-[0.14em] text-dim">records · {windowLabel(rangeDays)}</div>
                        <div className="tnum mt-1 font-display text-[30px] font-semibold leading-none text-ink">{fmtNumber(total)}</div>
                      </div>
                      <div>
                        <div className="font-mono text-[8px] uppercase tracking-[0.14em] text-dim">vs prior window</div>
                        <div className={clsx("tnum mt-1 font-mono text-[13px]", delta == null ? "text-dim" : delta > 0 ? "text-crit" : "text-low")}>
                          {delta == null ? "no baseline" : `${delta > 0 ? "+" : ""}${delta}%`}
                        </div>
                      </div>
                      <div>
                        <div className="font-mono text-[8px] uppercase tracking-[0.14em] text-dim">sources</div>
                        <div className="mt-1 font-mono text-[11px] text-mist">{stats.sources.length || "none"}</div>
                      </div>
                    </div>
                  </div>
                  <div className="border-b border-line p-5 lg:border-b-0 lg:border-r">
                    <SectionLabel>Severity mix</SectionLabel>
                    {stats.severity.length ? (
                      <DistributionDonut
                        data={stats.severity}
                        colors={stats.severity.map((entry) => (entry.name === "Critical" ? "#ff4d5e" : entry.name === "High" ? "#ff963d" : entry.name === "Medium" ? "#ffd166" : "#42c98a"))}
                        centerLabel="records"
                        height={168}
                      />
                    ) : (
                      <div className="py-10 text-center text-[10.5px] text-dim">No severity values.</div>
                    )}
                  </div>
                  <div className="p-5">
                    <SectionLabel>Profile pressure</SectionLabel>
                    <div className="mt-3 space-y-3">
                      {[
                        ["Mean risk", stats.avgRisk.toFixed(1), stats.avgRisk],
                        ["Peak risk", stats.maxRisk.toFixed(1), stats.maxRisk],
                        ["Critical share", fmtPct(total ? (stats.critical / total) * 100 : 0, 0), total ? (stats.critical / total) * 100 : 0],
                        ["Known exploited", fmtNumber(stats.knownExploited), Math.min(100, (stats.knownExploited / Math.max(1, total)) * 100)],
                      ].map(([label, value, weight]) => (
                        <div key={String(label)}>
                          <div className="mb-1 flex items-baseline justify-between gap-2">
                            <span className="text-[10.5px] text-mist">{label}</span>
                            <span className="tnum font-mono text-[9.5px]" style={{ color: riskColor(Number(weight)) }}>{value}</span>
                          </div>
                          <div className="h-[3px] overflow-hidden rounded-full bg-veil/[0.06]">
                            <div className="h-full rounded-full" style={{ width: `${Math.max(2, Math.min(100, Number(weight)))}%`, background: riskColor(Number(weight)) }} />
                          </div>
                        </div>
                      ))}
                    </div>
                    <div className="mt-4 flex items-center gap-2 border-t border-line pt-3 font-mono text-[8px] uppercase tracking-[0.1em] text-dim">
                      <Fingerprint size={10} className="text-violet" /> {observedTechniques} technique code(s) observed
                    </div>
                  </div>
                </div>
              </Panel>

              <div className="mb-4 grid grid-cols-2 gap-2.5 sm:grid-cols-3 xl:grid-cols-6">
                <Kpi label="Records" value={fmtNumber(total)} detail={`${fmtNumber(stats.critical)} critical`} icon={<Database size={15} />} tone="ion" />
                <Kpi label="Known exploited" value={fmtNumber(stats.knownExploited)} detail="Records with exploitation evidence" icon={<ShieldAlert size={15} />} tone="crit" />
                <Kpi label="Peak risk" value={stats.maxRisk.toFixed(1)} detail="Highest prioritisation score" icon={<Target size={15} />} tone="high" />
                <Kpi label="Exposed assets" value={fmtNumber(new Set(exposures.map((row: any) => row.asset?.ref)).size)} detail={`${fmtNumber(exposures.length)} validated matches`} icon={<Boxes size={15} />} tone="violet" />
                <Kpi label="Warnings" value={fmtNumber(alerts.length)} detail="Rule-generated alerts" icon={<Siren size={15} />} tone="med" />
                <Kpi label="Mitigations" value={fmtNumber(recommendations.length)} detail="Drafted recommendations" icon={<Wrench size={15} />} tone="low" />
              </div>

              <Panel className="mb-4">
                <PanelHead
                  title="Observed attack lifecycle"
                  kicker="Recorded progression, not an inferred kill chain"
                  right={<span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{windowLabel(rangeDays)} window</span>}
                />
                <div className="overflow-x-auto p-4">
                  <div className="flex min-w-[760px] items-stretch gap-2">
                    {lifecycle.map((stage, index) => {
                      const Icon = stage.icon;
                      const ratio = total ? Math.min(100, (stage.value / total) * 100) : 0;
                      return (
                        <div key={stage.key} className="relative flex-1">
                          <div className="relative h-[92px] overflow-hidden rounded-lg border border-line bg-surface/80 p-3">
                            <div className="flex items-center justify-between">
                              <span className="grid h-6 w-6 place-items-center rounded-[5px] border border-ion/25 bg-ion/[0.07] text-ion"><Icon size={12} /></span>
                              <span className="tnum font-display text-[20px] font-semibold leading-none text-ink">{fmtNumber(stage.value)}</span>
                            </div>
                            <div className="mt-3 font-mono text-[8px] uppercase tracking-[0.12em] text-mist">{stage.label}</div>
                            <div className="mt-1 text-[8.5px] leading-snug text-dim">{stage.note}</div>
                            <div className="absolute inset-x-0 bottom-0 h-[2px] bg-veil/[0.04]">
                              <div className="h-full bg-ion/70" style={{ width: `${Math.max(2, ratio)}%` }} />
                            </div>
                          </div>
                          {index < lifecycle.length - 1 && (
                            <span className="absolute -right-1.5 top-1/2 z-10 hidden -translate-y-1/2 text-dim xl:block">›</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
                <p className="border-t border-line px-4 py-2 text-[9.5px] leading-relaxed text-dim">
                  Stages count records that reach each evidenced state. A smaller later stage is not a failure; it means the evidence chain stops there.
                </p>
              </Panel>

              <div className="mb-4 grid gap-4 xl:grid-cols-[1.25fr_1fr]">
                <Panel className="min-w-0">
                  <PanelHead
                    title="MITRE ATT&CK coverage"
                    kicker="Technique IDs present in stored records"
                    right={<span className="chip">{observedTechniques} observed</span>}
                  />
                  <div className="overflow-x-auto p-4">
                    {observedTechniques ? (
                      <div className="flex min-w-[1240px] gap-1.5">
                        {techniqueMatrix.map((column) => (
                          <div key={column.tactic} className="min-w-[88px] flex-1">
                            <div className="mb-1.5 h-7 font-mono text-[7.2px] uppercase leading-tight tracking-[0.06em] text-dim">{column.tactic}</div>
                            <div className={clsx("min-h-[84px] rounded-[4px] border p-1", column.cells.length ? "border-ion/25 bg-ion/[0.045]" : "border-line bg-veil/[0.015]")}>
                              {column.cells.length ? (
                                column.cells.map((cell) => (
                                  <div key={cell.code} className="mb-1 rounded-[3px] border border-ion/25 bg-ion/[0.1] px-1.5 py-1" title={`${cell.code} · ${cell.name} · ${cell.note}`}>
                                    <div className="font-mono text-[8px] text-ion">{cell.code}</div>
                                    <div className="mt-0.5 line-clamp-2 text-[8px] leading-tight text-mist">{cell.name}</div>
                                    <div className="mt-0.5 font-mono text-[7px] text-dim">{cell.count} rec</div>
                                  </div>
                                ))
                              ) : (
                                <div className="grid h-[76px] place-items-center font-mono text-[8px] text-dim">·</div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="py-12 text-center text-[11px] text-dim">No ATT&CK technique IDs are attached to records in this class.</div>
                    )}
                  </div>
                  <p className="border-t border-line px-4 py-2 text-[9.5px] leading-relaxed text-dim">
                    Public reference mapping. Multi-tactic techniques appear under their primary tactic. An empty column means no observed technique, not that the tactic is impossible. This matrix is not a prediction of attacker behaviour.
                  </p>
                </Panel>

                <Panel className="min-w-0">
                  <PanelHead title="Technique density" kicker="Records carrying each code" right={<Crosshair size={13} className="text-dim" />} />
                  <div className="p-4">
                    {stats.techniques.length ? (
                      <HBarList
                        data={stats.techniques.map(([code, count]) => ({ name: code, value: count }))}
                        labelKey="name"
                        valueKey="value"
                        color="#9a8cff"
                      />
                    ) : (
                      <div className="py-10 text-center text-[10.5px] text-dim">No technique indicators.</div>
                    )}
                    <div className="mt-4 border-t border-line pt-3">
                      <SectionLabel right={<span className="font-mono text-[8px] text-dim">{stats.technologies.length} technologies</span>}>Affected technologies</SectionLabel>
                      {stats.technologies.length ? (
                        <Treemap
                          height={190}
                          items={stats.technologies.slice(0, 10).map((tech) => ({
                            name: tech.name,
                            value: tech.count,
                            meta: `${tech.count} rec · risk ${tech.avgRisk}`,
                            detail: `${tech.count} records, mean risk ${tech.avgRisk}`,
                            color: riskColor(tech.avgRisk),
                          }))}
                        />
                      ) : (
                        <div className="py-8 text-center text-[10.5px] text-dim">No technology attribution.</div>
                      )}
                    </div>
                  </div>
                </Panel>
              </div>

              <div className="grid gap-4 xl:grid-cols-[1fr_1fr]">
                <Panel className="min-w-0">
                  <PanelHead
                    title="Exposed inventory"
                    kicker="Version-validated matches for this class"
                    right={<span className="chip">{exposures.length} rows</span>}
                  />
                  {exposureQuery.isLoading ? (
                    <LoadingBlock rows={4} />
                  ) : exposures.length ? (
                    <div className="max-h-[320px] overflow-y-auto">
                      <table className="table-shell">
                        <thead>
                          <tr><th>Asset</th><th>CVE</th><th className="text-right">Exposure</th></tr>
                        </thead>
                        <tbody>
                          {exposures.slice(0, 12).map((row: any) => (
                            <tr key={row.id} onClick={() => navigate(`/app/assets?focus=${row.asset?.ref}`)}>
                              <td>
                                <div className="text-[11px] text-ink">{row.asset?.name}</div>
                                <div className="font-mono text-[8px] uppercase tracking-[0.08em] text-dim">{row.asset?.ref} · criticality {row.asset?.criticality}/5</div>
                              </td>
                              <td className="font-mono text-[9.5px] text-info">{row.vulnerability?.cve_id}</td>
                              <td className="text-right">
                                <span className={clsx("font-mono text-[8.5px] uppercase tracking-[0.08em]", row.asset?.exposure === "internet-facing" ? "text-high" : "text-mist")}>
                                  {titleCase(row.asset?.exposure || "internal")}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <EmptyState title="No validated exposure" detail="No registered asset matched a product and version range for this class." icon={<ShieldCheck size={18} />} />
                  )}
                </Panel>

                <Panel className="min-w-0">
                  <PanelHead
                    title="Mitigation workflow"
                    kicker="Advisory recommendations linked to this class"
                    right={<Link to="/app/recommendations" className="font-mono text-[9px] uppercase tracking-[0.1em] text-ion">Open queue →</Link>}
                  />
                  {recommendationQuery.isLoading ? (
                    <LoadingBlock rows={4} />
                  ) : recommendations.length ? (
                    <div className="divide-y divide-veil/[0.045]">
                      {recommendations.slice(0, 7).map((rec: any) => (
                        <Link key={rec.id} to={`/app/recommendations?focus=${rec.ref}`} className="block px-4 py-3 transition-colors hover:bg-veil/[0.025]">
                          <div className="flex items-center gap-2">
                            <span className={clsx("font-mono text-[8px] uppercase tracking-[0.1em]", rec.priority === "critical" ? "text-crit" : rec.priority === "high" ? "text-high" : "text-med")}>{rec.priority}</span>
                            <span className="font-mono text-[8px] text-dim">{rec.status?.replace("_", " ")}</span>
                            <span className="ml-auto font-mono text-[8px] text-dim">{rec.due_at ? fmtDate(rec.due_at) : "no due date"}</span>
                          </div>
                          <div className="mt-1 line-clamp-2 text-[11px] leading-snug text-mist">{rec.title}</div>
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <EmptyState title="No mitigation drafted" detail="No recommendation references a record in this class for the current window." icon={<Wrench size={18} />} />
                  )}
                </Panel>
              </div>

              <InlineNotice tone="violet" className="mt-4" title="How to read this profile">
                Profiles group stored intelligence records by their recorded category. Technique codes come from structured indicators; tactic labels are a static public ATT&CK mapping. Exposure counts include only version-validated matches, and warnings are rule outputs — none of these panels predicts a future attack.
              </InlineNotice>
            </>
          )}
        </>
      )}
    </>
  );
}
