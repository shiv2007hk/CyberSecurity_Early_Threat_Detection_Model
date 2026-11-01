import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import {
  Activity,
  ArrowUpRight,
  Bot,
  Boxes,
  ChartNoAxesCombined,
  CornerDownLeft,
  Crosshair,
  FileText,
  FlaskConical,
  GitFork,
  Globe2,
  LayoutDashboard,
  LifeBuoy,
  ListFilter,
  Radar,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Siren,
  TriangleAlert,
  Users,
  Waypoints,
  Wrench,
} from "lucide-react";
import clsx from "clsx";
import { api } from "../lib/api";
import { useAuth } from "../context/AuthContext";
import { SeverityBadge } from "./ui";

type Entry = {
  key: string;
  title: string;
  subtitle?: string;
  route: string;
  group: string;
  badge?: string | null;
  icon: React.ReactNode;
};

const GROUP_ICONS: Record<string, React.ReactNode> = {
  threats: <Radar size={13} />,
  vulnerabilities: <ShieldAlert size={13} />,
  assets: <Boxes size={13} />,
  alerts: <Siren size={13} />,
  recommendations: <Wrench size={13} />,
};

const GROUP_LABELS: Record<string, string> = {
  threats: "Threat intelligence",
  vulnerabilities: "Vulnerabilities",
  assets: "Assets",
  alerts: "Early warning",
  recommendations: "Recommendations",
};

export default function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [value, setValue] = useState("");
  const [debounced, setDebounced] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setValue("");
    setDebounced("");
    setActive(0);
    const timer = setTimeout(() => inputRef.current?.focus(), 40);
    return () => clearTimeout(timer);
  }, [open]);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value.trim()), 220);
    return () => clearTimeout(timer);
  }, [value]);

  const { data, isFetching } = useQuery({
    queryKey: ["global-search", debounced],
    queryFn: () => api<any>(`/search?q=${encodeURIComponent(debounced)}&limit=4`),
    enabled: open && debounced.length >= 2,
    staleTime: 20_000,
  });

  const quickLinks = useMemo<Entry[]>(() => {
    const links: Array<[string, string, string, React.ReactNode]> = [
      ["Command centre", "/app", "Watch floor overview", <LayoutDashboard size={13} />],
      ["Monitoring & anomalies", "/app/monitoring", "Two-sigma watch, geography, sources", <Activity size={13} />],
      ["Threat intelligence", "/app/threats", "Ingested reports and analysis", <Radar size={13} />],
      ["Vulnerability intelligence", "/app/vulnerabilities", "CVE, CVSS, EPSS and KEV", <ShieldAlert size={13} />],
      ["Asset inventory", "/app/assets", "Registered estate and ownership", <Boxes size={13} />],
      ["Exposure matching", "/app/exposure", "Validated product and version matches", <ShieldCheck size={13} />],
      ["Attack lab", "/app/attack-lab", "Category profile and ATT&CK matrix", <Crosshair size={13} />],
      ["Technique library", "/app/techniques", "Attack classes and ATT&CK reference index", <ListFilter size={13} />],
      ["Global threat map", "/app/threat-map", "Indicator geography and origin ranking", <Globe2 size={13} />],
      ["Early warning", "/app/alerts", "Detections and investigation", <Siren size={13} />],
      ["Risk assessment", "/app/risk", "Explainable scoring model", <TriangleAlert size={13} />],
      ["What-if simulator", "/app/simulator", "Projection under controlled assumptions", <FlaskConical size={13} />],
      ["Evidence provenance", "/app/provenance", "Source-to-warning decision chain", <Waypoints size={13} />],
      ["Correlation", "/app/correlations", "Campaign clusters and links", <GitFork size={13} />],
      ["Recommendations", "/app/recommendations", "Defensive remediation queue", <Wrench size={13} />],
      ["Analytics", "/app/analytics", "Trends, distributions, anomalies", <ChartNoAxesCombined size={13} />],
      ["Reports", "/app/reports", "Generated intelligence products", <FileText size={13} />],
      ["Sources", "/app/sources", "Connectors and ingestion logs", <LifeBuoy size={13} />],
      ["Aegis AI", "/app/ai", "Ask about vulnerabilities, assets and risk", <Bot size={13} />],
      ["Threat scenarios", "/app/scenarios", "Run end-to-end detection scenarios", <Sparkles size={13} />],
    ];
    if (user?.role === "admin") {
      links.push(["Users & roles", "/app/users", "Account administration", <Users size={13} />]);
      links.push(["Audit trail", "/app/audit", "Privileged action history", <FileText size={13} />]);
    }
    return links.map(([title, route, subtitle, icon]) => ({
      key: route,
      title,
      subtitle,
      route,
      group: "Jump to",
      icon,
    }));
  }, [user?.role]);

  const results = useMemo<Entry[]>(() => {
    if (debounced.length >= 2 && data?.results) {
      return Object.entries(data.results as Record<string, any[]>).flatMap(([group, items]) =>
        items.map((item) => ({
          key: `${group}-${item.ref}`,
          title: item.title,
          subtitle: item.subtitle,
          route: item.route,
          group: GROUP_LABELS[group] || group,
          badge: item.badge,
          icon: GROUP_ICONS[group] || <Search size={13} />,
        })),
      );
    }
    if (!debounced) return quickLinks;
    return quickLinks.filter((link) => `${link.title} ${link.subtitle}`.toLowerCase().includes(debounced.toLowerCase()));
  }, [data, debounced, quickLinks]);

  useEffect(() => setActive(0), [results.length]);

  const go = (entry?: Entry) => {
    if (!entry) return;
    onClose();
    navigate(entry.route);
  };

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((index) => Math.min(results.length - 1, index + 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((index) => Math.max(0, index - 1));
    } else if (event.key === "Enter") {
      event.preventDefault();
      go(results[active]);
    } else if (event.key === "Escape") {
      onClose();
    }
  };

  let lastGroup = "";

  return (
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-[90] flex items-start justify-center px-4 pt-[8vh] sm:pt-[12vh]" role="presentation">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="absolute inset-0 bg-sunken/78 backdrop-blur-[5px]"
            onClick={onClose}
          />
          <motion.div
            initial={{ opacity: 0, y: -12, scale: 0.985 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -6, scale: 0.99 }}
            transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
            role="dialog"
            aria-modal="true"
            aria-label="Global search"
            className="relative w-full max-w-[620px] overflow-hidden rounded-2xl border border-line-strong bg-surface shadow-lift"
            onKeyDown={onKeyDown}
          >
            <div className="flex items-center gap-3 border-b border-line px-4 py-3">
              <Search size={16} className="shrink-0 text-ion" />
              <input
                ref={inputRef}
                value={value}
                onChange={(event) => setValue(event.target.value)}
                placeholder="Search threats, CVEs, assets, alerts, recommendations…"
                className="h-8 w-full bg-transparent text-[13.5px] text-ink outline-none placeholder:text-dim"
                aria-label="Search the platform"
              />
              <kbd className="hidden shrink-0 rounded border border-line bg-veil/[0.03] px-1.5 py-0.5 font-mono text-[9px] text-dim sm:block">ESC</kbd>
            </div>
            <div className="max-h-[54vh] overflow-y-auto p-2">
              {isFetching && (
                <div className="flex items-center gap-2 px-3 py-2 font-mono text-[9px] uppercase tracking-[0.16em] text-dim">
                  <span className="h-1 w-1 animate-ping rounded-full bg-ion" /> Searching records
                </div>
              )}
              {!results.length && (
                <div className="px-4 py-10 text-center">
                  <p className="text-[12.5px] text-mist">
                    {debounced.length >= 2 ? `No records matched “${debounced}”.` : "Search the platform or jump to a module."}
                  </p>
                  <p className="mt-1.5 text-[10.5px] text-dim">Try a CVE identifier, asset name, threat reference or alert.</p>
                </div>
              )}
              {results.map((entry, index) => {
                const showGroup = entry.group !== lastGroup;
                lastGroup = entry.group;
                return (
                  <div key={entry.key}>
                    {showGroup && <div className="px-3 pb-1 pt-2.5 font-mono text-[8.5px] uppercase tracking-[0.18em] text-dim">{entry.group}</div>}
                    <button
                      onMouseEnter={() => setActive(index)}
                      onClick={() => go(entry)}
                      className={clsx(
                        "flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left transition-colors",
                        active === index ? "bg-ion/[0.09]" : "hover:bg-veil/[0.03]",
                      )}
                    >
                      <span className={clsx("grid h-7 w-7 shrink-0 place-items-center rounded-md border", active === index ? "border-ion/30 bg-ion/10 text-ion" : "border-line bg-veil/[0.02] text-dim")}>
                        {entry.icon}
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[12.5px] text-ink">{entry.title}</span>
                        {entry.subtitle && <span className="mt-0.5 block truncate text-[10.5px] text-dim">{entry.subtitle}</span>}
                      </span>
                      {entry.badge && ["critical", "high", "medium", "low"].includes(String(entry.badge).toLowerCase()) ? (
                        <SeverityBadge severity={entry.badge} />
                      ) : entry.badge ? (
                        <span className="chip">{entry.badge}</span>
                      ) : (
                        <ArrowUpRight size={12} className="shrink-0 text-dim" />
                      )}
                    </button>
                  </div>
                );
              })}
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line bg-shade/20 px-4 py-2 font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">
              <span className="flex items-center gap-3">
                <span className="flex items-center gap-1"><ArrowUpRight size={10} className="rotate-45" /> navigate</span>
                <span className="flex items-center gap-1"><CornerDownLeft size={10} /> open</span>
              </span>
              <span>Searches platform records</span>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
