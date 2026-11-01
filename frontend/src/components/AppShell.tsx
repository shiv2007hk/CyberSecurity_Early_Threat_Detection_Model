import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import clsx from "clsx";
import {
  Activity,
  Bell,
  Bot,
  Boxes,
  ChartNoAxesCombined,
  ChevronDown,
  ChevronLeft,
  Command,
  Crosshair,
  DatabaseZap,
  FileText,
  FlaskConical,
  GitFork,
  Globe2,
  LayoutDashboard,
  ListFilter,
  LogOut,
  Menu,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Radar,
  ScrollText,
  Search,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Sun,
  TriangleAlert,
  Users,
  Waypoints,
  Wrench,
  X,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { api } from "../lib/api";
import { relTime, titleCase } from "../lib/format";
import { useTheme } from "../lib/theme";
import { LogoMark, SeverityBadge } from "./ui";
import CommandPalette from "./CommandPalette";

type NavItem = { to: string; label: string; icon: React.ReactNode; end?: boolean; role?: "admin"; badgeKey?: string };

const NAV_GROUPS: Array<{ label: string; items: NavItem[] }> = [
  {
    label: "Command",
    items: [
      { to: "/app", label: "Command centre", icon: <LayoutDashboard size={16} />, end: true },
      { to: "/app/monitoring", label: "Monitoring & anomalies", icon: <Activity size={16} /> },
      { to: "/app/analytics", label: "Advanced analytics", icon: <ChartNoAxesCombined size={16} /> },
    ],
  },
  {
    label: "Intelligence",
    items: [
      { to: "/app/threats", label: "Threat intelligence", icon: <Radar size={16} /> },
      { to: "/app/vulnerabilities", label: "Vulnerabilities", icon: <ShieldAlert size={16} /> },
      { to: "/app/assets", label: "Asset inventory", icon: <Boxes size={16} /> },
      { to: "/app/exposure", label: "Exposure matching", icon: <ShieldCheck size={16} /> },
      { to: "/app/attack-lab", label: "Attack lab", icon: <Crosshair size={16} /> },
      { to: "/app/techniques", label: "Technique library", icon: <ListFilter size={16} /> },
      { to: "/app/threat-map", label: "Global threat map", icon: <Globe2 size={16} /> },
      { to: "/app/correlations", label: "Correlation network", icon: <GitFork size={16} /> },
    ],
  },
  {
    label: "Response",
    items: [
      { to: "/app/alerts", label: "Early warning", icon: <Siren size={16} />, badgeKey: "alerts" },
      { to: "/app/risk", label: "Risk assessment", icon: <TriangleAlert size={16} /> },
      { to: "/app/simulator", label: "What-if simulator", icon: <FlaskConical size={16} /> },
      { to: "/app/recommendations", label: "Recommendations", icon: <Wrench size={16} /> },
      { to: "/app/provenance", label: "Evidence provenance", icon: <Waypoints size={16} /> },
    ],
  },
  {
    label: "Operations",
    items: [
      { to: "/app/reports", label: "Reports", icon: <FileText size={16} /> },
      { to: "/app/sources", label: "Sources & ingestion", icon: <DatabaseZap size={16} /> },
      { to: "/app/ai", label: "Aegis AI", icon: <Bot size={16} /> },
      { to: "/app/scenarios", label: "Threat scenarios", icon: <FlaskConical size={16} /> },
    ],
  },
  {
    label: "Administration",
    items: [
      { to: "/app/users", label: "Users & roles", icon: <Users size={16} />, role: "admin" },
      { to: "/app/audit", label: "Audit trail", icon: <ScrollText size={16} />, role: "admin" },
      { to: "/app/settings", label: "Settings", icon: <Settings2 size={16} /> },
    ],
  },
];

const TITLES: Record<string, string> = {
  "/app": "Command centre",
  "/app/monitoring": "Monitoring & anomaly detection",
  "/app/threats": "Threat intelligence",
  "/app/vulnerabilities": "Vulnerability intelligence",
  "/app/assets": "Asset inventory",
  "/app/exposure": "Exposure matching",
  "/app/attack-lab": "Attack lab",
  "/app/techniques": "Attack technique library",
  "/app/threat-map": "Global threat map",
  "/app/alerts": "Early warning",
  "/app/risk": "Risk assessment",
  "/app/simulator": "What-if risk simulator",
  "/app/provenance": "Evidence provenance",
  "/app/correlations": "Correlation network",
  "/app/recommendations": "Recommendations",
  "/app/analytics": "Advanced analytics",
  "/app/reports": "Reports",
  "/app/sources": "Sources & ingestion",
  "/app/ai": "Aegis AI",
  "/app/scenarios": "Threat scenarios",
  "/app/users": "Users & roles",
  "/app/audit": "Audit trail",
  "/app/settings": "Settings",
};

function useUtcClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 30_000);
    return () => clearInterval(timer);
  }, []);
  return now;
}

function SidebarContent({
  collapsed,
  onNavigate,
  onToggle,
  alertCount,
  criticalCount,
}: {
  collapsed: boolean;
  onNavigate?: () => void;
  onToggle?: () => void;
  alertCount: number;
  criticalCount: number;
}) {
  const { user, can } = useAuth();
  return (
    <div className="relative flex h-full flex-col">
      <div className={clsx("flex shrink-0 items-center border-b border-veil/[0.06] py-3.5", collapsed ? "justify-center px-2" : "gap-2.5 px-4")}>
        <Link to="/app" aria-label="CyberGuard command centre" className="rail-logo grid h-9 w-9 shrink-0 place-items-center rounded-[12px]">
          <LogoMark size={22} />
        </Link>
        {!collapsed && (
          <>
            <div className="min-w-0 flex-1">
              <div className="font-display text-[13.5px] font-semibold leading-none tracking-[-0.03em] text-ink">
                CYBER<span className="ml-1 text-[9px] font-medium tracking-[0.22em] text-ion/90">GUARD</span>
              </div>
              <div className="mt-1.5 font-mono text-[7px] uppercase leading-[1.55] tracking-[0.14em] text-dim">AI threat intelligence &amp; risk analytics</div>
            </div>
            {onToggle && (
              <button className="btn btn-quiet btn-icon btn-sm text-dim" onClick={onToggle} aria-label="Collapse navigation">
                <PanelLeftClose size={15} />
              </button>
            )}
          </>
        )}
      </div>

      {!collapsed && (
        <div className="relative mx-3 mt-3 rounded-[14px] border border-veil/[0.07] bg-veil/[0.035] px-3 py-2.5">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[7.5px] uppercase tracking-[0.18em] text-dim">Operator</span>
            <span className="inline-flex items-center gap-1 font-mono text-[7px] uppercase tracking-[0.12em] text-low/80">
              <span className="h-1 w-1 rounded-full bg-low" /> active
            </span>
          </div>
          <div className="mt-1 truncate text-[12px] font-medium text-ink">{user?.full_name}</div>
          <div className="mt-0.5 truncate font-mono text-[8px] uppercase tracking-[0.12em] text-dim">
            {titleCase(user?.role)} · {user?.organisation?.name || "Unassigned organisation"}
          </div>
        </div>
      )}

      <nav className="min-h-0 flex-1 overflow-y-auto px-2.5 py-3" aria-label="Console navigation">
        {NAV_GROUPS.map((group) => {
          const items = group.items.filter((item) => (item.role === "admin" ? can("admin") : true));
          if (!items.length) return null;
          return (
            <div key={group.label} className="mb-2">
              {collapsed ? (
                <div className="mx-auto mb-2 h-px w-6 bg-veil/[0.07]" />
              ) : (
                <div className="mb-1 flex items-center gap-2 px-2.5">
                  <span className="font-mono text-[7.5px] uppercase tracking-[0.2em] text-dim">{group.label}</span>
                  <span className="h-px flex-1 bg-gradient-to-r from-veil/[0.07] to-transparent" />
                </div>
              )}
              <div className="space-y-0.5">
                {items.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.end}
                    onClick={onNavigate}
                    title={collapsed ? item.label : undefined}
                    className={({ isActive }) => clsx("rail-item group", collapsed && "justify-center px-0")}
                  >
                    {({ isActive }) => (
                      <>
                        <span className="rail-icon grid shrink-0 place-items-center">{item.icon}</span>
                        {!collapsed && <span className="min-w-0 flex-1 truncate text-[12px]">{item.label}</span>}
                        {!collapsed && item.badgeKey === "alerts" && alertCount > 0 && (
                          <span className="ml-auto grid h-[17px] min-w-[17px] place-items-center rounded-full border border-crit/40 bg-crit/20 px-1 font-mono text-[8.5px] text-crit">
                            {alertCount > 99 ? "99+" : alertCount}
                          </span>
                        )}
                        {collapsed && item.badgeKey === "alerts" && alertCount > 0 && (
                          <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-crit shadow-[0_0_6px_rgba(255,77,94,0.9)]" />
                        )}
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          );
        })}
      </nav>

      <div className={clsx("shrink-0 border-t border-veil/[0.06] p-3", collapsed && "px-2")}>
        {collapsed ? (
          <div className="flex flex-col items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-violet" title="Console operational" />
            <Link to="/app/alerts" className="rail-item justify-center px-0" aria-label={`${alertCount} active warnings`}>
              <span className="rail-icon grid place-items-center"><Siren size={16} /></span>
              {criticalCount > 0 && <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-crit" />}
            </Link>
            {onToggle && (
              <button className="btn btn-quiet btn-icon btn-sm text-dim" onClick={onToggle} aria-label="Expand navigation">
                <PanelLeftOpen size={15} />
              </button>
            )}
          </div>
        ) : (
          <>
            <div className="mb-2 rounded-[14px] border border-veil/[0.07] bg-veil/[0.028] px-3 py-2.5">
              <div className="flex items-center justify-between font-mono text-[7px] uppercase tracking-[0.14em] text-dim">
                <span>Posture</span>
                <Link to="/app/alerts" className="text-ion/80 hover:text-ion">/alerts</Link>
              </div>
              <div className="mt-2 grid grid-cols-2 gap-2">
                <div>
                  <div className="tnum font-display text-[16px] font-semibold leading-none text-ink">{alertCount}</div>
                  <div className="mt-1 font-mono text-[6.5px] uppercase tracking-[0.08em] text-dim">active warnings</div>
                </div>
                <div>
                  <div className={clsx("tnum font-display text-[16px] font-semibold leading-none", criticalCount > 0 ? "text-crit" : "text-ink")}>
                    {criticalCount}
                  </div>
                  <div className="mt-1 font-mono text-[6.5px] uppercase tracking-[0.08em] text-dim">critical</div>
                </div>
              </div>
            </div>
            <div className="mt-2.5 flex items-center justify-between px-1 font-mono text-[7.5px] uppercase tracking-[0.1em] text-dim">
              <span className="flex items-center gap-1.5"><span className="h-1 w-1 rounded-full bg-low" /> API v1.0.0</span>
              <span>SOAR off</span>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default function AppShell() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout, can } = useAuth();
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("aegis.sidebar") !== "0");
  const theme = useTheme();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [bellOpen, setBellOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const bellRef = useRef<HTMLDivElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const now = useUtcClock();

  const { data: alertSummary } = useQuery({
    queryKey: ["alert-summary"],
    queryFn: () => api<any>("/alerts/summary"),
    refetchInterval: 60_000,
    staleTime: 30_000,
  });

  useEffect(() => {
    localStorage.setItem("aegis.sidebar", collapsed ? "1" : "0");
  }, [collapsed]);

  useEffect(() => setMobileOpen(false), [location.pathname]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    const onPointer = (event: PointerEvent) => {
      if (bellRef.current && !bellRef.current.contains(event.target as Node)) setBellOpen(false);
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) setMenuOpen(false);
    };
    document.addEventListener("pointerdown", onPointer);
    return () => document.removeEventListener("pointerdown", onPointer);
  }, []);

  const activeCount = alertSummary?.active || 0;
  const criticalCount = alertSummary?.critical || 0;
  const title = TITLES[location.pathname] || (location.pathname.startsWith("/app/reports") ? "Report" : "Console");
  const group = NAV_GROUPS.find((entry) => entry.items.some((item) => (item.end ? location.pathname === item.to : location.pathname.startsWith(item.to))))?.label || "Console";

  const signOut = async () => {
    setMenuOpen(false);
    await logout();
    navigate("/login", { replace: true });
  };

  return (
    <div className="relative min-h-screen bg-void">
      <div className="console-bg" aria-hidden="true" />
      <div className="console-rim" aria-hidden="true" />

      {/* Desktop rail */}
      <aside
        className={clsx(
          "rail-shell fixed bottom-3 left-3 top-3 z-40 hidden overflow-hidden rounded-[22px] transition-[width] duration-300 lg:block",
          collapsed ? "w-[72px]" : "w-[252px]",
        )}
      >
        <SidebarContent collapsed={collapsed} onToggle={() => setCollapsed((value) => !value)} alertCount={activeCount} criticalCount={criticalCount} />
      </aside>

      {/* Mobile rail */}
      <AnimatePresence>
        {mobileOpen && (
          <div className="fixed inset-0 z-[70] lg:hidden">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-sunken/80 backdrop-blur-sm"
              onClick={() => setMobileOpen(false)}
            />
            <motion.aside
              initial={{ x: "-100%" }}
              animate={{ x: 0 }}
              exit={{ x: "-100%" }}
              transition={{ duration: 0.26, ease: [0.16, 1, 0.3, 1] }}
              className="rail-shell absolute inset-y-2 left-2 w-[272px] overflow-hidden rounded-[22px]"
            >
              <button className="btn btn-quiet btn-icon absolute right-2 top-3.5 z-10" onClick={() => setMobileOpen(false)} aria-label="Close navigation">
                <X size={16} />
              </button>
              <SidebarContent collapsed={false} onNavigate={() => setMobileOpen(false)} alertCount={activeCount} criticalCount={criticalCount} />
            </motion.aside>
          </div>
        )}
      </AnimatePresence>

      <div className={clsx("relative transition-[padding] duration-300", collapsed ? "lg:pl-[84px]" : "lg:pl-[264px]")}>
        <div className="sticky top-0 z-30 px-3 pt-3">
          <header className="console-topbar px-1.5 py-2 sm:px-3.5">
            <div className="flex items-center gap-1 min-[380px]:gap-1.5 sm:gap-2.5">
              <button className="btn btn-quiet btn-icon lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open navigation">
                <Menu size={18} />
              </button>

              <div className="min-w-0 flex-1">
                <div className="hidden items-center gap-1.5 font-mono text-[8px] uppercase tracking-[0.18em] text-dim sm:flex">
                  <span>{group}</span>
                  <ChevronLeft size={9} className="rotate-180" />
                  <span className="text-mist">{title}</span>
                </div>
                <div className="flex items-center gap-2">
                  <h2 className="truncate text-[14px] font-semibold tracking-[-0.02em] text-ink min-[380px]:text-[15px] sm:text-[16.5px]">{title}</h2>
                  <span className="hidden items-center gap-1.5 rounded-full border border-veil/[0.08] bg-veil/[0.04] px-2 py-[3px] font-mono text-[7.5px] uppercase tracking-[0.14em] text-dim md:inline-flex">
                    <span className="h-1 w-1 rounded-full bg-ion shadow-[0_0_6px_rgba(100,216,255,0.9)]" /> console
                  </span>
                </div>
              </div>

              {can("admin") && (
                <Link
                  to="/app/users?create=1"
                  className="hidden h-9 items-center gap-1.5 rounded-[10px] border border-veil/10 bg-veil/[0.04] px-3.5 text-[12px] font-medium text-mist transition-colors hover:border-veil/20 hover:bg-veil/[0.07] hover:text-ink sm:inline-flex"
                >
                  Add user <Plus size={13} />
                </Link>
              )}

              <button
                onClick={theme.toggle}
                className="btn btn-quiet btn-icon shrink-0"
                aria-label={theme.mode === "dark" ? "Switch to daylight theme" : "Switch to midnight theme"}
                title={theme.mode === "dark" ? "Daylight theme" : "Midnight theme"}
              >
                {theme.mode === "dark" ? <Sun size={16} /> : <Moon size={16} />}
              </button>

              <button
                onClick={() => setPaletteOpen(true)}
                className="group flex h-9 w-9 items-center justify-center gap-2 rounded-[10px] border border-veil/[0.09] bg-surface/85 text-dim transition-colors hover:border-veil/20 hover:text-ink sm:w-[240px] sm:justify-start sm:px-3.5"
                aria-label="Search platform (Control K)"
              >
                <Search size={13.5} />
                <span className="hidden min-w-0 flex-1 truncate text-left text-[11px] text-dim sm:block">Search records, CVEs, alerts…</span>
                <kbd className="hidden items-center gap-0.5 rounded border border-veil/10 bg-veil/[0.04] px-1.5 py-0.5 font-mono text-[8.5px] text-dim sm:flex">
                  <Command size={9} />K
                </kbd>
              </button>

              <Link
                to="/app/alerts"
                title="Open early warning"
                className="hidden items-center gap-2 rounded-[10px] border border-veil/[0.09] bg-veil/[0.03] px-3 py-2 transition-colors hover:border-veil/20 xl:flex"
              >
                <span
                  className={clsx(
                    "h-1.5 w-1.5 rounded-full",
                    criticalCount > 0 ? "bg-crit shadow-[0_0_7px_rgba(255,77,94,0.8)]" : activeCount > 0 ? "bg-med" : "bg-low",
                  )}
                />
                <span className="tnum font-mono text-[9px] tracking-[0.06em] text-mist">{activeCount} active</span>
                <span className="h-3 w-px bg-veil/10" />
                <span className={clsx("tnum font-mono text-[9px] tracking-[0.06em]", criticalCount > 0 ? "text-crit" : "text-dim")}>
                  {criticalCount} critical
                </span>
              </Link>

              <div className="hidden items-center gap-2 rounded-[10px] border border-veil/[0.09] bg-veil/[0.03] px-3 py-2 2xl:flex">
                <span className="h-1 w-1 rounded-full bg-ion shadow-[0_0_6px_rgba(100,216,255,0.85)]" />
                <span className="tnum font-mono text-[9px] tracking-[0.08em] text-mist">
                  {now.toLocaleTimeString("en-GB", { timeZone: "UTC", hour: "2-digit", minute: "2-digit", hour12: false })} UTC
                </span>
              </div>

              <div className="relative" ref={bellRef}>
                <button
                  className={clsx("btn btn-quiet btn-icon relative", bellOpen && "bg-veil/[0.06] text-ink")}
                  onClick={() => setBellOpen((open) => !open)}
                  aria-label={`Notifications, ${activeCount} active alerts`}
                  aria-expanded={bellOpen}
                >
                  <Bell size={16} />
                  {activeCount > 0 && (
                    <span className={clsx("absolute right-2 top-2 h-2 w-2 rounded-full border-2 border-hull", criticalCount > 0 ? "bg-crit" : "bg-med")} />
                  )}
                </button>
                <AnimatePresence>
                  {bellOpen && (
                    <motion.div
                      initial={{ opacity: 0, y: -6, scale: 0.985 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      exit={{ opacity: 0, y: -4 }}
                      transition={{ duration: 0.16 }}
                      className="absolute right-0 top-[46px] w-[min(360px,calc(100vw-24px))] overflow-hidden rounded-2xl border border-line-strong bg-surface shadow-lift"
                    >
                      <div className="flex items-center justify-between border-b border-line px-3.5 py-2.5">
                        <span className="font-mono text-[8.5px] uppercase tracking-[0.16em] text-dim">Early warning</span>
                        <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-crit">{activeCount} active</span>
                      </div>
                      <div className="max-h-[320px] overflow-y-auto">
                        {(alertSummary?.recent || []).slice(0, 5).map((alert: any) => (
                          <button
                            key={alert.id}
                            onClick={() => {
                              setBellOpen(false);
                              navigate(`/app/alerts?focus=${alert.ref}`);
                            }}
                            className="flex w-full items-start gap-2.5 border-b border-veil/[0.04] px-3.5 py-2.5 text-left hover:bg-veil/[0.03]"
                          >
                            <span className={clsx("mt-1 h-1.5 w-1.5 shrink-0 rounded-full", alert.severity === "critical" ? "bg-crit" : alert.severity === "high" ? "bg-high" : "bg-med")} />
                            <span className="min-w-0 flex-1">
                              <span className="block truncate text-[11.5px] text-ink">{alert.title}</span>
                              <span className="mt-0.5 block font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">
                                {alert.ref} · {relTime(alert.detected_at)} · {titleCase(alert.status)}
                              </span>
                            </span>
                            <SeverityBadge severity={alert.severity} />
                          </button>
                        ))}
                        {!(alertSummary?.recent || []).length && <div className="px-4 py-8 text-center text-[11.5px] text-dim">No alerts have been generated yet.</div>}
                      </div>
                      <div className="flex items-center justify-between px-3.5 py-2.5">
                        <Link to="/app/alerts" onClick={() => setBellOpen(false)} className="font-mono text-[9px] uppercase tracking-[0.12em] text-ion hover:text-crystal">
                          Open alert centre
                        </Link>
                        <span className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">Latest {relTime(alertSummary?.latest_at)}</span>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              <div className="relative" ref={menuRef}>
                <button
                  onClick={() => setMenuOpen((open) => !open)}
                  className={clsx(
                    "flex h-9 items-center gap-2 rounded-full border border-veil/[0.09] bg-veil/[0.03] pl-1 pr-2 transition-colors hover:border-veil/20",
                    menuOpen && "border-veil/20 bg-veil/[0.06]",
                  )}
                  aria-expanded={menuOpen}
                  aria-label="Account menu"
                >
                  <span className="avatar-mark grid h-7 w-7 place-items-center rounded-full font-mono text-[9px] font-semibold tracking-wide">
                    {user?.initials || "—"}
                  </span>
                  <span className="hidden text-left md:block">
                    <span className="block max-w-[110px] truncate text-[11px] text-ink">{user?.full_name}</span>
                    <span className="block font-mono text-[7.5px] uppercase tracking-[0.1em] text-dim">{user?.role}</span>
                  </span>
                  <ChevronDown size={12} className={clsx("hidden text-dim transition-transform md:block", menuOpen && "rotate-180")} />
                </button>
                <AnimatePresence>
                  {menuOpen && (
                    <motion.div
                      initial={{ opacity: 0, y: -6, scale: 0.985 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      exit={{ opacity: 0, y: -4 }}
                      transition={{ duration: 0.16 }}
                      className="absolute right-0 top-[46px] w-[240px] overflow-hidden rounded-2xl border border-line-strong bg-surface shadow-lift"
                    >
                      <div className="border-b border-line px-3.5 py-3">
                        <div className="text-[12px] text-ink">{user?.full_name}</div>
                        <div className="mt-0.5 truncate text-[10.5px] text-dim">{user?.email}</div>
                        <div className="mt-2 inline-flex items-center gap-1.5 rounded border border-ion/25 bg-ion/[0.06] px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-[0.12em] text-ion">
                          <ShieldCheck size={9} /> {titleCase(user?.role)}
                        </div>
                      </div>
                      <div className="p-1">
                        <Link to="/app/settings" onClick={() => setMenuOpen(false)} className="flex items-center gap-2 rounded-md px-2.5 py-2 text-[11.5px] text-mist hover:bg-veil/[0.04] hover:text-ink">
                          <Settings2 size={13} /> Account settings
                        </Link>
                        <Link to="/app/ai" onClick={() => setMenuOpen(false)} className="flex items-center gap-2 rounded-md px-2.5 py-2 text-[11.5px] text-mist hover:bg-veil/[0.04] hover:text-ink">
                          <Bot size={13} /> Aegis AI
                        </Link>
                        <button onClick={signOut} className="flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-[11.5px] text-crit hover:bg-crit/[0.08]">
                          <LogOut size={13} /> Sign out
                        </button>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>
          </header>
        </div>

        <main className="relative mx-auto w-full max-w-[1600px] px-3 pb-8 pt-4 sm:px-4 lg:px-5">
          {/* Opacity-only: a transformed route wrapper would re-anchor fixed
              overlays (map/graph full-screen) to the page instead of the viewport. */}
          <div key={`${location.pathname}:${theme.mode}`} className="route-enter">
            <Outlet />
          </div>
        </main>
      </div>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  );
}
