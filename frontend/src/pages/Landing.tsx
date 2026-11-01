import { useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  Boxes,
  Bot,
  BrainCircuit,
  Check,
  Crosshair,
  Database,
  FileSearch,
  Layers,
  LineChart,
  Menu,
  Moon,
  Network,
  Radar,
  ScanSearch,
  ShieldCheck,
  Sparkles,
  Sun,
  Users,
  X,
} from "lucide-react";
import clsx from "clsx";
import { api } from "../lib/api";
import { fmtDate, fmtNumber, titleCase } from "../lib/format";
import { tone } from "../lib/theme";
import { AnimatedNumber, LogoMark } from "../components/ui";
import { IntelligenceOrbit } from "../components/visuals/IntelligenceOrbit";
import { useAuth } from "../context/AuthContext";
import { useTheme } from "../lib/theme";

const VIDEO = "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260912_105953_21ad8049-9088-4a00-bad3-aee6b5575a2b.mp4";
const POSTER = "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260912_105822_bf7c2d53-9957-4521-bbbf-7c1ab7a70130.png";

const NAV = [
  { id: "top", label: "Home" },
  { id: "platform", label: "Platform" },
  { id: "intelligence", label: "Intelligence" },
  { id: "modules", label: "Modules" },
];

const CAPS = [
  { title: "Threat Intelligence", note: "Normalised reporting with provenance attached", icon: Radar },
  { title: "Asset Correlation", note: "Validated product and version matching", icon: Network },
  { title: "Early Warning", note: "Deterministic rules with evidence linked", icon: ShieldCheck },
];

const STAGES = [
  {
    label: "Ingest",
    title: "Collect reporting",
    body: "Connectors pull advisories, exploited-vulnerability catalogues, scoring feeds and partner reporting. Failures surface as failures.",
    out: "Source record",
    icon: Database,
  },
  {
    label: "Normalise",
    title: "Resolve a common shape",
    body: "Records are deduplicated, timestamps normalised to UTC and identifiers extracted into structured fields.",
    out: "Canonical record",
    icon: Layers,
  },
  {
    label: "Classify",
    title: "Show the reasoning",
    body: "A deterministic NLP pipeline classifies the report and extracts entities, with method, confidence and limits visible.",
    out: "Classification",
    icon: BrainCircuit,
  },
  {
    label: "Correlate",
    title: "Connect the reports",
    body: "Shared CVEs, products, indicators and lexical evidence are weighted into a graph with analyst-readable reasons on every edge.",
    out: "Correlation edge",
    icon: Network,
  },
  {
    label: "Validate",
    title: "Verify the exposure claim",
    body: "A vulnerability is only matched to an asset when product aliases and version ranges validate. Text similarity is never exposure.",
    out: "Validated match",
    icon: ScanSearch,
  },
  {
    label: "Warn",
    title: "Raise a defensible warning",
    body: "Rules assess known exploitation, corroboration, velocity and critical-asset intersection. Nothing executes automatically.",
    out: "Alert + action",
    icon: ShieldCheck,
  },
];

const MODULES = [
  { title: "Command centre", summary: "One operational picture across intelligence, risk and exposure.", icon: Radar, to: "/app" },
  { title: "Threat intelligence", summary: "Filter, investigate and annotate incoming reporting.", icon: Activity, to: "/app/threats" },
  { title: "Vulnerabilities", summary: "CVSS, EPSS and known-exploited evidence in one record.", icon: FileSearch, to: "/app/vulnerabilities" },
  { title: "Exposure matching", summary: "Only validated product and version matches become exposure.", icon: Boxes, to: "/app/exposure" },
  { title: "Explainable risk", summary: "A transparent score with a full contribution breakdown.", icon: Crosshair, to: "/app/risk" },
  { title: "Early warning", summary: "Deterministic rules, deduplicated and evidence-backed.", icon: Sparkles, to: "/app/alerts" },
  { title: "Recommendations", summary: "Defensive actions with ownership and due dates.", icon: ShieldCheck, to: "/app/recommendations" },
  { title: "Advanced analytics", summary: "Temporal, categorical, geographic and relational views.", icon: LineChart, to: "/app/analytics" },
  { title: "Aegis AI", summary: "Grounded answers over platform records, with citations.", icon: Bot, to: "/app/ai" },
  { title: "Governance", summary: "Roles, audit trails, sources and evaluation.", icon: Users, to: "/app/settings" },
];

const SOURCE_LABELS: Record<string, string> = {
  nvd: "NVD",
  cisa_kev: "CISA KEV",
  epss: "EPSS",
  mitre: "MITRE ATT&CK",
  otx: "AlienVault OTX",
  abuseipdb: "AbuseIPDB",
  shodan: "Shodan",
  github: "GitHub Advisories",
  cve: "CVE.org",
};

const SEV_COLORS: Record<string, string> = {
  Critical: "#ff4d5e",
  High: "#ff963d",
  Medium: "#ffd166",
  Low: "#42c98a",
  Informational: "#78b7ff",
  Info: "#78b7ff",
};

function useOverview() {
  return useQuery({
    queryKey: ["public-overview"],
    queryFn: () => api<any>("/public/overview"),
    staleTime: 60_000,
  });
}

function Rise({ children, delay = 0, className }: { children: ReactNode; delay?: number; className?: string }) {
  return (
    <div className={clsx("tpl-rise", className)} style={{ "--d": `${delay}ms` } as CSSProperties}>
      {children}
    </div>
  );
}

function sourceLabel(source: any) {
  return SOURCE_LABELS[source?.key] || titleCase(source?.key || source?.category || "source");
}

function statusColor(status?: string) {
  if (status === "operational") return "#2f8f68";
  if (status === "degraded") return "#b8862f";
  if (status === "offline") return "#c0444f";
  return "#8a93a6";
}

export default function Landing() {
  const { user } = useAuth();
  const { data } = useOverview();
  const theme = useTheme();
  const [active, setActive] = useState("top");
  const [open, setOpen] = useState(false);
  const [stuck, setStuck] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);

  const metrics = data?.metrics || {};
  const sources: any[] = data?.source_status || [];
  const severity: any[] = data?.severity_distribution || [];
  const online = Number(metrics.sources_online || 0);
  const totalSources = Number(metrics.sources_total || 0);
  const coverage = totalSources ? Math.max(3, Math.min(100, (online / totalSources) * 100)) : 0;
  const sevTotal = useMemo(() => severity.reduce((sum, entry) => sum + Number(entry.value || 0), 0), [severity]);
  const sourcePreview = useMemo(
    () => [...sources].sort((a, b) => Number(b.status === "operational") - Number(a.status === "operational")).slice(0, 5),
    [sources],
  );
  const enterHref = user ? "/app" : "/login";

  useEffect(() => {
    const video = videoRef.current;
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    const sync = () => {
      if (!video) return;
      if (query.matches) video.pause();
      else video.play().catch(() => undefined);
    };
    sync();
    query.addEventListener("change", sync);
    return () => query.removeEventListener("change", sync);
  }, []);

  useEffect(() => {
    const onScroll = () => setStuck(window.scrollY > 12);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    if (!window.location.hash) return;
    const target = document.querySelector(window.location.hash);
    if (target) requestAnimationFrame(() => target.scrollIntoView({ block: "start" }));
  }, []);

  useEffect(() => {
    const ids = ["top", "platform", "intelligence", "modules"];
    const sections = ids.map((id) => document.getElementById(id)).filter(Boolean) as HTMLElement[];
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((entry) => entry.isIntersecting);
        if (visible.length) setActive(visible[0].target.id);
      },
      { rootMargin: "-42% 0px -52% 0px", threshold: 0 },
    );
    sections.forEach((section) => observer.observe(section));
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <div className="tpl">
      <div className="tpl-sky" aria-hidden="true">
        <video ref={videoRef} autoPlay muted loop playsInline preload="metadata" poster={POSTER}>
          <source src={VIDEO} type="video/mp4" />
        </video>
      </div>
      <div className="tpl-veil" aria-hidden="true" />
      <div className="tpl-grain" aria-hidden="true" />

      <header className="tpl-header" data-stuck={stuck}>
        <Rise delay={0}>
          <Link to="/" className="tpl-brand" aria-label="CyberGuard home">
            <span className="tpl-brand-mark">
              <LogoMark size={24} />
            </span>
            <span className="tpl-brand-name">
              CYBER
              <small>GUARD</small>
            </span>
          </Link>
        </Rise>

        <nav className="tpl-nav" aria-label="Primary">
          {NAV.map((item) => (
            <a key={item.id} href={`#${item.id}`} data-active={active === item.id} onClick={() => setActive(item.id)}>
              {item.label}
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={theme.toggle}
            className="grid h-10 w-10 shrink-0 place-items-center rounded-full border border-line bg-veil/[0.06] text-mist transition-colors hover:border-line-strong hover:text-ink"
            aria-label={theme.mode === "dark" ? "Switch to daylight theme" : "Switch to midnight theme"}
            title={theme.mode === "dark" ? "Daylight theme" : "Midnight theme"}
          >
            {theme.mode === "dark" ? <Sun size={15} /> : <Moon size={15} />}
          </button>
          <Rise delay={140}>
            <Link to={enterHref} className="tpl-cta">
              Enter Console <ArrowUpRight size={14} />
            </Link>
          </Rise>
          <button className="tpl-menu-btn" onClick={() => setOpen((value) => !value)} aria-label={open ? "Close menu" : "Open menu"} aria-expanded={open}>
            {open ? <X size={16} /> : <Menu size={16} />}
          </button>
        </div>

        {open && (
          <div className="tpl-mobile">
            {NAV.map((item) => (
              <a key={item.id} href={`#${item.id}`} onClick={() => { setActive(item.id); setOpen(false); }}>
                {item.label} <ArrowRight size={13} />
              </a>
            ))}
            <Link to={enterHref} className="tpl-mobile-cta" onClick={() => setOpen(false)}>
              Enter Console <ArrowUpRight size={13} />
            </Link>
          </div>
        )}
      </header>

      <main>
        <section id="top" className="tpl-hero">
          <div className="tpl-hero-grid">
            <div className="tpl-copy">
              <Rise delay={280}>
                <div className="tpl-eyebrow">AI-driven threat intelligence &amp; risk analytics</div>
              </Rise>

              <Rise delay={380}>
                <h1 className="tpl-h1">
                  See the Threat.
                  <br />
                  <em>Know the Risk.</em>
                </h1>
              </Rise>

              <Rise delay={500}>
                <div className="tpl-tagline" aria-label="Detect. Correlate. Prioritise.">
                  <span>Detect</span>
                  <span>Correlate</span>
                  <span>Prioritise</span>
                </div>
              </Rise>

              <Rise delay={580}>
                <p className="tpl-support">See the threats. Understand the risks. Secure what matters.</p>
              </Rise>

              <Rise delay={640}>
                <p className="tpl-desc">
                  An intelligent cybersecurity platform connecting threat intelligence, vulnerabilities and organisational
                  assets to deliver explainable risk assessments and actionable early warnings.
                </p>
              </Rise>

              <Rise delay={700}>
                <div className="tpl-copy-links">
                  <a className="tpl-textlink" href="#platform">
                    See how the pipeline works <ArrowRight size={13} />
                  </a>
                  <span className="tpl-mode-chip">
                    <i /> {fmtNumber(metrics.threat_records)} threat records under analysis
                  </span>
                </div>
              </Rise>
            </div>

            <Rise delay={760}>
              <aside className="tpl-panel" aria-label="AI-driven intelligence summary">
                <div className="tpl-panel-head">
                  <b>AI-DRIVEN</b>
                  <span className="tpl-live">
                    <i /> Active
                  </span>
                </div>

                <div className="tpl-panel-icon">
                  <ShieldCheck size={21} strokeWidth={1.6} />
                </div>
                <h2 className="tpl-panel-title">Cyber Threat Intelligence &amp; Risk Prioritisation</h2>
                <p className="tpl-panel-copy">
                  Correlates reporting, exploited vulnerabilities and registered assets into explainable,
                  evidence-linked warnings.
                </p>

                <div className="tpl-progress">
                  <div className="tpl-progress-meta">
                    <span>Source coverage</span>
                    <b>{totalSources ? `${online} / ${totalSources} online` : "Awaiting data"}</b>
                  </div>
                  <div className="tpl-progress-track" role="img" aria-label={`${online} of ${totalSources} sources online`}>
                    <span className="tpl-progress-fill" style={{ width: `${coverage}%` }} />
                    <span className="tpl-progress-knob" style={{ left: `${coverage}%` }} />
                  </div>
                </div>

                <div className="tpl-panel-rows">
                  <div className="tpl-panel-row">
                    <span>Stored threat records</span>
                    <b>{fmtNumber(metrics.threat_records)}</b>
                  </div>
                  <div className="tpl-panel-row">
                    <span>Known-exploited records</span>
                    <b>{fmtNumber(metrics.known_exploited)}</b>
                  </div>
                  <div className="tpl-panel-row">
                    <span>Correlated pairs</span>
                    <b>{fmtNumber(metrics.correlated_pairs)}</b>
                  </div>
                </div>
              </aside>
            </Rise>
          </div>

          <Rise delay={1000}>
            <div className="tpl-caps">
              {CAPS.map(({ title, note, icon: Icon }, index) => (
                <div className="tpl-cap" key={title}>
                  <div className="tpl-cap-index">0{index + 1}</div>
                  <div className="tpl-cap-title">
                    <Icon size={12} className="text-ion/70" /> {title}
                  </div>
                  <div className="tpl-cap-note">{note}</div>
                </div>
              ))}
            </div>
          </Rise>

          <a href="#platform" className="tpl-float">
            Meet Aegis AI <ArrowUpRight size={14} />
          </a>
        </section>

        <section id="platform" className="tpl-section" data-tone="white">
          <div className="tpl-wrap">
            <div className="tpl-sec-head">
              <div>
                <div className="tpl-kicker">The platform</div>
                <h2 className="tpl-h2">From raw reporting to a defensible warning.</h2>
              </div>
              <p className="tpl-lead">
                Six stages carry every record. Each keeps its source, method, confidence and limitation attached, so a
                warning can be inspected rather than trusted on faith.
              </p>
            </div>

            <IntelligenceOrbit stages={STAGES} />
          </div>
        </section>

        <section id="intelligence" className="tpl-section">
          <div className="tpl-wrap">
            <div className="tpl-sec-head">
              <div>
                <div className="tpl-kicker">Intelligence</div>
                <h2 className="tpl-h2">The record, not a performance claim.</h2>
              </div>
              <p className="tpl-lead">
                Every figure below is read live from the platform API against stored records. No customer counts,
                accuracy claims or connector states are invented for this page.
              </p>
            </div>

            <div className="tpl-stats">
              <div className="tpl-stat">
                <div className="tpl-stat-label">Threat records</div>
                <div className="tpl-stat-value">
                  <AnimatedNumber value={metrics.threat_records} />
                </div>
                <div className="tpl-stat-note">Normalised, classified and source-attributed.</div>
              </div>
              <div className="tpl-stat">
                <div className="tpl-stat-label">Sources online</div>
                <div className="tpl-stat-value">{totalSources ? `${online} / ${totalSources}` : "—"}</div>
                <div className="tpl-stat-note">Connector state at the last stored sync.</div>
              </div>
              <div className="tpl-stat">
                <div className="tpl-stat-label">Known exploited</div>
                <div className="tpl-stat-value">
                  <AnimatedNumber value={metrics.known_exploited} />
                </div>
                <div className="tpl-stat-note">Vulnerability records with exploitation evidence.</div>
              </div>
              <div className="tpl-stat">
                <div className="tpl-stat-label">Alerts generated</div>
                <div className="tpl-stat-value">
                  <AnimatedNumber value={metrics.alerts_generated} />
                </div>
                <div className="tpl-stat-note">Produced by deterministic rules, not live attacks.</div>
              </div>
            </div>

            <div className="tpl-evidence-grid">
              <div className="tpl-card">
                <div className="tpl-card-head">
                  <span>Severity composition</span>
                  <span>{fmtNumber(sevTotal)} records</span>
                </div>
                <div className="tpl-sevbar">
                  {severity.map((entry) => (
                    <span
                      key={entry.name}
                      style={{
                        width: sevTotal ? `${(Number(entry.value) / sevTotal) * 100}%` : "0%",
                        background: tone(SEV_COLORS[entry.name] || "#78b7ff"),
                      }}
                      title={`${entry.name}: ${entry.value}`}
                    />
                  ))}
                </div>
                <div className="tpl-sevlegend">
                  {severity.map((entry) => (
                    <span key={entry.name}>
                      <i style={{ background: tone(SEV_COLORS[entry.name] || "#78b7ff") }} />
                      {entry.name} · {fmtNumber(entry.value)}
                    </span>
                  ))}
                </div>
                <div className="tpl-note">
                  <ShieldCheck size={12} className="mt-[1px] shrink-0" />
                  <span>
                    Latest stored intelligence: {fmtDate(metrics.last_intelligence_at, true)} · {fmtNumber(metrics.sources_online)}
                    of {fmtNumber(metrics.sources_total)} connectors online.
                  </span>
                </div>
              </div>

              <div className="tpl-card">
                <div className="tpl-card-head">
                  <span>Source health</span>
                  <span>{online} online</span>
                </div>
                <div className="tpl-source-list">
                  {sourcePreview.map((source) => (
                    <div className="tpl-source" key={source.key || source.id}>
                      <span className="tpl-source-dot" style={{ background: statusColor(source.status) }} />
                      <span className="tpl-source-name">{sourceLabel(source)}</span>
                      <span className="tpl-source-state">{titleCase(source.status)}</span>
                    </div>
                  ))}
                  {!sourcePreview.length && <div className="tpl-source-state">Source state is unavailable.</div>}
                </div>
                <div className="tpl-note">
                  <Database size={12} className="mt-[1px] shrink-0" />
                  <span>Connector state is reported from the last stored sync. A failed fetch is shown as failed.</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section id="modules" className="tpl-section" data-tone="pale">
          <div className="tpl-wrap">
            <div className="tpl-sec-head">
              <div>
                <div className="tpl-kicker">Modules</div>
                <h2 className="tpl-h2">Ten modules. One operational picture.</h2>
              </div>
              <p className="tpl-lead">
                Move from incoming reporting to validated exposure, explainable risk and evidence-backed warning without
                leaving the console. Role-scoped access is enforced by the API.
              </p>
            </div>

            <div className="tpl-modules">
              {MODULES.map(({ title, summary, icon: Icon, to }) => (
                <Link className="tpl-module" key={title} to={user ? to : "/login"}>
                  <span className="tpl-module-icon">
                    <Icon size={15} />
                  </span>
                  <span className="tpl-module-title">{title}</span>
                  <span className="tpl-module-summary">{summary}</span>
                  <span className="tpl-module-arrow">
                    {user ? "Open module" : "Sign in to open"} <ArrowUpRight size={10} />
                  </span>
                </Link>
              ))}
            </div>
          </div>
        </section>

        <section className="tpl-band">
          <div className="tpl-band-inner">
            <div className="tpl-band-grid">
              <div>
                <div className="tpl-band-kicker">Inside the console</div>
                <h2>Total visibility. Total control.</h2>
                <p>
                  The watch floor opens on stored intelligence, validated exposure and active warning. Every figure
                  resolves to a labelled record, and every response waits for a human.
                </p>
                <div className="tpl-band-points">
                  {[
                    "Validated exposure, not text similarity",
                    "Explainable risk scores you can reproduce",
                    "Human approval on every response",
                  ].map((point) => (
                    <div className="tpl-band-point" key={point}>
                      <Check size={13} /> {point}
                    </div>
                  ))}
                </div>
                <Link to={enterHref} className="tpl-band-cta">
                  Enter Console <ArrowUpRight size={14} />
                </Link>
              </div>

              <div className="tpl-console" aria-label="Command centre preview">
                <div className="tpl-console-head">
                  <span>Watch floor · snapshot</span>
                  <span>live platform data</span>
                </div>
                <div className="tpl-console-rows">
                  <div className="tpl-console-row">
                    <span>Threat records</span>
                    <b>{fmtNumber(metrics.threat_records)}</b>
                  </div>
                  <div className="tpl-console-row">
                    <span>Active warnings</span>
                    <b>{fmtNumber(metrics.alerts_generated)}</b>
                  </div>
                  <div className="tpl-console-row">
                    <span>Assets monitored</span>
                    <b>{fmtNumber(metrics.assets_monitored)}</b>
                  </div>
                  <div className="tpl-console-row">
                    <span>Sources online</span>
                    <b>{totalSources ? `${online} / ${totalSources}` : "—"}</b>
                  </div>
                  <div className="tpl-console-row">
                    <span>Correlated pairs</span>
                    <b>{fmtNumber(metrics.correlated_pairs)}</b>
                  </div>
                </div>
                <div className="tpl-console-foot">Every figure links back to its stored record</div>
              </div>
            </div>
          </div>
        </section>

        <section className="tpl-final">
          <div className="tpl-final-inner">
            <div className="tpl-kicker" style={{ justifyContent: "center" }}>
              Access the platform
            </div>
            <h2>Intelligence before impact.</h2>
            <p>
              Connect threat intelligence, vulnerabilities and your assets. See what matters, understand why, and act
              before impact.
            </p>
            <div className="tpl-final-actions">
              <Link to={enterHref} className="tpl-cta">
                {user ? "Open command centre" : "Enter Console"} <ArrowUpRight size={14} />
              </Link>
              {!user && (
                <Link to="/register" className="tpl-final-ghost">
                  Create a viewer account <ArrowRight size={13} />
                </Link>
              )}
              {user && (
                <Link to="/app/analytics" className="tpl-final-ghost">
                  Open analytics <ArrowRight size={13} />
                </Link>
              )}
            </div>
          </div>
        </section>
      </main>

      <footer className="tpl-footer">
        <div className="tpl-footer-inner">
          <div className="tpl-footer-top">
            <div className="tpl-footer-brand">
              <div className="flex items-center gap-2.5 text-[#eaf4ff]">
                <span className="grid h-8 w-8 place-items-center rounded-[9px] border border-white/10 bg-white/[0.05]">
                  <LogoMark size={20} />
                </span>
                <span className="text-[12px] font-semibold tracking-[0.16em]">CYBERGUARD AI</span>
              </div>
              <p>
                An AI-driven cyber threat intelligence and risk analytics platform: validated exposure, explainable
                risk and evidence-linked early warning.
              </p>
            </div>

            <div className="tpl-footer-col">
              <h3>Intelligence</h3>
              <Link to="/app/threats">Threat ledger</Link>
              <Link to="/app/vulnerabilities">Vulnerabilities</Link>
              <Link to="/app/assets">Asset inventory</Link>
              <Link to="/app/threat-map">Global threat map</Link>
            </div>

            <div className="tpl-footer-col">
              <h3>Operations</h3>
              <Link to="/app/alerts">Early warning</Link>
              <Link to="/app/risk">Risk assessment</Link>
              <Link to="/app/recommendations">Recommendations</Link>
              <Link to="/app/reports">Reports</Link>
            </div>

            <div className="tpl-footer-col">
              <h3>Access</h3>
              <Link to={enterHref}>Enter console</Link>
              <Link to="/register">Create account</Link>
              <Link to="/app/ai">Aegis AI</Link>
              <Link to="/app/sources">Sources &amp; ingestion</Link>
            </div>
          </div>
          <div className="tpl-footer-bottom">
            <span>© 2026 CyberGuard AI</span>
            <span>Advisory platform · no automated containment</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
