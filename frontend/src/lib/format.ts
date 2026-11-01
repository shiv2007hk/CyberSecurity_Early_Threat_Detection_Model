import { palette } from "./theme";

export const SEVERITY: Record<string, { label: string; hex: string; text: string; bg: string; border: string; dot: string }> = {
  critical: { label: "Critical", get hex() { return palette().crit; }, text: "text-crit", bg: "bg-crit/10", border: "border-crit/35", dot: "bg-crit" },
  high: { label: "High", get hex() { return palette().high; }, text: "text-high", bg: "bg-high/10", border: "border-high/35", dot: "bg-high" },
  medium: { label: "Medium", get hex() { return palette().med; }, text: "text-med", bg: "bg-med/10", border: "border-med/35", dot: "bg-med" },
  low: { label: "Low", get hex() { return palette().low; }, text: "text-low", bg: "bg-low/10", border: "border-low/35", dot: "bg-low" },
  informational: { label: "Info", get hex() { return palette().info; }, text: "text-info", bg: "bg-info/10", border: "border-info/35", dot: "bg-info" },
  unknown: { label: "Unrated", get hex() { return palette().neutral; }, text: "text-mist", bg: "bg-veil/5", border: "border-veil/15", dot: "bg-mist" },
};

export const STATUS_TONE: Record<string, string> = {
  new: "border-info/30 bg-info/10 text-info",
  acknowledged: "border-violet/30 bg-violet/10 text-violet",
  investigating: "border-med/30 bg-med/10 text-med",
  resolved: "border-low/30 bg-low/10 text-low",
  dismissed: "border-veil/10 bg-veil/5 text-dim",
  open: "border-info/30 bg-info/10 text-info",
  in_progress: "border-med/30 bg-med/10 text-med",
  done: "border-low/30 bg-low/10 text-low",
  operational: "border-low/30 bg-low/10 text-low",
  degraded: "border-med/30 bg-med/10 text-med",
  offline: "border-crit/30 bg-crit/10 text-crit",
  unconfigured: "border-veil/10 bg-veil/5 text-dim",
  potentially_exposed: "border-med/30 bg-med/10 text-med",
  needs_verification: "border-violet/30 bg-violet/10 text-violet",
  confirmed: "border-crit/30 bg-crit/10 text-crit",
  not_affected: "border-low/30 bg-low/10 text-low",
  live: "border-low/30 bg-low/10 text-low",
  cached: "border-med/30 bg-med/10 text-med",
  recorded: "border-violet/30 bg-violet/10 text-violet",
};

export function severityMeta(value?: string | null) {
  return SEVERITY[(value || "unknown").toLowerCase()] || SEVERITY.unknown;
}

export function titleCase(value?: string | null): string {
  if (!value) return "—";
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .replace(/\bIds\b/g, "IDs")
    .replace(/\bIp\b/g, "IP")
    .replace(/\bCve\b/g, "CVE")
    .replace(/\bCvss\b/g, "CVSS")
    .replace(/\bEpss\b/g, "EPSS")
    .replace(/\bKev\b/g, "KEV")
    .replace(/\bRce\b/g, "RCE");
}

const DATE_OPTS: Intl.DateTimeFormatOptions = { day: "2-digit", month: "short", year: "numeric" };

export function fmtDate(value?: string | null, withTime = false): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const base = date.toLocaleDateString("en-GB", DATE_OPTS);
  if (!withTime) return base;
  return `${base} · ${date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false })}`;
}

export function fmtTime(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false });
}

export function relTime(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const diff = Date.now() - date.getTime();
  const future = diff < 0;
  const abs = Math.abs(diff);
  const minutes = Math.round(abs / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return future ? `in ${minutes}m` : `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return future ? `in ${hours}h` : `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return future ? `in ${days}d` : `${days}d ago`;
  return fmtDate(value);
}

export function fmtNumber(value?: number | null, digits = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return value.toLocaleString("en-GB", { maximumFractionDigits: digits, minimumFractionDigits: digits });
}

export function fmtPct(value?: number | null, digits = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  const normalised = value <= 1 && value >= 0 ? value * 100 : value;
  return `${normalised.toFixed(digits)}%`;
}

export function riskColor(score?: number | null): string {
  const colors = palette();
  if (score === null || score === undefined) return colors.neutral;
  if (score >= 75) return colors.crit;
  if (score >= 50) return colors.high;
  if (score >= 25) return colors.med;
  return colors.low;
}

export function initialsOf(name?: string | null): string {
  if (!name) return "—";
  return name
    .split(/\s+/)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() || "")
    .join("");
}

export function objectEntries(value: unknown): Array<[string, string]> {
  if (!value || typeof value !== "object") return [];
  return Object.entries(value as Record<string, unknown>).map(([key, val]) => [
    key,
    Array.isArray(val) ? val.join(", ") : String(val ?? "—"),
  ]);
}

export function relativeCsvPath(path: string) {
  return path;
}

export function parseFocus(search: string): string | null {
  const params = new URLSearchParams(search);
  return params.get("focus");
}

export function categoryColors(): string[] {
  const p = palette();
  return [p.pulse, p.ion, p.crystal, p.violet, p.info, p.med, p.high, p.crit, p.low, p.neutral, p.mist];
}
