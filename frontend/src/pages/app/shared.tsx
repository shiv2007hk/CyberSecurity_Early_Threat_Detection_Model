import type { ReactNode } from "react";
import clsx from "clsx";
import { titleCase, riskColor } from "../../lib/format";
import { palette, tone } from "../../lib/theme";

export function FilterSelect({
  label,
  value,
  onChange,
  options,
  className,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
  className?: string;
}) {
  return (
    <label className={clsx("min-w-0", className)}>
      <span className="field-label">{label}</span>
      <select className="field" value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function FieldLabel({ label, hint, children, className }: { label: string; hint?: string; children: ReactNode; className?: string }) {
  return (
    <label className={clsx("block min-w-0", className)}>
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-[9.5px] leading-relaxed text-dim">{hint}</span>}
    </label>
  );
}

export function DrawerSection({
  title,
  kicker,
  right,
  children,
  className,
}: {
  title: ReactNode;
  kicker?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={clsx("border-t border-line py-4 first:border-t-0 first:pt-0", className)}>
      <div className="mb-3 flex items-start justify-between gap-3">
        <div>
          {kicker && <div className="panel-kicker mb-1">{kicker}</div>}
          <h3 className="text-[12px] font-semibold text-ink">{title}</h3>
        </div>
        {right}
      </div>
      {children}
    </section>
  );
}

export type EvidenceItem = { label: string; value: string };

export function normalizeEvidence(items: unknown): EvidenceItem[] {
  if (!Array.isArray(items)) return [];
  return items
    .map((item, index) => {
      if (typeof item === "string") return { label: `Evidence ${index + 1}`, value: item };
      if (item && typeof item === "object") {
        const record = item as Record<string, unknown>;
        const label = String(record.label ?? record.name ?? record.key ?? `Evidence ${index + 1}`);
        const value = String(record.value ?? record.detail ?? record.text ?? record.note ?? "—");
        return { label, value };
      }
      return { label: `Evidence ${index + 1}`, value: String(item) };
    })
    .filter((entry) => entry.value !== "");
}

export function EvidenceList({ items, empty = "No evidence attached." }: { items: unknown; empty?: string }) {
  const rows = normalizeEvidence(items);
  if (!rows.length) return <p className="text-[11px] text-dim">{empty}</p>;
  return (
    <ul className="space-y-1.5">
      {rows.map((row, index) => (
        <li key={`${row.label}-${index}`} className="flex items-start gap-2 rounded-md border border-line bg-shade/20 px-2.5 py-2">
          <span className="mt-[5px] h-1 w-1 shrink-0 rounded-full bg-ion/70" />
          <div className="min-w-0">
            <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">{row.label}</span>
            <p className="mt-0.5 break-words text-[11px] leading-relaxed text-ink">{row.value}</p>
          </div>
        </li>
      ))}
    </ul>
  );
}

export function ScoreChip({ score, suffix = "" }: { score?: number | null; suffix?: string }) {
  if (score === null || score === undefined || Number.isNaN(Number(score))) return <span className="text-dim">—</span>;
  const value = Number(score);
  return (
    <span className="tnum inline-flex items-center gap-1.5 font-mono text-[11px]" style={{ color: riskColor(value) }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: riskColor(value) }} />
      {value.toFixed(1)}
      {suffix}
    </span>
  );
}

export function StatRow({ entries, className }: { entries: Array<{ label: string; value: ReactNode; tone?: string }>; className?: string }) {
  return (
    <div className={clsx("flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[9px] uppercase tracking-[0.1em]", className)}>
      {entries.map((entry) => (
        <span key={entry.label} className="text-dim">
          {entry.label} <span className={clsx("tnum text-[10px] normal-case tracking-normal", entry.tone || "text-ink")}>{entry.value}</span>
        </span>
      ))}
    </div>
  );
}

export function SeverityDot({ severity }: { severity?: string | null }) {
  const map: Record<string, string> = {
    critical: "bg-crit",
    high: "bg-high",
    medium: "bg-med",
    low: "bg-low",
    info: "bg-info",
    unknown: "bg-dim",
  };
  return <span className={clsx("inline-block h-1.5 w-1.5 rounded-full", map[String(severity || "unknown").toLowerCase()] || "bg-dim")} />;
}

export function TogglePill({ active, onClick, children }: { active: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button
      onClick={onClick}
      aria-pressed={active}
      className={clsx("btn btn-sm", active ? "btn-primary" : "btn-ghost")}
    >
      {children}
    </button>
  );
}

export function MiniBar({ value, max = 100, color, height = 3 }: { value: number; max?: number; color?: string; height?: number }) {
  const pct = Math.max(2, Math.min(100, (value / (max || 1)) * 100));
  return (
    <div className="w-full overflow-hidden rounded-full bg-veil/[0.06]" style={{ height }}>
      <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, background: tone(color) || palette().ion }} />
    </div>
  );
}

export function SectionLabel({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-2 flex items-center justify-between gap-2">
      <span className="font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">{children}</span>
      {right}
    </div>
  );
}

export { titleCase };
