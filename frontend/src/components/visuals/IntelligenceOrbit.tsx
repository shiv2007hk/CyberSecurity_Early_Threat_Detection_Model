import { useState, type CSSProperties } from "react";
import clsx from "clsx";
import { ArrowRight } from "lucide-react";
import type { LucideIcon } from "lucide-react";

export interface OrbitStage {
  label: string;
  title: string;
  body: string;
  out: string;
  icon: LucideIcon;
}

/* Six stages at 60° on a clockwise orbit. Each node counter-rotates its own
   content from the same --orbit-turn value, so labels stay upright while the
   ring turns; hovering or focusing a stage pauses both together. */
export function IntelligenceOrbit({ stages, className }: { stages: OrbitStage[]; className?: string }) {
  const [active, setActive] = useState(0);
  const [showAll, setShowAll] = useState(false);
  const stage = stages[active];

  return (
    <div className={clsx("orbit-layout", className)}>
      <div
        className="orbit"
        role="group"
        aria-label="Six-stage intelligence pipeline. Select a stage to read what it produces."
      >
        <div className="orbit-aura" aria-hidden="true" />

        <div className="orbit-ring">
          <span className="orbit-track" aria-hidden="true" />
          <span className="orbit-track orbit-track--inner" aria-hidden="true" />
          {stages.map((entry, index) => (
            <span
              key={`spoke-${entry.label}`}
              className="orbit-spoke"
              aria-hidden="true"
              style={{ "--a": `${index * 60}deg` } as CSSProperties}
            />
          ))}
          <span className="orbit-sweep" aria-hidden="true" />

          <div className="orbit-flow" aria-hidden="true">
            <span className="orbit-particle" style={{ "--a": "24deg" } as CSSProperties} />
            <span className="orbit-particle" style={{ "--a": "148deg" } as CSSProperties} />
            <span className="orbit-particle" style={{ "--a": "272deg" } as CSSProperties} />
          </div>

          {stages.map((entry, index) => (
            <div key={entry.label} className="orbit-node" style={{ "--a": `${index * 60}deg` } as CSSProperties}>
              <div className="orbit-node-spin">
                <div className="orbit-node-upright">
                  <button
                    type="button"
                    className={clsx("orbit-chip", index === active && "is-active")}
                    aria-pressed={index === active}
                    aria-label={`Stage ${index + 1}, ${entry.label}: ${entry.title}`}
                    onClick={() => setActive(index)}
                  >
                    <span className="orbit-beacon" style={{ "--i": index } as CSSProperties} aria-hidden="true" />
                    <span className="orbit-chip-index" aria-hidden="true">0{index + 1}</span>
                    <entry.icon size={16} strokeWidth={1.6} aria-hidden="true" />
                    <span className="orbit-chip-label">{entry.label}</span>
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="orbit-hub">
          <span className="orbit-hub-halo" aria-hidden="true" />
          <div className="orbit-hub-core">
            <span className="orbit-hub-kicker">Intelligence engine</span>
            <span className="orbit-hub-name">
              CYBER <em>GUARD</em>
            </span>
            <span className="orbit-hub-meta">{stages.length} stages · evidence first</span>
          </div>
        </div>
      </div>

      <aside className="orbit-panel" aria-live="polite">
        <div className="orbit-panel-head">
          <span className="orbit-panel-kicker">
            Stage 0{active + 1} · {stage.label}
          </span>
          <span className="orbit-panel-out">{stage.out}</span>
        </div>
        <h3 className="orbit-panel-title">{stage.title}</h3>
        <p className="orbit-panel-body">{stage.body}</p>

        <div className="orbit-panel-foot">
          <span className="orbit-panel-hint">Hover a stage to pause · select one to read</span>
          <button
            type="button"
            className="orbit-expand"
            aria-expanded={showAll}
            onClick={() => setShowAll((value) => !value)}
          >
            {showAll ? "Hide stages" : "View all stages"}
            <ArrowRight size={13} className={clsx("transition-transform", showAll && "rotate-90")} aria-hidden="true" />
          </button>
        </div>

        {showAll && (
          <ol className="orbit-list">
            {stages.map((entry, index) => (
              <li key={entry.label}>
                <button
                  type="button"
                  className={clsx("orbit-list-row", index === active && "is-active")}
                  aria-current={index === active ? "true" : undefined}
                  onClick={() => setActive(index)}
                >
                  <span className="orbit-list-index">0{index + 1}</span>
                  <span className="orbit-list-copy">
                    <span className="orbit-list-label">{entry.label}</span>
                    <span className="orbit-list-title">{entry.title}</span>
                  </span>
                  <span className="orbit-list-out">{entry.out}</span>
                </button>
              </li>
            ))}
          </ol>
        )}
      </aside>
    </div>
  );
}
