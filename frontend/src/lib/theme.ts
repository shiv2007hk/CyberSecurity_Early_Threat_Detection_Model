import { useSyncExternalStore } from "react";

export type ThemeMode = "dark" | "light";

const STORAGE_KEY = "aegis.theme";

export interface ChartTokens {
  grid: string;
  axis: string;
  surface: string;
  tooltip: string;
  ink: string;
  mist: string;
  dim: string;
  hair: string;
  pulse: string;
  ion: string;
  crystal: string;
  violet: string;
  crit: string;
  high: string;
  med: string;
  low: string;
  info: string;
  neutral: string;
  mapDeep: string;
  mapMid: string;
  mapLight: string;
  plotInk: string;
  plotMist: string;
  strongInk: string;
}

export const PALETTE: Record<ThemeMode, ChartTokens> = {
  dark: {
    grid: "rgba(150,195,235,0.09)",
    axis: "#92abc1",
    surface: "#06101f",
    tooltip: "#071424",
    ink: "#eef6ff",
    mist: "#a9c1d8",
    dim: "#92abc1",
    hair: "rgba(150,195,235,0.13)",
    pulse: "#49b8ff",
    ion: "#64d8ff",
    crystal: "#8be4ff",
    violet: "#9a8cff",
    crit: "#ff4d5e",
    high: "#ff963d",
    med: "#ffd166",
    low: "#42c98a",
    info: "#78b7ff",
    neutral: "#7f94ad",
    mapDeep: "#040d19",
    mapMid: "#071a2d",
    mapLight: "#0c2338",
    plotInk: "#eaf4ff",
    plotMist: "rgba(220,235,250,0.62)",
    strongInk: "#04101d",
  },
  light: {
    grid: "rgba(20,60,104,0.12)",
    axis: "#506479",
    surface: "#ffffff",
    tooltip: "#ffffff",
    ink: "#0a1a2c",
    mist: "#3e5874",
    dim: "#506479",
    hair: "rgba(20,60,104,0.15)",
    pulse: "#0860a5",
    ion: "#05648e",
    crystal: "#0a6f9e",
    violet: "#5f4fd8",
    crit: "#ba2032",
    high: "#8e4404",
    med: "#5c3e02",
    low: "#0c6c4a",
    info: "#1a6cb7",
    neutral: "#55677d",
    mapDeep: "#dfeaf6",
    mapMid: "#cadcf0",
    mapLight: "#b3cfe9",
    plotInk: "#0b1a2c",
    plotMist: "rgba(24,56,90,0.66)",
    strongInk: "#020b16",
  },
};

/**
 * Charts and inline SVG receive literal hexes from many call sites. Resolving
 * them here means one lookup table instead of editing every page.
 */
const TONES: Record<string, keyof ChartTokens> = {
  "#49b8ff": "pulse",
  "#7190ad": "dim",
  "#64d8ff": "ion",
  "#8be4ff": "crystal",
  "#8be6ff": "crystal",
  "#a3ecff": "crystal",
  "#bfe9ff": "crystal",
  "#dcf0ff": "crystal",
  "#9a8cff": "violet",
  "#c9a6ff": "violet",
  "#c8c0ed": "violet",
  "#ff4d5e": "crit",
  "#ffc3cc": "crit",
  "#ffb3bc": "crit",
  "#ffa3ae": "crit",
  "#ff963d": "high",
  "#7fd2ff": "ion",
  "#5fb3e6": "pulse",
  "#ffd166": "med",
  "#42c98a": "low",
  "#6fdcb0": "low",
  "#78b7ff": "info",
  "#7f94ad": "neutral",
  "#7c93ab": "neutral",
  "#eef6ff": "ink",
  "#eaf4ff": "ink",
  "#d6e8f7": "ink",
  "#dcebfa": "ink",
  "#dcecfa": "ink",
  "#cfe0f2": "ink",
  "#cfe3f4": "ink",
  "#cedff0": "ink",
  "#c1d4e8": "mist",
  "#a9c1d8": "mist",
  "#a9c2d8": "mist",
  "#a7c1d8": "mist",
  "#a3bdd4": "mist",
  "#b4cbe0": "mist",
  "#d2e3f2": "mist",
  "#8fa9c2": "dim",
  "#7f9ab3": "dim",
  "#6f8aa4": "dim",
  "#6b8199": "dim",
  "#5d7590": "dim",
  "#64798f": "dim",
  "#06101f": "surface",
  "#071426": "surface",
  "#071424": "tooltip",
  "#0a1b2e": "mapLight",
  "#040d19": "mapDeep",
  "#0c2338": "mapLight",
};

export function tone(value: string | undefined): string {
  if (!value) return value as string;
  const key = value.trim().toLowerCase();
  const token = TONES[key];
  return token ? PALETTE[getTheme()][token] : value;
}

export function palette(): ChartTokens {
  return PALETTE[getTheme()];
}

function toRgb(hex: string): [number, number, number] {
  const body = hex.replace("#", "");
  const full = body.length === 3 ? body.split("").map((c) => c + c).join("") : body.slice(0, 6);
  const n = parseInt(full, 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function srgb(v: number): number {
  const s = v / 255;
  return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
}

function luminance(color: [number, number, number]): number {
  return 0.2126 * srgb(color[0]) + 0.7152 * srgb(color[1]) + 0.0722 * srgb(color[2]);
}

function contrast(a: [number, number, number], b: [number, number, number]): number {
  const la = luminance(a);
  const lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/**
 * A heat cell is the accent alpha-composited on the chart surface, so the accent
 * reads lighter than the plate at midnight and darker than it at daylight.
 * Picking the ink per cell keeps the digit legible in both worlds.
 */
export function heatInk(intensity: number): string {
  const p = palette();
  const accent = toRgb(p.ion);
  const plate = toRgb(p.surface);
  const cell: [number, number, number] = [
    accent[0] * intensity + plate[0] * (1 - intensity),
    accent[1] * intensity + plate[1] * (1 - intensity),
    accent[2] * intensity + plate[2] * (1 - intensity),
  ];
  let best = p.strongInk;
  let bestRatio = -1;
  for (const candidate of [p.plotInk, p.ink, p.surface, p.strongInk]) {
    const ratio = contrast(toRgb(candidate), cell);
    if (ratio > bestRatio) {
      bestRatio = ratio;
      best = candidate;
    }
  }
  return best;
}

function readStored(): ThemeMode | null {
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    return saved === "light" || saved === "dark" ? saved : null;
  } catch {
    return null;
  }
}

function preferred(): ThemeMode {
  const stored = readStored();
  if (stored) return stored;
  if (typeof document !== "undefined") {
    const attr = document.documentElement.getAttribute("data-theme");
    if (attr === "light" || attr === "dark") return attr;
  }
  return "dark";
}

let current: ThemeMode = "dark";
const listeners = new Set<() => void>();

function emit() {
  listeners.forEach((listener) => listener());
}

function paint(mode: ThemeMode) {
  const root = document.documentElement;
  root.setAttribute("data-theme", mode);
  root.classList.toggle("dark", mode === "dark");
  root.classList.toggle("light", mode === "light");
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", mode === "dark" ? "#06101F" : "#E9EFF7");
}

export function getTheme(): ThemeMode {
  return current;
}

export function setTheme(mode: ThemeMode, options: { persist?: boolean } = {}) {
  if (mode !== current) {
    current = mode;
    paint(mode);
    emit();
  }
  if (options.persist !== false) {
    try {
      window.localStorage.setItem(STORAGE_KEY, mode);
    } catch {
      /* storage blocked — the in-memory theme still applies */
    }
  }
}

export function toggleTheme(): ThemeMode {
  setTheme(current === "dark" ? "light" : "dark");
  return current;
}

/** Runs once from main.tsx; the inline script in index.html already set the attribute. */
export function initTheme(): ThemeMode {
  current = preferred();
  paint(current);
  window.addEventListener("storage", (event) => {
    if (event.key === STORAGE_KEY && (event.newValue === "light" || event.newValue === "dark")) {
      current = event.newValue;
      paint(current);
      emit();
    }
  });
  return current;
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useTheme(): { mode: ThemeMode; setMode: (mode: ThemeMode) => void; toggle: () => void } {
  const mode = useSyncExternalStore(subscribe, getTheme, getTheme);
  return {
    mode,
    setMode: (next: ThemeMode) => setTheme(next),
    toggle: () => setTheme(mode === "dark" ? "light" : "dark"),
  };
}
