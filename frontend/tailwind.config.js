/** @type {import('tailwindcss').Config} */

/**
 * Every semantic colour resolves through a CSS custom property so the whole
 * utility layer flips when `data-theme` changes on <html>.
 * `rgb(var(--x-rgb) / <alpha-value>)` keeps Tailwind opacity modifiers working.
 */
const rgb = (name) => `rgb(var(--${name}-rgb) / <alpha-value>)`;
const tinted = (name, alpha) => `rgb(var(--${name}-rgb) / calc(var(--${name}-a) * <alpha-value>))`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        void: rgb("void"),
        abyss: rgb("abyss"),
        hull: rgb("hull"),
        steel: rgb("steel"),
        deck: rgb("deck"),
        line: tinted("line", 1),
        "line-strong": tinted("line-strong", 1),
        ink: rgb("ink"),
        mist: rgb("mist"),
        dim: rgb("dim"),
        pulse: rgb("pulse"),
        ion: rgb("ion"),
        violet: rgb("violet"),
        emerald: rgb("pulse"),
        jade: rgb("pulse"),
        aurora: rgb("ion"),
        crystal: rgb("crystal"),
        silver: rgb("silver"),
        champagne: "#D8C69B",
        crit: rgb("crit"),
        high: rgb("high"),
        med: rgb("med"),
        low: rgb("low"),
        info: rgb("info"),
        veil: rgb("veil"),
        shade: rgb("shade"),
        surface: rgb("surface"),
        sunken: rgb("sunken"),
        tooltip: rgb("tooltip"),
        ice: "var(--ice-1)",
        pale: "var(--ice-2)",
        slateblue: "var(--ice-3)",
        frost: "var(--ice-0)",
        glacier: "var(--glacier)",
        midnight: "var(--midnight)",
        terrain: "var(--terrain)",
        "deep-ink": "var(--deep-ink)",
        "deep-panel": "var(--deep-panel)",
        "deep-raise": "var(--deep-raise)",
      },
      fontFamily: {
        display: ["Inter", "Public Sans", "sans-serif"],
        condensed: ["Barlow Condensed", "Public Sans", "sans-serif"],
        sans: ["Inter", "Public Sans", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "Cascadia Code", "monospace"],
      },
      boxShadow: {
        lift: "var(--shadow-lift)",
        glow: "0 0 0 1px rgba(var(--pulse-rgb) / 0.18), 0 18px 60px -20px rgba(var(--pulse-rgb) / 0.28)",
        "glow-soft": "0 0 40px -12px rgba(var(--pulse-rgb) / 0.3)",
      },
      backgroundImage: {
        "deck-grid":
          "linear-gradient(rgba(var(--veil-rgb) / 0.045) 1px, transparent 1px), linear-gradient(90deg, rgba(var(--veil-rgb) / 0.045) 1px, transparent 1px)",
        "aurora-sweep":
          "radial-gradient(ellipse 65% 55% at 50% 0%, rgba(var(--pulse-rgb) / 0.22), transparent 70%), radial-gradient(ellipse 45% 45% at 80% 30%, rgba(var(--ion-rgb) / 0.14), transparent 70%)",
      },
      keyframes: {
        scan: { "0%": { transform: "translateY(-100%)" }, "100%": { transform: "translateY(100%)" } },
        pulseRing: { "0%": { opacity: "0.55", transform: "scale(0.92)" }, "70%": { opacity: "0", transform: "scale(1.35)" }, "100%": { opacity: "0" } },
        drift: { "0%": { backgroundPosition: "0 0" }, "100%": { backgroundPosition: "0 -48px" } },
        flicker: { "0%,100%": { opacity: "0.7" }, "50%": { opacity: "1" } },
        floaty: { "0%,100%": { transform: "translate3d(0,0,0)" }, "50%": { transform: "translate3d(0,-14px,0)" } },
        shimmer: { "0%": { transform: "translateX(-120%)" }, "100%": { transform: "translateX(320%)" } },
      },
      animation: {
        scan: "scan 7s linear infinite",
        "pulse-ring": "pulseRing 3s cubic-bezier(0.16,1,0.3,1) infinite",
        drift: "drift 18s linear infinite",
        flicker: "flicker 2.4s ease-in-out infinite",
        floaty: "floaty 9s ease-in-out infinite",
        "floaty-slow": "floaty 14s ease-in-out infinite",
        shimmer: "shimmer 1.8s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
