import { motion } from "framer-motion";
import { ArrowLeft, ArrowUpRight, Fingerprint, LockKeyhole, Moon, ShieldCheck, Sun, Waypoints } from "lucide-react";
import { useEffect, useRef, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { LogoMark } from "../../components/ui";
import { useTheme } from "../../lib/theme";

const VIDEO =
  "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260912_105953_21ad8049-9088-4a00-bad3-aee6b5575a2b.mp4";
const POSTER =
  "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260912_105822_bf7c2d53-9957-4521-bbbf-7c1ab7a70130.png";

const PRINCIPLES = [
  { icon: ShieldCheck, label: "Role-scoped access", note: "Enforced by the API" },
  { icon: Waypoints, label: "Evidence-linked warnings", note: "Record · rule · validation" },
  { icon: LockKeyhole, label: "Human-controlled response", note: "Nothing runs automatically" },
];

const FACTS = [
  { label: "Session", value: "12h signed token" },
  { label: "Containment", value: "0 automated actions" },
];

export function AuthLayout({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const theme = useTheme();

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

  return (
    <div className="auth-shell relative min-h-[100svh] overflow-hidden">
      <div className="auth-sky" aria-hidden="true">
        <video ref={videoRef} autoPlay muted loop playsInline preload="metadata" poster={POSTER}>
          <source src={VIDEO} type="video/mp4" />
        </video>
      </div>
      <div className="auth-veil" aria-hidden="true" />
      <div className="auth-grain" aria-hidden="true" />

      <div className="relative z-10 mx-auto flex min-h-[100svh] w-full max-w-[1460px] flex-col px-4 sm:px-6 lg:px-10">
        <header className="flex items-center justify-between gap-4 py-6">
          <Link to="/" aria-label="CyberGuard home" className="auth-brand">
            <span className="auth-brand-mark">
              <LogoMark size={22} onLight={theme.mode === "light"} />
            </span>
            <span className="auth-brand-name">
              CYBER
              <small>GUARD</small>
            </span>
          </Link>

          <div className="flex items-center gap-2.5">
            <span className="hidden sm:block">
              <span className="auth-chip">
                <i /> Authorised personnel only
              </span>
            </span>
            <button
              type="button"
              onClick={theme.toggle}
              className="auth-navlink"
              aria-label={theme.mode === "dark" ? "Switch to daylight theme" : "Switch to midnight theme"}
              title={theme.mode === "dark" ? "Daylight theme" : "Midnight theme"}
            >
              {theme.mode === "dark" ? <Sun size={11} /> : <Moon size={11} />} Theme
            </button>
            <Link to="/" className="auth-navlink">
              <ArrowLeft size={11} /> Landing
            </Link>
          </div>
        </header>

        <div className="grid flex-1 items-center gap-10 pb-10 pt-2 lg:grid-cols-[1.04fr_0.96fr] lg:gap-14 xl:gap-20">
          <section className="hidden flex-col justify-center lg:flex">
            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
            >
              <div className="auth-eyebrow">
                <span />
                Secure analyst session
              </div>

              <h2 className="auth-h2">
                The watch floor
                <br />
                is open.
              </h2>

              <div className="auth-tagline" aria-label="Detect. Correlate. Prioritise.">
                <span>Detect</span>
                <span>Correlate</span>
                <span>Prioritise</span>
              </div>

              <p className="auth-lede">
                One operational picture for ingestion, validated exposure, explainable risk and evidence-backed warning.
                Every claim on the floor shows its provenance.
              </p>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 18 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.75, delay: 0.14, ease: [0.16, 1, 0.3, 1] }}
              className="auth-panel mt-9 max-w-[520px]"
            >
              <div className="auth-panel-head">
                <b>AI-DRIVEN ACCESS</b>
                <span className="auth-live">
                  <i /> Active
                </span>
              </div>
              <div className="mt-4 grid gap-x-6 gap-y-0 sm:grid-cols-2">
                <div>
                  <div className="auth-panel-icon">
                    <Fingerprint size={20} strokeWidth={1.6} />
                  </div>
                  <div className="mt-3 text-[15px] font-[560] leading-snug tracking-[-0.02em] text-ink">
                    Role-scoped by the API
                  </div>
                  <p className="mt-1.5 text-[10.5px] leading-relaxed text-dim">
                    Viewer, analyst and admin permissions are enforced server-side, not in the interface.
                  </p>
                </div>
                <div className="mt-4 sm:mt-0">
                  <div className="auth-panel-icon">
                    <LockKeyhole size={20} strokeWidth={1.6} />
                  </div>
                  <div className="mt-3 text-[15px] font-[560] leading-snug tracking-[-0.02em] text-ink">
                    Response needs a human
                  </div>
                  <p className="mt-1.5 text-[10.5px] leading-relaxed text-dim">
                    No containment action runs automatically. Every recommendation waits for analyst approval.
                  </p>
                </div>
              </div>
            </motion.div>

            <div className="auth-principles">
              {PRINCIPLES.map(({ icon: Icon, label, note }) => (
                <div key={label}>
                  <Icon size={13} strokeWidth={1.7} />
                  <div className="mt-2 text-[11.5px] font-[560] leading-snug text-ink">{label}</div>
                  <div className="mt-0.5 text-[10px] text-dim">{note}</div>
                </div>
              ))}
            </div>
          </section>

          <main className="flex items-center justify-center lg:justify-end">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.65, ease: [0.16, 1, 0.3, 1] }}
              className="w-full max-w-[452px]"
            >
              <div className="auth-card">
                <div className="auth-card-head">
                  <span className="auth-card-kicker">
                    <i /> Secure access
                  </span>
                  <span className="auth-card-meta">Signed session</span>
                </div>
                <h1 className="auth-title">{title}</h1>
                {subtitle && <p className="auth-subtitle">{subtitle}</p>}
                <div className="mt-6">{children}</div>
                {footer && <div className="auth-card-foot">{footer}</div>}
              </div>

              <div className="mt-4 grid grid-cols-2 gap-2.5">
                {FACTS.map(({ label, value }) => (
                  <div key={label} className="auth-fact">
                    <div className="auth-fact-label">{label}</div>
                    <div className="auth-fact-value">{value}</div>
                  </div>
                ))}
              </div>

              <p className="auth-footnote">
                <LockKeyhole size={10} />
                Advisory console · no automated containment
              </p>
            </motion.div>
          </main>
        </div>

        <footer className="flex items-center justify-between border-t border-line py-4 text-[8px] uppercase tracking-[0.14em] text-dim">
          <span>Every record carries its source</span>
          <Link to="/" className="inline-flex items-center gap-1 transition-colors hover:text-ink">
            View the platform <ArrowUpRight size={10} />
          </Link>
        </footer>
      </div>
    </div>
  );
}
