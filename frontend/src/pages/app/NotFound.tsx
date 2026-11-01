import { Link } from "react-router-dom";
import { ArrowLeft, Compass, Radio, SearchX, ShieldQuestion } from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { LogoMark, Wordmark } from "../../components/ui";

export default function NotFound({ publicPage = false }: { publicPage?: boolean }) {
  const { user } = useAuth();

  if (!publicPage) {
    return (
      <div className="mx-auto flex max-w-[620px] flex-col items-center py-16 text-center">
        <div className="relative mb-6 h-20 w-20">
          <span className="absolute inset-0 rounded-full border border-line" />
          <span className="absolute inset-3 rounded-full border border-ion/25" />
          <span className="absolute inset-0 grid place-items-center text-ion"><SearchX size={26} /></span>
        </div>
        <div className="font-mono text-[9px] uppercase tracking-[0.24em] text-dim">404 · route unresolved</div>
        <h1 className="mt-2 font-display text-[24px] font-semibold text-ink">This console route does not exist</h1>
        <p className="mt-2 max-w-[46ch] text-[12px] leading-relaxed text-mist">
          The address is outside the registered navigation surface. It may be from an older build, or the link may be malformed.
        </p>
        <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
          <Link to="/app" className="btn btn-primary btn-sm"><Compass size={13} /> Command centre</Link>
          <Link to="/app/threats" className="btn btn-ghost btn-sm"><Radio size={13} /> Live intelligence</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-void px-6 py-16">
      <div className="pointer-events-none absolute inset-0" aria-hidden="true">
        {Array.from({ length: 9 }).map((_, index) => (
          <span
            key={index}
            className="absolute left-1/2 top-1/2 rounded-full border border-ion/[0.07]"
            style={{ width: 200 + index * 130, height: 200 + index * 130, transform: "translate(-50%, -50%)" }}
          />
        ))}
        <span className="absolute left-1/2 top-1/2 h-[520px] w-px -translate-x-1/2 -translate-y-1/2 bg-gradient-to-b from-transparent via-ion/15 to-transparent" />
        <span className="absolute left-1/2 top-1/2 h-px w-[520px] -translate-x-1/2 -translate-y-1/2 bg-gradient-to-r from-transparent via-ion/15 to-transparent" />
      </div>

      <div className="relative w-full max-w-[560px] text-center">
        <div className="mb-8 flex justify-center"><Wordmark /></div>
        <div className="font-mono text-[10px] uppercase tracking-[0.26em] text-ion/80">Signal lost · 404</div>
        <h1 className="mt-3 font-display text-[clamp(2.4rem,7vw,3.6rem)] font-semibold leading-[0.95] tracking-[-0.03em] text-ink">
          This bearing is not on the chart.
        </h1>
        <p className="mx-auto mt-4 max-w-[44ch] text-[12.5px] leading-relaxed text-mist">
          The page you requested does not exist in this deployment. Return to the public overview or sign in to the command centre.
        </p>

        <div className="mt-7 flex flex-wrap items-center justify-center gap-2">
          <Link to="/" className="btn btn-primary btn-sm"><ArrowLeft size={13} /> Back to overview</Link>
          <Link to={user ? "/app" : "/login"} className="btn btn-ghost btn-sm">
            {user ? <ShieldQuestion size={13} /> : <Compass size={13} />} {user ? "Command centre" : "Sign in"}
          </Link>
        </div>

        <div className="mt-10 flex items-center justify-center gap-3 font-mono text-[8px] uppercase tracking-[0.14em] text-dim">
          <span className="h-px w-8 bg-line-strong" />
          <span>CYBERGUARD AI · Threat Intelligence Console</span>
          <span className="h-px w-8 bg-line-strong" />
        </div>
      </div>

      <div className="pointer-events-none absolute bottom-5 left-6 flex items-center gap-2 opacity-60">
        <LogoMark size={18} />
        <span className="font-mono text-[7.5px] uppercase tracking-[0.18em] text-dim">advisory console · no automated containment</span>
      </div>
    </div>
  );
}
