import { Component, useEffect, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import { useAuth } from "./context/AuthContext";
import AppShell from "./components/AppShell";
import Landing from "./pages/Landing";
import Login from "./pages/auth/Login";
import Register from "./pages/auth/Register";
import Dashboard from "./pages/app/Dashboard";
import Threats from "./pages/app/Threats";
import Vulnerabilities from "./pages/app/Vulnerabilities";
import Assets from "./pages/app/Assets";
import Exposure from "./pages/app/Exposure";
import Alerts from "./pages/app/Alerts";
import Risk from "./pages/app/Risk";
import Correlations from "./pages/app/Correlations";
import Recommendations from "./pages/app/Recommendations";
import Analytics from "./pages/app/Analytics";
import AttackLab from "./pages/app/AttackLab";
import Techniques from "./pages/app/Techniques";
import GlobalMap from "./pages/app/GlobalMap";
import Monitoring from "./pages/app/Monitoring";
import Simulator from "./pages/app/Simulator";
import Provenance from "./pages/app/Provenance";
import Reports from "./pages/app/Reports";
import Sources from "./pages/app/Sources";
import AegisAI from "./pages/app/AegisAI";
import Users from "./pages/app/Users";
import Audit from "./pages/app/Audit";
import Settings from "./pages/app/Settings";
import ScenarioRunner from "./pages/app/ScenarioRunner";
import NotFound from "./pages/app/NotFound";

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div className="grid min-h-screen place-items-center bg-void px-6">
          <div className="panel max-w-[520px] p-7 text-center">
            <div className="mx-auto mb-4 grid h-12 w-12 place-items-center rounded-xl border border-crit/30 bg-crit/[0.07] text-crit">
              <AlertTriangle size={20} />
            </div>
            <h1 className="font-display text-xl font-semibold text-ink">The console encountered an error</h1>
            <p className="mt-2 text-[12.5px] leading-relaxed text-mist">
              {this.state.error.message || "An unexpected rendering error occurred."}
            </p>
            <button className="btn btn-primary mt-5" onClick={() => window.location.reload()}>
              Reload console
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function ScrollToTop() {
  const { pathname } = useLocation();
  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: "instant" });
  }, [pathname]);
  return null;
}

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, initializing } = useAuth();
  const location = useLocation();
  if (initializing) {
    return (
      <div className="grid min-h-screen place-items-center bg-void">
        <div className="flex flex-col items-center gap-4">
          <div className="relative h-14 w-14">
            <span className="absolute inset-0 animate-ping rounded-full border border-ion/30" />
            <span className="absolute inset-0 grid place-items-center rounded-full border border-ion/30 bg-ion/[0.05]">
              <span className="h-2 w-2 rounded-full bg-ion shadow-[0_0_14px_rgba(100,216,255,0.9)]" />
            </span>
          </div>
          <div className="font-mono text-[10px] uppercase tracking-[0.24em] text-dim">Establishing secure session</div>
        </div>
      </div>
    );
  }
  if (!user) {
    const next = encodeURIComponent(`${location.pathname}${location.search}`);
    return <Navigate to={`/login?next=${next}`} replace />;
  }
  return <>{children}</>;
}

function Forbidden() {
  return (
    <div className="panel mx-auto mt-10 max-w-[560px] p-8 text-center">
      <h1 className="font-display text-xl font-semibold text-ink">This area requires elevated permissions</h1>
      <p className="mt-2 text-[12.5px] leading-relaxed text-mist">
        Your account role does not include this administrative surface. Ask an administrator to review your role if
        access is required for your duties.
      </p>
    </div>
  );
}

function RoleGate({ minimum, children }: { minimum: "analyst" | "admin"; children: ReactNode }) {
  const { can } = useAuth();
  return can(minimum) ? <>{children}</> : <Forbidden />;
}

export default function App() {
  return (
    <ErrorBoundary>
      <ScrollToTop />
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route
          path="/app"
          element={
            <RequireAuth>
              <AppShell />
            </RequireAuth>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="monitoring" element={<Monitoring />} />
          <Route path="threats" element={<Threats />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="assets" element={<Assets />} />
          <Route path="exposure" element={<Exposure />} />
          <Route path="attack-lab" element={<AttackLab />} />
          <Route path="techniques" element={<Techniques />} />
          <Route path="threat-map" element={<GlobalMap />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="risk" element={<Risk />} />
          <Route path="simulator" element={<Simulator />} />
          <Route path="provenance" element={<Provenance />} />
          <Route path="correlations" element={<Correlations />} />
          <Route path="recommendations" element={<Recommendations />} />
          <Route path="analytics" element={<Analytics />} />
          <Route path="reports" element={<Reports />} />
          <Route path="reports/:kind" element={<Reports />} />
          <Route path="sources" element={<Sources />} />
          <Route path="ai" element={<AegisAI />} />
          <Route path="assistant" element={<Navigate to="/app/ai" replace />} />
          <Route path="scenarios" element={<ScenarioRunner />} />
          <Route
            path="users"
            element={
              <RoleGate minimum="admin">
                <Users />
              </RoleGate>
            }
          />
          <Route
            path="audit"
            element={
              <RoleGate minimum="admin">
                <Audit />
              </RoleGate>
            }
          />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<NotFound />} />
        </Route>
        <Route path="*" element={<NotFound publicPage />} />
      </Routes>
    </ErrorBoundary>
  );
}
