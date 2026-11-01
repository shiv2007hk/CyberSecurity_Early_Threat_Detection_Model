import { useQuery } from "@tanstack/react-query";
import { AlertCircle, ArrowRight, Eye, EyeOff, Loader2, Lock, Mail, UserRound } from "lucide-react";
import { useState } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { api, ApiError, type RoleAccount } from "../../lib/api";
import { useAuth } from "../../context/AuthContext";
import { AuthLayout } from "./AuthLayout";

export default function Login() {
  const { user, initializing, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data: roleAccounts } = useQuery({
    queryKey: ["role-accounts"],
    queryFn: () => api<{ accounts: RoleAccount[] }>("/auth/role-accounts"),
    staleTime: 5 * 60_000,
    retry: false,
  });

  const next = new URLSearchParams(location.search).get("next");

  if (!initializing && user) {
    return <Navigate to={next || "/app"} replace />;
  }

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(email.trim(), password);
      navigate(next || "/app", { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Sign-in could not be completed. Try again.");
    } finally {
      setBusy(false);
    }
  };

  const useAccount = (account: RoleAccount) => {
    setEmail(account.email);
    setPassword(account.password);
    setError(null);
  };

  return (
    <AuthLayout
      title="Sign in to the watch floor"
      subtitle="Enter with a provisioned analyst or administrator account, or create a read-only viewer account."
      footer={
        <p className="text-center text-[11.5px] text-dim">
          Need read-only access?{" "}
          <Link to="/register" className="auth-link">
            Create a viewer account
          </Link>
        </p>
      }
    >
      <form onSubmit={submit} className="space-y-4" noValidate>
        {error && (
          <div className="auth-alert" role="alert">
            <AlertCircle size={14} />
            <div>
              <div className="auth-alert-title">Sign-in failed</div>
              <div className="auth-alert-body">{error}</div>
            </div>
          </div>
        )}

        <div>
          <label htmlFor="email" className="auth-label">
            Email address
          </label>
          <div className="relative">
            <Mail size={13} className="auth-field-icon" />
            <input
              id="email"
              type="email"
              autoComplete="username"
              className="auth-field pl-9"
              placeholder="analyst@aegissentinel.ai"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
            />
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between">
            <label htmlFor="password" className="auth-label">
              Password
            </label>
            <span className="mb-1.5 font-mono text-[8px] uppercase tracking-[0.14em] text-dim">12-hour session</span>
          </div>
          <div className="relative">
            <Lock size={13} className="auth-field-icon" />
            <input
              id="password"
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              className="auth-field pl-9 pr-11"
              placeholder="Enter your password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
            <button
              type="button"
              onClick={() => setShowPassword((value) => !value)}
              className="auth-field-action"
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? <EyeOff size={13} /> : <Eye size={13} />}
            </button>
          </div>
        </div>

        <button type="submit" className="auth-btn" disabled={busy || !email || !password}>
          {busy ? <Loader2 size={14} className="animate-spin" /> : <ArrowRight size={14} />}
          {busy ? "Establishing session…" : "Enter command centre"}
        </button>

        <div className="auth-divider">Role accounts</div>

        <div className="space-y-2">
          {(roleAccounts?.accounts || []).map((account) => (
            <button key={account.email} type="button" onClick={() => useAccount(account)} className="auth-role">
              <span className="flex min-w-0 items-center gap-2.5">
                <span className="auth-role-icon">
                  <UserRound size={13} />
                </span>
                <span className="min-w-0">
                  <span className="auth-role-role">{account.role}</span>
                  <span className="auth-role-mail">{account.email}</span>
                </span>
              </span>
              <span className="auth-role-use">Use account</span>
            </button>
          ))}
          {!roleAccounts?.accounts?.length && (
            <div className="rounded-xl border border-line bg-veil/[0.05] px-3 py-2.5 text-[10.5px] leading-relaxed text-dim">
              No preset role accounts are available in this environment. Sign in with a provisioned account.
            </div>
          )}
        </div>

        <p className="pt-1 text-center font-mono text-[8px] uppercase leading-relaxed tracking-[0.1em] text-dim">
          credentials are pre-filled locally and never leave this session except to the API
        </p>
      </form>
    </AuthLayout>
  );
}
