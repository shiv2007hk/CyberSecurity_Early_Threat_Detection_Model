import { AlertCircle, ArrowRight, Check, Loader2, Lock, Mail, ShieldCheck, UserRound } from "lucide-react";
import { useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { ApiError } from "../../lib/api";
import { useAuth } from "../../context/AuthContext";
import { AuthLayout } from "./AuthLayout";

const RULES = [
  { label: "At least 10 characters", test: (value: string) => value.length >= 10 },
  { label: "Upper and lower case letters", test: (value: string) => /[a-z]/.test(value) && /[A-Z]/.test(value) },
  { label: "At least one number", test: (value: string) => /\d/.test(value) },
  { label: "At least one symbol", test: (value: string) => /[^A-Za-z0-9]/.test(value) },
];

export default function Register() {
  const { user, initializing, register } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ full_name: "", email: "", password: "", confirm: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!initializing && user) return <Navigate to="/app" replace />;

  const valid = RULES.every((rule) => rule.test(form.password)) && form.password === form.confirm && form.full_name.length >= 2;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    if (form.password !== form.confirm) {
      setError("The two passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      await register({ full_name: form.full_name.trim(), email: form.email.trim(), password: form.password });
      navigate("/app", { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Registration could not be completed. Try again.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthLayout
      title="Request viewer access"
      subtitle="Self-service accounts receive read-only viewer permissions. An administrator can elevate your role after review."
      footer={
        <p className="text-center text-[11.5px] text-dim">
          Already registered?{" "}
          <Link to="/login" className="auth-link">
            Sign in to the console
          </Link>
        </p>
      }
    >
      <form onSubmit={submit} className="space-y-4" noValidate>
        <div className="auth-note">
          <ShieldCheck size={14} />
          <p>
            New accounts default to <b>viewer</b>: read-only analytics, intelligence and reports. Analyst actions require an
            administrator.
          </p>
        </div>

        {error && (
          <div className="auth-alert" role="alert">
            <AlertCircle size={14} />
            <div className="auth-alert-body">{error}</div>
          </div>
        )}

        <div>
          <label htmlFor="full_name" className="auth-label">
            Full name
          </label>
          <div className="relative">
            <UserRound size={13} className="auth-field-icon" />
            <input
              id="full_name"
              className="auth-field pl-9"
              placeholder="Your name"
              autoComplete="name"
              value={form.full_name}
              onChange={(event) => setForm({ ...form, full_name: event.target.value })}
              required
            />
          </div>
        </div>

        <div>
          <label htmlFor="email" className="auth-label">
            Work email
          </label>
          <div className="relative">
            <Mail size={13} className="auth-field-icon" />
            <input
              id="email"
              type="email"
              className="auth-field pl-9"
              placeholder="name@organisation.example"
              autoComplete="username"
              value={form.email}
              onChange={(event) => setForm({ ...form, email: event.target.value })}
              required
            />
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="password" className="auth-label">
              Password
            </label>
            <div className="relative">
              <Lock size={13} className="auth-field-icon" />
              <input
                id="password"
                type="password"
                className="auth-field pl-9"
                placeholder="Create password"
                autoComplete="new-password"
                value={form.password}
                onChange={(event) => setForm({ ...form, password: event.target.value })}
                required
              />
            </div>
          </div>
          <div>
            <label htmlFor="confirm" className="auth-label">
              Confirm
            </label>
            <div className="relative">
              <Lock size={13} className="auth-field-icon" />
              <input
                id="confirm"
                type="password"
                className="auth-field pl-9"
                placeholder="Repeat password"
                autoComplete="new-password"
                value={form.confirm}
                onChange={(event) => setForm({ ...form, confirm: event.target.value })}
                required
              />
            </div>
          </div>
        </div>

        <div className="auth-rules">
          <div className="auth-rules-label">Password requirements</div>
          <div className="grid gap-1.5 sm:grid-cols-2">
            {RULES.map((rule) => {
              const passed = rule.test(form.password);
              return (
                <span key={rule.label} className="auth-rule" data-passed={passed}>
                  <span className="auth-rule-dot">{passed && <Check size={8} />}</span>
                  {rule.label}
                </span>
              );
            })}
            <span className="auth-rule" data-passed={Boolean(form.confirm && form.confirm === form.password)}>
              <span className="auth-rule-dot">{form.confirm && form.confirm === form.password && <Check size={8} />}</span>
              Passwords match
            </span>
          </div>
        </div>

        <button type="submit" className="auth-btn" disabled={busy || !valid}>
          {busy ? <Loader2 size={14} className="animate-spin" /> : <ArrowRight size={14} />}
          {busy ? "Creating account…" : "Create viewer account"}
        </button>

        <p className="text-center font-mono text-[8px] uppercase leading-relaxed tracking-[0.1em] text-dim">
          registration is audited · read-only viewer access by default
        </p>
      </form>
    </AuthLayout>
  );
}
