import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  BadgeCheck,
  BellRing,
  Check,
  Cpu,
  Database,
  Gauge,
  KeyRound,
  LockKeyhole,
  Loader2,
  LogOut,
  Play,
  Settings2,
  ShieldCheck,
  UserRound,
} from "lucide-react";
import clsx from "clsx";
import { api } from "../../lib/api";
import { fmtDate, fmtNumber, fmtPct, relTime, titleCase } from "../../lib/format";
import { useAuth } from "../../context/AuthContext";
import {
  DefinitionList,
  InlineNotice,
  Kpi,
  LoadingBlock,
  PageHeader,
  Panel,
  PanelHead,
  Tabs,
  Toggle,
  useToast,
} from "../../components/ui";

const WEIGHT_LABELS: Record<string, string> = {
  severity: "Severity",
  exploitability: "Exploitability",
  exposure: "Exposure",
  asset_criticality: "Asset criticality",
  evidence_strength: "Evidence strength",
};

export default function Settings() {
  const { user, can, updateUser, logout } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();

  const [tab, setTab] = useState("profile");
  const [fullName, setFullName] = useState(user?.full_name || "");
  const [notifyEmail, setNotifyEmail] = useState(user?.notification_email ?? true);
  const [notifyCritical, setNotifyCritical] = useState(user?.notification_critical_only ?? false);
  const [passwords, setPasswords] = useState({ current: "", next: "", confirm: "" });

  useEffect(() => {
    if (user) {
      setFullName(user.full_name);
      setNotifyEmail(user.notification_email);
      setNotifyCritical(user.notification_critical_only);
    }
  }, [user]);

  const isAdmin = can("admin");
  const isAnalyst = can("analyst");

  const platformQuery = useQuery({
    queryKey: ["admin-settings"],
    queryFn: () => api<any>("/admin/settings"),
    enabled: isAdmin,
  });
  const systemQuery = useQuery({
    queryKey: ["admin-system"],
    queryFn: () => api<any>("/admin/system"),
    enabled: isAdmin,
  });
  const riskConfigQuery = useQuery({
    queryKey: ["risk-config"],
    queryFn: () => api<any>("/risk/config"),
    enabled: isAdmin,
  });
  const evaluationsQuery = useQuery({
    queryKey: ["classifier-quality"],
    queryFn: () => api<any>("/admin/classifier-quality"),
    enabled: isAnalyst,
  });

  const profileMutation = useMutation({
    mutationFn: (payload: Record<string, any>) => api<any>("/auth/profile", { method: "PATCH", body: JSON.stringify(payload) }),
    onSuccess: (result) => {
      updateUser(result);
      push("success", "Profile preferences saved.");
      queryClient.invalidateQueries({ queryKey: ["auth"] });
    },
    onError: (error: any) => push("error", error.message || "Profile could not be saved."),
  });

  const passwordMutation = useMutation({
    mutationFn: (payload: { current_password: string; new_password: string }) =>
      api<any>("/auth/change-password", { method: "POST", body: JSON.stringify(payload) }),
    onSuccess: (result: any) => {
      push("success", result.message || "Password updated.");
      setPasswords({ current: "", next: "", confirm: "" });
    },
    onError: (error: any) => push("error", error.message || "Password could not be changed."),
  });

  const runEvaluation = useMutation({
    mutationFn: () => api<any>("/admin/classifier-quality/run", { method: "POST" }),
    onSuccess: () => {
      push("success", "Classifier benchmark complete. Metrics stored with this run.");
      queryClient.invalidateQueries({ queryKey: ["classifier-quality"] });
    },
    onError: (error: any) => push("error", error.message || "The classifier run failed."),
  });

  const environment = platformQuery.data?.environment;
  const notifications = platformQuery.data?.notification_policy;
  const latest = evaluationsQuery.data?.latest;
  const riskConfig = riskConfigQuery.data;

  const savePassword = () => {
    if (!passwords.current || !passwords.next) {
      push("error", "Enter your current and new password.");
      return;
    }
    if (passwords.next !== passwords.confirm) {
      push("error", "The new passwords do not match.");
      return;
    }
    passwordMutation.mutate({ current_password: passwords.current, new_password: passwords.next });
  };

  return (
    <>
      <PageHeader
        title="Settings"
        description="Your profile, notification preferences and, for administrators, the platform configuration surface. Secrets are never displayed here — only configuration state."
        aside={
          user && (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
              <span>{user.email}</span><span>·</span><span>{user.role}</span><span>·</span>
              <span>member since {fmtDate(user.created_at)}</span>
            </div>
          )
        }
      />

      <Tabs
        value={tab}
        onChange={setTab}
        className="mb-4"
        tabs={[
          { value: "profile", label: "Profile" },
          { value: "notifications", label: "Notifications" },
          ...(isAdmin ? [{ value: "administration", label: "Administration" }] : []),
        ]}
      />

      {tab === "profile" && user && (
        <>
        <div className="grid items-start gap-4 xl:grid-cols-[1.2fr_1fr]">
          <Panel>
            <PanelHead title="Operator profile" kicker="Identity" right={<UserRound size={14} className="text-dim" />} />
            <div className="p-4">
              <div className="flex items-center gap-3 rounded-xl border border-line bg-shade/20 p-3.5">
                <span className="grid h-12 w-12 place-items-center rounded-xl border border-ion/25 bg-ion/[0.07] font-mono text-[13px] text-ion">{user.initials}</span>
                <div className="min-w-0">
                  <div className="text-[13px] font-semibold text-ink">{user.full_name}</div>
                  <div className="font-mono text-[9.5px] text-dim">{user.email}</div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    <span className="chip text-ion">{user.role}</span>
                    {user.organisation && <span className="chip text-dim">{user.organisation.name}</span>}
                  </div>
                </div>
              </div>

              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <label className="sm:col-span-2">
                  <span className="field-label">Full name</span>
                  <input className="field" value={fullName} onChange={(event) => setFullName(event.target.value)} />
                </label>
                <label>
                  <span className="field-label">Email</span>
                  <input className="field opacity-70" value={user.email} readOnly aria-readonly="true" />
                </label>
                <label>
                  <span className="field-label">Role</span>
                  <input className="field opacity-70" value={titleCase(user.role)} readOnly aria-readonly="true" />
                </label>
              </div>
              <p className="mt-2 text-[9.5px] leading-relaxed text-dim">Role and email are controlled by an administrator. Name changes are recorded in the audit trail.</p>
              <div className="mt-3 flex justify-end">
                <button
                  className="btn btn-primary btn-sm"
                  disabled={profileMutation.isPending || fullName.trim().length < 2 || fullName.trim() === user.full_name}
                  onClick={() => profileMutation.mutate({ full_name: fullName.trim() })}
                >
                  {profileMutation.isPending ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />} Save profile
                </button>
              </div>
            </div>
          </Panel>

          <div className="space-y-4">
            <Panel>
              <PanelHead title="Session" kicker="Current authentication" right={<ShieldCheck size={14} className="text-dim" />} />
              <div className="p-4">
                <DefinitionList
                  rows={[
                    { label: "Method", value: "Bearer JWT · HS256" },
                    { label: "Last sign-in", value: user.last_login_at ? `${fmtDate(user.last_login_at)} (${relTime(user.last_login_at)})` : "—" },
                    { label: "Token lifetime", value: environment?.token_lifetime_minutes ? `${environment.token_lifetime_minutes} minutes` : "Configured server-side" },
                    { label: "Storage", value: "Browser local storage; token removed on sign-out" },
                  ]}
                />
                <button className="btn btn-ghost btn-sm mt-3 w-full" onClick={logout}><LogOut size={12} /> Sign out of this browser</button>
              </div>
            </Panel>

          </div>
        </div>

        <Panel className="mt-4">
          <PanelHead title="Change password" kicker="Credential hygiene" right={<KeyRound size={14} className="text-dim" />} />
          <div className="p-4">
            <div className="grid gap-3 sm:grid-cols-3">
              <label><span className="field-label">Current password</span><input type="password" className="field" value={passwords.current} onChange={(event) => setPasswords({ ...passwords, current: event.target.value })} autoComplete="current-password" /></label>
              <label><span className="field-label">New password</span><input type="password" className="field" value={passwords.next} onChange={(event) => setPasswords({ ...passwords, next: event.target.value })} autoComplete="new-password" /></label>
              <label><span className="field-label">Confirm new password</span><input type="password" className="field" value={passwords.confirm} onChange={(event) => setPasswords({ ...passwords, confirm: event.target.value })} autoComplete="new-password" /></label>
            </div>
            <div className="mt-3 flex flex-col-reverse items-start gap-3 sm:flex-row sm:items-center sm:justify-between">
              <p className="max-w-2xl text-[9px] leading-relaxed text-dim">Minimum 10 characters with uppercase, lowercase, a number and a symbol. Existing sessions remain valid until token expiry.</p>
              <button className="btn btn-primary btn-sm shrink-0" disabled={passwordMutation.isPending} onClick={savePassword}>
                {passwordMutation.isPending ? <Loader2 size={12} className="animate-spin" /> : <LockKeyhole size={12} />} Update password
              </button>
            </div>
          </div>
        </Panel>
        </>
      )}

      {tab === "notifications" && user && (
        <div className="grid gap-4 xl:grid-cols-[1.15fr_1fr]">
          <Panel>
            <PanelHead title="Notification routing" kicker="Your preferences" right={<BellRing size={14} className="text-dim" />} />
            <div className="space-y-2 p-4">
              <div className="flex items-center justify-between gap-4 rounded-lg border border-line bg-shade/20 px-3.5 py-3">
                <div>
                  <div className="text-[11.5px] text-ink">Email notifications</div>
                  <p className="mt-0.5 text-[10px] leading-relaxed text-dim">Receive early-warning and assignment summaries by email, if SMTP is configured on the server.</p>
                </div>
                <Toggle checked={notifyEmail} onChange={setNotifyEmail} label="Email notifications" />
              </div>
              <div className="flex items-center justify-between gap-4 rounded-lg border border-line bg-shade/20 px-3.5 py-3">
                <div>
                  <div className="text-[11.5px] text-ink">Critical only</div>
                  <p className="mt-0.5 text-[10px] leading-relaxed text-dim">Suppress non-critical mail. Critical alerting is based on stored severity, not on a prediction.</p>
                </div>
                <Toggle checked={notifyCritical} onChange={setNotifyCritical} label="Critical only" />
              </div>
              <div className="flex justify-end pt-1">
                <button
                  className="btn btn-primary btn-sm"
                  disabled={profileMutation.isPending}
                  onClick={() => profileMutation.mutate({ notification_email: notifyEmail, notification_critical_only: notifyCritical })}
                >
                  {profileMutation.isPending ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />} Save preferences
                </button>
              </div>
            </div>
          </Panel>

          <div className="space-y-4">
            <InlineNotice tone={notifications?.smtp_configured ? "low" : "med"} title="Delivery dependency">
              {notifications?.smtp_configured
                ? "SMTP is configured on this server. Delivery still depends on the mail provider accepting the message."
                : "SMTP is not configured. Preferences are stored, but no email will be delivered until an administrator configures the mail server."}
            </InlineNotice>
            <Panel>
              <PanelHead title="What gets notified" kicker="Policy" />
              <div className="p-4">
                <ul className="space-y-2 text-[10.5px] leading-relaxed text-mist">
                  {[
                    "New early-warning alerts that meet your severity threshold.",
                    "Assignment changes on remediation recommendations.",
                    "Account and access changes initiated by an administrator.",
                  ].map((item) => (
                    <li key={item} className="flex items-start gap-2"><span className="mt-[6px] h-1 w-1 shrink-0 rounded-full bg-ion/70" />{item}</li>
                  ))}
                </ul>
                <p className="mt-3 border-t border-line pt-3 text-[9.5px] leading-relaxed text-dim">{notifications?.note}</p>
              </div>
            </Panel>
          </div>
        </div>
      )}

      {tab === "administration" && isAdmin && (
        <div className="space-y-4">
          {platformQuery.isError || systemQuery.isError ? (
            <Panel><div className="p-4 text-[11.5px] text-crit">Platform state could not be loaded. {(platformQuery.error as any)?.message || (systemQuery.error as any)?.message}</div></Panel>
          ) : platformQuery.isLoading || systemQuery.isLoading ? (
            <Panel><LoadingBlock rows={6} label="Loading platform configuration" /></Panel>
          ) : (
            <>
              <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
                <Kpi label="Environment" value={titleCase(systemQuery.data?.environment || "unknown")} detail={`Python ${systemQuery.data?.python}`} icon={<Cpu size={15} />} tone="ion" />
                <Kpi label="Database" value={titleCase(systemQuery.data?.database_backend || "—")} detail={`${fmtNumber(Number(Object.values(systemQuery.data?.table_counts || {}).reduce((acc: number, value: unknown) => acc + Number(value || 0), 0)))} rows tracked`} icon={<Database size={15} />} tone="violet" />
                <Kpi label="Risk model" value={systemQuery.data?.risk_model || "—"} detail="Configurable weighted model" icon={<Gauge size={15} />} tone="med" />
                <Kpi label="Audit events" value={fmtNumber(systemQuery.data?.table_counts?.audit_events)} detail="Account actions recorded by the API" icon={<Activity size={15} />} tone="low" />
              </div>

              <div className="grid gap-4 xl:grid-cols-2">
                <Panel>
                  <PanelHead title="Environment flags" kicker="Runtime configuration" right={<Settings2 size={14} className="text-dim" />} />
                  <div className="divide-y divide-veil/[0.05]">
                    {Object.entries(environment || {}).map(([key, value]) => (
                      <div key={key} className="flex items-center justify-between gap-3 px-4 py-2">
                        <span className="font-mono text-[9px] uppercase tracking-[0.1em] text-dim">{key.replace(/_/g, " ")}</span>
                        {typeof value === "boolean" ? (
                          <span className={clsx("chip", value ? "text-low" : "text-dim")}>{value ? "enabled" : "disabled"}</span>
                        ) : (
                          <span className="font-mono text-[10px] text-ink">{String(value)}</span>
                        )}
                      </div>
                    ))}
                  </div>
                  <div className="border-t border-line px-4 py-2.5 text-[9px] leading-relaxed text-dim">{platformQuery.data?.secret_policy}</div>
                </Panel>

                <Panel>
                  <PanelHead title="Connector configuration" kicker="Keys configured server-side" right={<BadgeCheck size={14} className="text-dim" />} />
                  <div className="grid grid-cols-2 gap-2 p-4">
                    {Object.entries(platformQuery.data?.connectors || {}).map(([key, configured]) => (
                      <div key={key} className="flex items-center justify-between gap-2 rounded-md border border-line bg-shade/20 px-2.5 py-2">
                        <span className="font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim">{key.replace(/_/g, " ")}</span>
                        <span className={clsx("h-1.5 w-1.5 rounded-full", configured ? "bg-low" : "bg-veil/15")} title={configured ? "Configured" : "Not configured"} />
                      </div>
                    ))}
                  </div>
                  <div className="flex items-center justify-between gap-2 border-t border-line px-4 py-2.5">
                    <span className="font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">Manage sources</span>
                    <Link to="/app/sources" className="text-[10px] text-ion hover:text-crystal">Open connectors</Link>
                  </div>
                </Panel>
              </div>

              <div className="grid gap-4 xl:grid-cols-[1fr_1.15fr]">
                <Panel>
                  <PanelHead title="Stored records" kicker="Database inventory" right={<Activity size={14} className="text-dim" />} />
                  <div className="grid grid-cols-2 gap-2 p-4 sm:grid-cols-3">
                    {Object.entries(systemQuery.data?.table_counts || {}).map(([key, value]) => (
                      <div key={key} className="rounded-md border border-line bg-shade/20 px-3 py-2">
                        <div className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{key.replace(/_/g, " ")}</div>
                        <div className="tnum mt-1 font-display text-[16px] text-ink">{fmtNumber(Number(value))}</div>
                      </div>
                    ))}
                  </div>
                  <div className="border-t border-line px-4 py-2.5 font-mono text-[8px] uppercase tracking-[0.1em] text-dim">Generated {relTime(systemQuery.data?.generated_at)} · v{systemQuery.data?.version}</div>
                </Panel>

                <Panel>
                  <PanelHead
                    title="Risk model configuration"
                    kicker={riskConfig?.model_version || "Weighted model"}
                    right={<Link to="/app/risk" className="text-[10px] text-ion hover:text-crystal">Tune in Risk module</Link>}
                  />
                  {riskConfigQuery.isLoading ? (
                    <LoadingBlock rows={4} label="Loading risk configuration" />
                  ) : (
                    <div className="p-4">
                      <div className="grid gap-2 sm:grid-cols-2">
                        {Object.entries(riskConfig?.weights || {}).map(([key, weight]) => (
                          <div key={key} className="rounded-md border border-line bg-shade/20 px-3 py-2">
                            <div className="flex items-baseline justify-between">
                              <span className="text-[10px] text-mist">{WEIGHT_LABELS[key] || titleCase(key)}</span>
                              <span className="font-mono text-[10px] text-ion">{Math.round(Number(weight) * 100)}%</span>
                            </div>
                            <div className="mt-1.5 h-[3px] overflow-hidden rounded-full bg-veil/[0.06]">
                              <div className="h-full rounded-full bg-ion" style={{ width: `${Number(weight) * 100}%` }} />
                            </div>
                          </div>
                        ))}
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {["medium", "high", "critical"].map((key) => (
                          <span key={key} className="chip text-dim">{titleCase(key)} ≥ {riskConfig?.thresholds?.[key]}</span>
                        ))}
                      </div>
                      <p className="mt-3 text-[9.5px] leading-relaxed text-dim">{riskConfig?.formula}</p>
                    </div>
                  )}
                </Panel>
              </div>

              <Panel>
                <PanelHead
                  title="Classifier quality"
                  kicker="Curated benchmark, run by run"
                  right={
                    <div className="flex items-center gap-2">
                      <Link to="/app/analytics" className="text-[10px] text-ion hover:text-crystal">Analytics</Link>
                      <button className="btn btn-ghost btn-sm" onClick={() => runEvaluation.mutate()} disabled={runEvaluation.isPending}>
                        {runEvaluation.isPending ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />} Run benchmark
                      </button>
                    </div>
                  }
                />
                {evaluationsQuery.isLoading ? (
                  <LoadingBlock rows={4} label="Loading classifier history" />
                ) : latest ? (
                  <>
                    <div className="grid grid-cols-2 gap-2 p-4 sm:grid-cols-5">
                      {[
                        ["Precision", latest.precision],
                        ["Recall", latest.recall],
                        ["F1", latest.f1],
                        ["Macro F1", latest.macro_f1],
                      ].map(([label, value]) => (
                        <div key={label as string} className="rounded-md border border-line bg-shade/20 px-3 py-2">
                          <div className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">{label}</div>
                          <div className="tnum mt-1 font-display text-[18px] text-ink">{fmtPct(value as number, 1)}</div>
                        </div>
                      ))}
                      <div className="rounded-md border border-line bg-shade/20 px-3 py-2">
                        <div className="font-mono text-[8px] uppercase tracking-[0.1em] text-dim">Samples</div>
                        <div className="tnum mt-1 font-display text-[18px] text-ink">{fmtNumber(latest.samples)}</div>
                      </div>
                    </div>
                    <div className="border-t border-line px-4 py-3">
                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
                        <span>{latest.model_name}</span><span>·</span><span>{latest.dataset_name}</span><span>·</span><span>{relTime(latest.evaluated_at)}</span>
                      </div>
                      <p className="mt-2 text-[10px] leading-relaxed text-mist">{latest.notes}</p>
                    </div>
                    <div className="table-shell overflow-x-auto border-0 border-t border-line">
                      <table className="w-full">
                        <thead><tr><th>Run</th><th className="text-right">Precision</th><th className="text-right">Recall</th><th className="text-right">F1</th><th className="text-right">Samples</th><th>When</th></tr></thead>
                        <tbody>
                          {(evaluationsQuery.data?.history || []).slice(0, 8).map((entry: any) => (
                            <tr key={entry.id}>
                              <td className="font-mono text-[9.5px] text-mist">#{entry.id}</td>
                              <td className="tnum text-right font-mono text-[9.5px]">{fmtPct(entry.precision, 1)}</td>
                              <td className="tnum text-right font-mono text-[9.5px]">{fmtPct(entry.recall, 1)}</td>
                              <td className="tnum text-right font-mono text-[9.5px]">{fmtPct(entry.f1, 1)}</td>
                              <td className="tnum text-right font-mono text-[9.5px]">{fmtNumber(entry.samples)}</td>
                              <td className="font-mono text-[9px] text-dim">{relTime(entry.evaluated_at)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <InlineNotice tone="med" className="m-4">{evaluationsQuery.data?.note}</InlineNotice>
                  </>
                ) : (
                  <div className="p-4">
                    <p className="text-[11.5px] text-mist">No classifier run recorded yet. The lexicon is deterministic; a run scores it against the curated benchmark and stores the metrics here.</p>
                    <InlineNotice tone="med" className="mt-3">{evaluationsQuery.data?.note}</InlineNotice>
                  </div>
                )}
              </Panel>
            </>
          )}
        </div>
      )}

      {tab === "administration" && !isAdmin && (
        <Panel><div className="p-6 text-[11.5px] text-mist">Administration settings require an administrator account.</div></Panel>
      )}
    </>
  );
}
