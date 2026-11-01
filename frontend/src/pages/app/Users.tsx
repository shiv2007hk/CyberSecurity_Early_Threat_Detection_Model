import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BadgeCheck,
  Check,
  KeyRound,
  Loader2,
  Plus,
  Search,
  ShieldCheck,
  UserCog,
  UserPlus,
  Users as UsersIcon,
  UserX,
} from "lucide-react";
import clsx from "clsx";
import { api, qs, type Paginated, type User } from "../../lib/api";
import { fmtDate, relTime, titleCase } from "../../lib/format";
import { useAuth } from "../../context/AuthContext";
import {
  ConfirmDialog,
  Drawer,
  ErrorState,
  Kpi,
  LoadingBlock,
  Modal,
  PageHeader,
  Pagination,
  Panel,
  PanelHead,
  SearchField,
  Toggle,
  useToast,
} from "../../components/ui";
import { FilterSelect, SectionLabel } from "./shared";

const ROLES = ["admin", "analyst", "viewer"] as const;

const ROLE_TONE: Record<string, string> = {
  admin: "border-crit/30 bg-crit/[0.07] text-crit",
  analyst: "border-ion/30 bg-ion/[0.07] text-ion",
  viewer: "border-veil/10 bg-veil/[0.03] text-mist",
};

const PASSWORD_RULES = ["10+ characters", "uppercase", "lowercase", "number", "symbol"];

function passwordIssues(password: string) {
  const issues: string[] = [];
  if (password.length < 10) issues.push("10+ characters");
  if (!/[A-Z]/.test(password)) issues.push("uppercase");
  if (!/[a-z]/.test(password)) issues.push("lowercase");
  if (!/\d/.test(password)) issues.push("number");
  if (!/[^A-Za-z0-9]/.test(password)) issues.push("symbol");
  return issues;
}

export default function Users() {
  const { user: currentUser } = useAuth();
  const { push } = useToast();
  const queryClient = useQueryClient();

  const [searchParams, setSearchParams] = useSearchParams();
  const [q, setQ] = useState("");
  const [role, setRole] = useState("all");
  const [active, setActive] = useState("all");
  const [page, setPage] = useState(1);
  const [createOpen, setCreateOpen] = useState(false);
  const [selected, setSelected] = useState<User | null>(null);
  const [confirmDeactivate, setConfirmDeactivate] = useState(false);

  useEffect(() => {
    if (searchParams.get("create") !== "1") return;
    setCreateOpen(true);
    const next = new URLSearchParams(searchParams);
    next.delete("create");
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);

  const [form, setForm] = useState({ full_name: "", email: "", password: "", role: "analyst", organisation_id: "" });
  const [editRole, setEditRole] = useState("viewer");
  const [editActive, setEditActive] = useState(true);
  const [notifyEmail, setNotifyEmail] = useState(true);
  const [notifyCritical, setNotifyCritical] = useState(false);
  const [resetPassword, setResetPassword] = useState("");

  const usersQuery = useQuery({
    queryKey: ["admin-users", q, role, active, page],
    queryFn: () =>
      api<Paginated<User> & { stats: Record<string, number>; organisations: any[] }>(
        `/admin/users${qs({
          q: q || undefined,
          role: role === "all" ? undefined : role,
          active: active === "all" ? undefined : active === "true",
          page,
          size: 25,
        })}`,
      ),
  });

  const data = usersQuery.data;
  const items = data?.items || [];
  const organisations = data?.organisations || [];

  useEffect(() => {
    if (selected) {
      setEditRole(selected.role);
      setEditActive(selected.is_active);
      setNotifyEmail(selected.notification_email);
      setNotifyCritical(selected.notification_critical_only);
      setResetPassword("");
    }
  }, [selected]);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["admin-users"] });
    queryClient.invalidateQueries({ queryKey: ["admin-users-lite"] });
    queryClient.invalidateQueries({ queryKey: ["audit-logs"] });
  };

  const create = useMutation({
    mutationFn: (payload: Record<string, any>) => api<any>("/admin/users", { method: "POST", body: JSON.stringify(payload) }),
    onSuccess: () => {
      push("success", "Account created. Share the temporary password through an approved channel.");
      setCreateOpen(false);
      setForm({ full_name: "", email: "", password: "", role: "analyst", organisation_id: "" });
      invalidate();
    },
    onError: (error: any) => push("error", error.message || "The account could not be created."),
  });

  const update = useMutation({
    mutationFn: (vars: { id: number; payload: Record<string, any> }) =>
      api<any>(`/admin/users/${vars.id}`, { method: "PATCH", body: JSON.stringify(vars.payload) }),
    onSuccess: (result: any) => {
      push("success", result.message || "Account updated.");
      setSelected(result.user);
      invalidate();
    },
    onError: (error: any) => push("error", error.message || "The account could not be updated."),
  });

  const reset = useMutation({
    mutationFn: (vars: { id: number; new_password: string }) =>
      api<any>(`/admin/users/${vars.id}/reset-password`, { method: "POST", body: JSON.stringify({ new_password: vars.new_password }) }),
    onSuccess: (result: any) => {
      push("success", result.message || "Password reset.");
      setResetPassword("");
      invalidate();
    },
    onError: (error: any) => push("error", error.message || "The password could not be reset."),
  });

  const deactivate = useMutation({
    mutationFn: (id: number) => api<any>(`/admin/users/${id}`, { method: "DELETE" }),
    onSuccess: (result: any) => {
      push("success", result.message || "Account deactivated.");
      setConfirmDeactivate(false);
      setSelected(null);
      invalidate();
    },
    onError: (error: any) => {
      push("error", error.message || "The account could not be deactivated.");
      setConfirmDeactivate(false);
    },
  });

  const submitCreate = () => {
    if (!form.full_name.trim() || !form.email.trim()) {
      push("error", "Full name and email are required.");
      return;
    }
    const issues = passwordIssues(form.password);
    if (issues.length) {
      push("error", `Password must contain ${issues.join(", ")}.`);
      return;
    }
    create.mutate({
      full_name: form.full_name.trim(),
      email: form.email.trim(),
      password: form.password,
      role: form.role,
      organisation_id: form.organisation_id ? Number(form.organisation_id) : null,
    });
  };

  const stats = data?.stats;
  const isSelf = selected?.id === currentUser?.id;

  return (
    <>
      <PageHeader
        title="User administration"
        description="Accounts, roles and access state. Role changes take effect on the next authenticated request. Deactivation is reversible; the last active administrator cannot be removed."
        aside={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
            <span><span className="text-ink">{stats?.total ?? "—"}</span> accounts</span>
            <span>·</span>
            <span><span className="text-crit">{stats?.admins ?? "—"}</span> admins</span>
            <span>·</span>
            <span><span className="text-ion">{stats?.analysts ?? "—"}</span> analysts</span>
            <span>·</span>
            <span><span className="text-mist">{stats?.viewers ?? "—"}</span> viewers</span>
          </div>
        }
        actions={
          <button className="btn btn-primary btn-sm" onClick={() => setCreateOpen(true)}><UserPlus size={13} /> Create account</button>
        }
      />

      <div className="mb-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="All accounts" value={String(stats?.total ?? "—")} detail="Active and deactivated" icon={<UsersIcon size={15} />} tone="ion" />
        <Kpi label="Active administrators" value={String(stats?.admins ?? "—")} detail="Full platform authority" icon={<ShieldCheck size={15} />} tone="crit" />
        <Kpi label="Analysts" value={String(stats?.analysts ?? "—")} detail="Triage and investigation" icon={<UserCog size={15} />} tone="violet" />
        <Kpi label="Viewers" value={String(stats?.viewers ?? "—")} detail="Read-only access" icon={<BadgeCheck size={15} />} tone="low" />
      </div>

      <Panel>
        <PanelHead
          title="Directory"
          kicker="Role-based access control"
          right={<span className="font-mono text-[9px] uppercase tracking-[0.1em] text-dim">{data?.total ?? 0} matching</span>}
        />
        <div className="grid gap-2 border-b border-line px-4 py-3 sm:grid-cols-[minmax(200px,1.4fr)_150px_150px_auto]">
          <div>
            <span className="field-label">Search</span>
            <SearchField value={q} onChange={(value) => { setQ(value); setPage(1); }} placeholder="Name or email…" />
          </div>
          <FilterSelect
            label="Role"
            value={role}
            onChange={(value) => { setRole(value); setPage(1); }}
            options={[{ value: "all", label: "All roles" }, ...ROLES.map((entry) => ({ value: entry, label: titleCase(entry) }))]}
          />
          <FilterSelect
            label="State"
            value={active}
            onChange={(value) => { setActive(value); setPage(1); }}
            options={[
              { value: "all", label: "Any state" },
              { value: "true", label: "Active only" },
              { value: "false", label: "Deactivated" },
            ]}
          />
          <div className="flex items-end">
            <span className="rounded-md border border-line bg-shade/20 px-3 py-2 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">page {data?.page ?? 1}</span>
          </div>
        </div>

        {usersQuery.isError ? (
          <ErrorState message={(usersQuery.error as any)?.message} retry={() => usersQuery.refetch()} />
        ) : usersQuery.isLoading ? (
          <LoadingBlock rows={7} label="Loading user directory" />
        ) : !items.length ? (
          <div className="py-16 text-center">
            <Search size={18} className="mx-auto text-dim" />
            <p className="mt-2 text-[12px] text-mist">No accounts match the current filters.</p>
          </div>
        ) : (
          <div className="table-shell overflow-x-auto border-0">
            <table className="w-full">
              <thead>
                <tr>
                  <th>Account</th>
                  <th>Role</th>
                  <th>Organisation</th>
                  <th>State</th>
                  <th>Last sign-in</th>
                  <th>Created</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {items.map((account) => (
                  <tr key={account.id} className="cursor-pointer" onClick={() => setSelected(account)}>
                    <td>
                      <div className="flex items-center gap-2.5">
                        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-line bg-veil/[0.03] font-mono text-[9.5px] text-ion">{account.initials}</span>
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="truncate text-[11.5px] text-ink">{account.full_name}</span>
                            {account.id === currentUser?.id && <span className="chip text-ion">you</span>}
                          </div>
                          <div className="truncate font-mono text-[9px] text-dim">{account.email}</div>
                        </div>
                      </div>
                    </td>
                    <td><span className={clsx("inline-flex h-[20px] items-center rounded-[4px] border px-2 font-mono text-[8.5px] uppercase tracking-[0.1em]", ROLE_TONE[account.role])}>{account.role}</span></td>
                    <td className="text-[10.5px] text-mist">{account.organisation?.name || "—"}</td>
                    <td>
                      <span className={clsx("chip", account.is_active ? "text-low" : "text-dim")}>{account.is_active ? "Active" : "Deactivated"}</span>
                    </td>
                    <td className="font-mono text-[9.5px] text-dim">{account.last_login_at ? relTime(account.last_login_at) : "never"}</td>
                    <td className="font-mono text-[9.5px] text-dim">{fmtDate(account.created_at)}</td>
                    <td className="text-right">
                      <button className="btn btn-quiet btn-sm" onClick={(event) => { event.stopPropagation(); setSelected(account); }}>Manage</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && <Pagination page={data.page} pages={data.pages} total={data.total} onPage={setPage} />}
      </Panel>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Create account"
        description="New accounts are created directly by an administrator. Share the initial password through an approved secure channel."
        className="max-w-[560px]"
        footer={
          <>
            <button className="btn btn-ghost" onClick={() => setCreateOpen(false)}>Cancel</button>
            <button className="btn btn-primary" onClick={submitCreate} disabled={create.isPending}>
              {create.isPending ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />} Create account
            </button>
          </>
        }
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="sm:col-span-2">
            <span className="field-label">Full name</span>
            <input className="field" value={form.full_name} onChange={(event) => setForm({ ...form, full_name: event.target.value })} placeholder="Dana Whitfield" />
          </label>
          <label>
            <span className="field-label">Email</span>
            <input type="email" className="field" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} placeholder="analyst@organisation.example" />
          </label>
          <label>
            <span className="field-label">Role</span>
            <select className="field" value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value })}>
              {ROLES.map((entry) => <option key={entry} value={entry}>{titleCase(entry)}</option>)}
            </select>
          </label>
          <label className="sm:col-span-2">
            <span className="field-label">Initial password</span>
            <input type="password" className="field font-mono" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} placeholder="At least 10 characters" autoComplete="new-password" />
            <div className="mt-1.5 flex flex-wrap gap-1">
              {PASSWORD_RULES.map((rule) => {
                const satisfied = !passwordIssues(form.password).includes(rule);
                return (
                  <span key={rule} className={clsx("chip", satisfied ? "text-low" : "text-dim")}>
                    {satisfied && <Check size={8} className="mr-1" />} {rule}
                  </span>
                );
              })}
            </div>
          </label>
          <label className="sm:col-span-2">
            <span className="field-label">Organisation (optional)</span>
            <select className="field" value={form.organisation_id} onChange={(event) => setForm({ ...form, organisation_id: event.target.value })}>
              <option value="">Default to your organisation</option>
              {organisations.map((org: any) => <option key={org.id} value={org.id}>{org.name}</option>)}
            </select>
          </label>
        </div>
      </Modal>

      <Drawer
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected ? (
          <div className="flex items-center gap-2.5">
            <span className="grid h-9 w-9 place-items-center rounded-lg border border-line bg-veil/[0.03] font-mono text-[10px] text-ion">{selected.initials}</span>
            <div>
              <div className="flex items-center gap-2 text-[14px] font-semibold text-ink">{selected.full_name} {isSelf && <span className="chip text-ion">you</span>}</div>
              <div className="font-mono text-[9px] text-dim">{selected.email}</div>
            </div>
          </div>
        ) : <span>Account</span>}
        subtitle={
          selected && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
              <span className={clsx("inline-flex h-[20px] items-center rounded-[4px] border px-1.5", ROLE_TONE[selected.role])}>{selected.role}</span>
              <span>·</span>
              <span>{selected.is_active ? "active" : "deactivated"}</span>
              <span>·</span>
              <span>created {fmtDate(selected.created_at)}</span>
            </div>
          )
        }
        width="max-w-[560px]"
        footer={
          selected && (
            <>
              <button className="btn btn-ghost btn-sm" onClick={() => setSelected(null)}>Close</button>
              <button
                className="btn btn-primary btn-sm"
                disabled={update.isPending}
                onClick={() =>
                  update.mutate({
                    id: selected.id,
                    payload: {
                      role: editRole,
                      is_active: editActive,
                      notification_email: notifyEmail,
                      notification_critical_only: notifyCritical,
                    },
                  })
                }
              >
                {update.isPending ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />} Save changes
              </button>
            </>
          )
        }
      >
        {selected && (
          <div>
            <section className="border-b border-line pb-4">
              <SectionLabel>Access</SectionLabel>
              <div className="grid gap-3 sm:grid-cols-2">
                <label>
                  <span className="field-label">Role</span>
                  <select className="field" value={editRole} onChange={(event) => setEditRole(event.target.value)}>
                    {ROLES.map((entry) => <option key={entry} value={entry}>{titleCase(entry)}</option>)}
                  </select>
                </label>
                <div className="flex items-end">
                  <div className="flex h-[36px] w-full items-center justify-between rounded-md border border-line bg-shade/20 px-3">
                    <span className="text-[10.5px] text-mist">Account active</span>
                    <Toggle checked={editActive} onChange={setEditActive} label="Account active" />
                  </div>
                </div>
              </div>
              {isSelf && (
                <p className="mt-2 text-[9.5px] leading-relaxed text-med">You cannot deactivate your own account or remove the final administrator. The server enforces both constraints.</p>
              )}
            </section>

            <section className="border-b border-line py-4">
              <SectionLabel>Notification preferences</SectionLabel>
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-3 rounded-md border border-line bg-shade/20 px-3 py-2.5">
                  <div>
                    <div className="text-[10.5px] text-ink">Email alerts</div>
                    <div className="text-[9px] text-dim">Requires SMTP configuration on the server</div>
                  </div>
                  <Toggle checked={notifyEmail} onChange={setNotifyEmail} label="Email alerts" />
                </div>
                <div className="flex items-center justify-between gap-3 rounded-md border border-line bg-shade/20 px-3 py-2.5">
                  <div>
                    <div className="text-[10.5px] text-ink">Critical only</div>
                    <div className="text-[9px] text-dim">Suppress non-critical notification mail</div>
                  </div>
                  <Toggle checked={notifyCritical} onChange={setNotifyCritical} label="Critical only notifications" />
                </div>
              </div>
            </section>

            <section className="border-b border-line py-4">
              <SectionLabel right={<KeyRound size={11} className="text-dim" />}>Reset password</SectionLabel>
              <div className="flex flex-col gap-2 sm:flex-row">
                <input
                  type="password"
                  className="field font-mono"
                  value={resetPassword}
                  onChange={(event) => setResetPassword(event.target.value)}
                  placeholder="New password"
                  autoComplete="new-password"
                />
                <button
                  className="btn btn-ghost btn-sm shrink-0"
                  disabled={reset.isPending || !resetPassword}
                  onClick={() => {
                    const issues = passwordIssues(resetPassword);
                    if (issues.length) {
                      push("error", `Password must contain ${issues.join(", ")}.`);
                      return;
                    }
                    reset.mutate({ id: selected.id, new_password: resetPassword });
                  }}
                >
                  {reset.isPending ? <Loader2 size={12} className="animate-spin" /> : <KeyRound size={12} />} Reset
                </button>
              </div>
              <p className="mt-1.5 text-[9px] leading-relaxed text-dim">Existing sessions remain valid until their token expires. Ask the account holder to change the password after signing in.</p>
            </section>

            <section className="pt-4">
              <SectionLabel>Lifecycle</SectionLabel>
              <div className="flex items-center justify-between gap-3 rounded-md border border-crit/20 bg-crit/[0.03] px-3 py-2.5">
                <div>
                  <div className="text-[10.5px] text-ink">Deactivate account</div>
                  <div className="text-[9px] text-dim">Sign-in is blocked; records and audit history are retained.</div>
                </div>
                <button className="btn btn-danger btn-sm" disabled={!selected.is_active || isSelf} onClick={() => setConfirmDeactivate(true)}>
                  <UserX size={12} /> Deactivate
                </button>
              </div>
            </section>
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={confirmDeactivate}
        onClose={() => setConfirmDeactivate(false)}
        onConfirm={() => selected && deactivate.mutate(selected.id)}
        title="Deactivate this account?"
        body={`${selected?.email || "This account"} will be unable to sign in. Existing records, assignments and audit entries are preserved. An administrator can reactivate the account later.`}
        confirmLabel="Deactivate account"
        danger
        busy={deactivate.isPending}
      />
    </>
  );
}
