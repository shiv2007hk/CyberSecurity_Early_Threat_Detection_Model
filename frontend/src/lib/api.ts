export const API_BASE = "/api";
const TOKEN_KEY = "aegis.token";

export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export function getStoredUser(): User | null {
  try {
    const raw = localStorage.getItem("aegis.user");
    return raw ? (JSON.parse(raw) as User) : null;
  } catch {
    return null;
  }
}

export function setStoredUser(user: User | null) {
  if (user) localStorage.setItem("aegis.user", JSON.stringify(user));
  else localStorage.removeItem("aegis.user");
}

export async function api<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  headers.set("Accept", "application/json");

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  } catch {
    throw new ApiError(0, "The API is unreachable. Confirm the backend is running and retry.");
  }

  if (response.status === 204) return undefined as T;

  const isJson = response.headers.get("content-type")?.includes("application/json");
  const body = isJson ? await response.json().catch(() => null) : await response.text();

  if (!response.ok) {
    let message = typeof body === "string" && body ? body : `Request failed (${response.status})`;
    let detail: unknown = body;
    if (body && typeof body === "object") {
      const payload = body as Record<string, unknown>;
      detail = payload.detail ?? body;
      if (typeof payload.detail === "string") message = payload.detail;
      else if (Array.isArray(payload.detail)) {
        const first = payload.detail[0] as Record<string, unknown> | undefined;
        message = (typeof first?.msg === "string" ? first.msg : null) || "Please check the submitted values.";
      }
    }
    if (response.status === 401 && !path.startsWith("/auth/login")) {
      window.dispatchEvent(new CustomEvent("aegis:unauthorized"));
    }
    throw new ApiError(response.status, message, detail);
  }
  return body as T;
}

export function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "" && value !== "all") search.set(key, String(value));
  });
  const out = search.toString();
  return out ? `?${out}` : "";
}

export async function downloadFile(path: string, fallbackName: string) {
  const token = getToken();
  const response = await fetch(`${API_BASE}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
  });
  if (!response.ok) throw new ApiError(response.status, "Export failed. Try again or narrow the filters.");
  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") || "";
  const match = /filename="?([^";]+)"?/.exec(disposition);
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = match?.[1] || fallbackName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export type Role = "viewer" | "analyst" | "admin";

export interface Organisation {
  id: number;
  name: string;
  sector?: string;
  country?: string;
}

export interface User {
  id: number;
  email: string;
  full_name: string;
  role: Role;
  organisation?: Organisation | null;
  organisation_id?: number | null;
  is_active: boolean;
  notification_email: boolean;
  notification_critical_only: boolean;
  created_at?: string;
  last_login_at?: string | null;
  initials: string;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
  facets?: Record<string, Array<{ name: string; count: number }>>;
  stats?: Record<string, number>;
  /** List endpoints attach their own caveats to the page payload, not to each row. */
  note?: string;
  methodology?: string;
  [key: string]: unknown;
}

export interface Threat {
  id: number;
  ref: string;
  name: string;
  category: string;
  ai_category: string;
  description: string;
  source: string;
  source_url: string;
  published_at: string;
  updated_at: string;
  cve_id?: string | null;
  cvss_score?: number | null;
  cvss_severity?: string | null;
  epss_score?: number | null;
  known_exploited?: boolean;
  affected_technology?: string | null;
  affected_versions?: string | null;
  indicators?: Array<{ type: string; value: string }>;
  indicator_count: number;
  source_reliability?: number;
  evidence_refs?: Array<{ label: string; url?: string }>;
  ai_summary?: string;
  ai_confidence?: number;
  ai_keywords?: string[];
  ai_entities?: Record<string, string[]>;
  ai_explanation?: Record<string, any>;
  ai_method?: string;
  risk_score?: number;
  risk_category?: string;
  confidence?: number;
  urgency?: string;
  exploitation_status?: string;
  recommended_action?: string;
  severity: string;
  status: string;
  assigned_to?: number | null;
  is_saved?: boolean;
  retrieval_timestamp?: string;
  created_at?: string;
  [key: string]: any;
}

export interface Vulnerability {
  id: number;
  cve_id: string;
  title: string;
  description: string;
  cvss_score?: number | null;
  cvss_severity?: string;
  epss_score?: number | null;
  epss_percentile?: number | null;
  known_exploited?: boolean;
  kev_due_date?: string | null;
  ransomware_use?: boolean;
  published_at?: string;
  modified_at?: string;
  affected_products?: Array<{ vendor?: string; product?: string; versions?: any; notes?: string }>;
  references?: Array<{ label: string; url?: string }>;
  source?: string;
  source_url?: string;
  remediation?: string;
  [key: string]: any;
}

export interface Asset {
  id: number;
  ref: string;
  name: string;
  category: string;
  organisation?: Organisation | null;
  organisation_id?: number | null;
  identifier?: string;
  software?: string;
  software_version?: string;
  os?: string;
  exposure?: string;
  internet_facing?: boolean;
  criticality?: number;
  business_importance?: string;
  owner?: string;
  last_assessed_at?: string;
  notes?: string;
  risk?: {
    risk_score: number;
    risk_category: string;
    matched_vulnerabilities: number;
    validated_vulnerabilities: number;
    needs_verification: number;
    known_exploited: number;
    matches?: any[];
  };
  [key: string]: any;
}

export interface Alert {
  id: number;
  ref: string;
  title: string;
  severity: string;
  category: string;
  detected_at: string;
  threat_id?: number | null;
  vulnerability_id?: number | null;
  asset_ids?: number[];
  source?: string;
  risk_score?: number;
  confidence?: number;
  trigger_reason?: string;
  evidence?: Array<{ label: string; value: string; [key: string]: any }>;
  recommended_action?: string;
  status: string;
  assignee_id?: number | null;
  acknowledged_at?: string | null;
  resolved_at?: string | null;
  rule_key?: string;
  created_at?: string;
  [key: string]: any;
}

export interface Recommendation {
  id: number;
  ref: string;
  title: string;
  reason: string;
  priority: string;
  threat_id?: number | null;
  vulnerability_id?: number | null;
  asset_id?: number | null;
  alert_id?: number | null;
  action: string;
  evidence?: Array<{ label: string; value: string }>;
  status: string;
  owner_id?: number | null;
  due_at?: string | null;
  source_url?: string;
  created_at?: string;
  asset?: { ref: string; name: string; category?: string } | null;
  threat?: { ref: string; name: string; severity?: string } | null;
  vulnerability?: { cve_id: string; title: string; cvss?: number } | null;
  alert?: { ref: string; title: string; severity?: string } | null;
  owner?: { full_name: string; email: string } | null;
  [key: string]: any;
}

export interface Assessment {
  id: number;
  ref: string;
  risk_score: number;
  risk_category: string;
  urgency: string;
  exploitation_status: string;
  evidence_confidence: number;
  severity: number;
  exploitability: number;
  exposure: number;
  asset_criticality: number;
  evidence_strength: number;
  factors?: Array<{ key?: string; label?: string; value?: number; weight?: number; contribution?: number; [key: string]: any }>;
  explanation?: string;
  model_version?: string;
  created_at?: string;
  threat?: { ref: string; name: string; severity: string; cve_id?: string };
  asset?: { ref: string; name: string; category: string; criticality: number };
  vulnerability?: { cve_id: string; title: string; cvss?: number };
  [key: string]: any;
}

export interface Source {
  id: number;
  key: string;
  name: string;
  description: string;
  url: string;
  category: string;
  requires_key: boolean;
  key_configured: boolean;
  enabled: boolean;
  status: string;
  reliability: number;
  last_sync_at?: string | null;
  last_success_at?: string | null;
  items_ingested: number;
  latency_ms?: number | null;
  last_message?: string;
  automated_sync?: boolean;
  [key: string]: any;
}

export interface RoleAccount {
  role: string;
  email: string;
  password: string;
}
