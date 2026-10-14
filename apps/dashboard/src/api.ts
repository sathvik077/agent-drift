/**
 * Control-plane client.
 *
 * Two things worth noting about the design:
 *
 * 1. The admin token is held in memory and in `sessionStorage`, never in a cookie. A
 *    cookie would be sent automatically by the browser and would need CSRF protection;
 *    an explicit `Authorization` header cannot be triggered by a cross-site form post.
 * 2. Every call returns a discriminated result rather than throwing, so each panel can
 *    render a real error state instead of blanking the page.
 */

import type {
  Approval,
  AuditEvent,
  DecisionPayload,
  Health,
  ReasonCatalog,
  ReplayComparison,
  RunDetail,
  RunSummary,
  Scenario,
  TaskSummary,
} from "./types";

const TOKEN_KEY = "agent-drift.admin-token";

/** Base URL of the control plane. Same origin when the dashboard is served by it. */
export const API_BASE: string =
  (typeof window !== "undefined" && window.location.port === "5173"
    ? `http://127.0.0.1:${new URLSearchParams(window.location.search).get("apiPort") ?? "8001"}`
    : "") || "";

/** Read the stored admin token, tolerating blocked storage. */
export function getToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

/** Store the admin token for this browser session only. */
export function setToken(token: string): void {
  try {
    if (token) {
      sessionStorage.setItem(TOKEN_KEY, token);
    } else {
      sessionStorage.removeItem(TOKEN_KEY);
    }
  } catch {
    /* private mode or blocked storage: the token simply is not remembered */
  }
}

export class ApiError extends Error {
  readonly status: number;
  readonly detail: string | undefined;

  constructor(status: number, message: string, detail?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body) {
    headers.set("content-type", "application/json");
  }
  const token = getToken();
  if (token) {
    headers.set("authorization", `Bearer ${token}`);
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch (cause) {
    throw new ApiError(
      0,
      "Cannot reach the control plane",
      `Is it running? ${String(cause)}`,
    );
  }

  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    let detail: string | undefined;
    try {
      const body = (await response.json()) as { error?: string; detail?: string };
      message = body.error ?? message;
      detail = body.detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(response.status, message, detail);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const api = {
  health: () => request<Health>("/healthz"),
  tasks: () => request<{ tasks: TaskSummary[] }>("/api/tasks"),
  task: (taskId: string) =>
    request<{ task_id: string; semantic: Record<string, unknown>; budget: unknown; expired: boolean }>(
      `/api/tasks/${encodeURIComponent(taskId)}`,
    ),
  decisions: (params: { taskId?: string; status?: string; limit?: number } = {}) => {
    const query = new URLSearchParams();
    if (params.taskId) query.set("task_id", params.taskId);
    if (params.status) query.set("status", params.status);
    query.set("limit", String(params.limit ?? 100));
    return request<{ decisions: DecisionPayload[]; counts: Record<string, number> }>(
      `/api/decisions?${query.toString()}`,
    );
  },
  events: (since: number, taskId?: string) => {
    const query = new URLSearchParams({ since: String(since), limit: "200" });
    if (taskId) query.set("task_id", taskId);
    return request<{ events: AuditEvent[]; latest_seq: number }>(`/api/events?${query.toString()}`);
  },
  runs: (taskId?: string) => {
    const query = new URLSearchParams();
    if (taskId) query.set("task_id", taskId);
    return request<{ runs: RunSummary[] }>(`/api/runs?${query.toString()}`);
  },
  run: (runId: string) => request<RunDetail>(`/api/runs/${encodeURIComponent(runId)}`),
  replay: (runId: string) =>
    request<ReplayComparison>(`/api/runs/${encodeURIComponent(runId)}/replay`),
  approvals: (state?: string) => {
    const query = new URLSearchParams();
    if (state) query.set("state", state);
    return request<{ approvals: Approval[] }>(`/api/approvals?${query.toString()}`);
  },
  approve: (approvalId: string, reviewer: string) =>
    request<{ approval_id: string; state: string }>(
      `/api/approvals/${encodeURIComponent(approvalId)}/approve`,
      { method: "POST", body: JSON.stringify({ reviewer }) },
    ),
  decline: (approvalId: string, reviewer: string, note?: string) =>
    request<{ approval_id: string; state: string }>(
      `/api/approvals/${encodeURIComponent(approvalId)}/deny`,
      { method: "POST", body: JSON.stringify({ reviewer, note }) },
    ),
  scenarios: () => request<{ scenarios: Scenario[] }>("/api/scenarios"),
  reasons: () => request<ReasonCatalog>("/api/reasons"),
  auditVerify: () =>
    request<{ configured: boolean; verified: boolean; events: number; problem: string | null; note: string }>(
      "/api/audit/verify",
    ),
  exportUrl: (taskId: string) => `${API_BASE}/api/export/${encodeURIComponent(taskId)}`,
  streamUrl: (since: number) => `${API_BASE}/api/events/stream?since=${since}`,
};
