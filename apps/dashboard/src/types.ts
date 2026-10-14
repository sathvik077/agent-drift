/** Shared types mirroring the control-plane JSON shapes. */

export type DecisionStatus = "allow" | "deny" | "needs_approval";
export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface Health {
  status: "ok" | "degraded";
  version: string;
  mcp_sdk_version: string;
  mcp_protocol_revision: string;
  database: string;
  schema_version: string;
  events: number;
  tasks: number;
  time: string;
}

export interface Budget {
  calls_used: number;
  writes_used: number;
}

export interface TaskSummary {
  task_id: string;
  user_goal: string;
  policy_revision: number;
  contract_hash: string;
  source: string;
  principal: string;
  approved_by: string;
  expires_at: string | null;
  expired: boolean;
  allowed_tools: string[];
  denied_actions: string[];
  resource_scopes: string[];
  allowed_destinations: string[];
  max_writes: number;
  max_calls: number;
  approval_rules: string[];
  budget: Budget;
  decision_counts: Record<string, number>;
  created_at: string;
}

export interface AttemptPayload {
  attempt_id: string;
  request_id: string;
  trace_id: string;
  run_id: string;
  task_id: string | null;
  tool_server: string;
  tool_name: string;
  args: Record<string, unknown>;
  args_digest: string;
  operation: string;
  target_resource: string | null;
  destination: string | null;
  untrusted_context_ref: string | null;
  timestamp: string;
}

export interface DecisionPayload {
  decision_id: string;
  attempt_id: string;
  task_id: string | null;
  status: DecisionStatus;
  tool_name: string | null;
  tool_server: string | null;
  operation: string | null;
  target_resource: string | null;
  destination: string | null;
  reason_codes: string[];
  rule_ids: string[];
  evidence: Record<string, unknown>;
  risk: RiskLevel;
  contract_hash: string | null;
  policy_revision: number | null;
  elapsed_ms: number;
  upstream_executed: boolean | "yes" | "no" | "unknown";
  upstream_error: string | null;
  approval_id: string | null;
  reviewer: Record<string, unknown> | null;
  timestamp: string;
  run_id?: string;
}

export interface AuditEvent {
  seq: number;
  event_id: string;
  kind: string;
  task_id: string | null;
  run_id: string | null;
  attempt_id: string | null;
  payload: Record<string, unknown>;
  hmac: string | null;
  created_at: string;
}

export interface Approval {
  approval_id: string;
  attempt_id: string;
  task_id: string;
  tool_name: string;
  tool_server: string;
  args_digest: string;
  args_preview: Record<string, unknown>;
  policy_revision: number;
  contract_hash: string;
  state: "pending" | "approved" | "declined" | "consumed" | "expired";
  created_at: string;
  expires_at: string;
  decided_at: string | null;
  decided_by: string | null;
  consumed_at: string | null;
  operation: string;
  target_resource: string | null;
}

export interface RunSummary {
  run_id: string;
  task_id: string | null;
  scenario: string | null;
  label: string | null;
  started_at: string;
  ended_at: string | null;
  decisions: number;
  allowed: number;
  denied: number;
  pending: number;
}

export type ExecutionState = "yes" | "no" | "unknown";

export interface RunStep {
  attempt: AttemptPayload;
  decision: DecisionPayload | null;
  status: DecisionStatus | null;
  upstream_executed: ExecutionState;
  at: string;
}

export interface RunDetail {
  run_id: string;
  task_id: string | null;
  scenario: string | null;
  label: string | null;
  started_at: string;
  ended_at: string | null;
  steps: RunStep[];
}

export interface ReplayRow {
  source: "observed" | "simulated";
  provenance: string;
  attempt_id: string;
  tool: string;
  operation: string;
  resource: string | null;
  destination: string | null;
  status: string;
  reason_codes?: string[];
  rule_ids?: string[];
  upstream_executed?: ExecutionState;
  would_have_executed?: boolean;
  elapsed_ms?: number | null;
  note?: string;
  at: string;
}

export interface ReplayComparison {
  run_id: string;
  task_id: string | null;
  labels: { observed: string; simulated: string };
  metric_definitions: Record<string, string>;
  summary: {
    attempts: number;
    blocked: number;
    executed: number;
    execution_unknown: number;
    would_execute_unguarded: number;
  };
  guarded: ReplayRow[];
  unguarded_simulated: ReplayRow[];
}

export interface Scenario {
  id: string;
  name: string;
  category: "benign" | "adversarial";
  attack_label?: string;
  task_id: string;
  narrative: string;
  untrusted_content?: string;
  steps: Array<{
    tool: string;
    args: Record<string, unknown>;
    expected_decision: DecisionStatus;
    expected_reason?: string;
    note?: string;
  }>;
  _file?: string;
}

export interface ReasonEntry {
  code: string;
  explanation: string;
  rule: string;
}

export interface ReasonCatalog {
  rules: string[];
  reasons: ReasonEntry[];
  tool_specs: Array<{
    name: string;
    operation: string;
    resource_arg: string | null;
    destination_arg: string | null;
  }>;
}

/** Loading state shared by every async panel. */
export type Loadable<T> =
  | { state: "loading" }
  | { state: "error"; message: string }
  | { state: "ready"; value: T };
