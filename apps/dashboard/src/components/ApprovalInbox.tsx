/**
 * Human review queue.
 *
 * The important UX property is that a reviewer sees exactly what they are authorizing:
 * the tool, the canonical argument digest, the frozen argument preview, the contract
 * revision, and when the grant expires. Approving here authorizes *those* arguments
 * once. The copy says so, because a reviewer who believes they granted a standing
 * permission has been misled by the interface.
 */

import { useState } from "react";
import type { Approval } from "../types";
import { EmptyState, KeyValues, relativeTime } from "./primitives";

export function ApprovalInbox({
  approvals,
  reviewer,
  onDecide,
  disabled,
  disabledReason,
}: {
  approvals: Approval[];
  reviewer: string;
  onDecide: (approvalId: string, approve: boolean) => Promise<void>;
  disabled: boolean;
  disabledReason?: string;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const pending = approvals.filter((a) => a.state === "pending");
  const settled = approvals.filter((a) => a.state !== "pending").slice(0, 8);

  async function decide(approvalId: string, approve: boolean) {
    setBusy(approvalId);
    setError(null);
    try {
      await onDecide(approvalId, approve);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      {disabled ? (
        <div className="banner warn">
          <span>
            {disabledReason ??
              "Enter the admin token to approve or decline. Reviewing is a mutating action and requires authentication."}
          </span>
        </div>
      ) : null}
      {error ? (
        <div className="banner error" role="alert">
          <span>{error}</span>
        </div>
      ) : null}

      {pending.length === 0 ? (
        <EmptyState title="Nothing waiting for review">
          Calls to a tool listed in the contract&rsquo;s <code className="chip">approval_rules</code>{" "}
          pause here until a reviewer decides, or until the gateway&rsquo;s approval timeout
          elapses and the call is denied.
        </EmptyState>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: "0.8rem" }}>
          {pending.map((approval) => (
            <li key={approval.approval_id} className="panel">
              <h3>
                <span className="pill needs_approval">Awaiting review</span>
                <code className="chip">{approval.tool_name}</code>
              </h3>
              <KeyValues
                entries={[
                  ["Task", <code className="chip">{approval.task_id}</code>],
                  ["Operation", <code className="chip">{approval.operation}</code>],
                  ["Target", approval.target_resource ? <code className="chip">{approval.target_resource}</code> : "—"],
                  [
                    "Args digest",
                    <code className="chip" title={approval.args_digest}>
                      {approval.args_digest.slice(0, 20)}…
                    </code>,
                  ],
                  ["Revision", `#${approval.policy_revision}`],
                  ["Requested", relativeTime(approval.created_at)],
                  ["Expires", new Date(approval.expires_at).toLocaleTimeString()],
                ]}
              />
              <details style={{ marginTop: "0.5rem" }}>
                <summary>Frozen arguments (redacted)</summary>
                <pre>{JSON.stringify(approval.args_preview, null, 2)}</pre>
              </details>
              <p className="provenance">
                Approving authorizes exactly these canonical arguments, once, under revision
                #{approval.policy_revision}. Any other argument value, or a new contract
                revision, needs a fresh approval.
              </p>
              <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.6rem", flexWrap: "wrap" }}>
                <button
                  type="button"
                  className="btn primary"
                  disabled={disabled || busy === approval.approval_id}
                  onClick={() => decide(approval.approval_id, true)}
                >
                  {busy === approval.approval_id ? "Working…" : `Approve as ${reviewer}`}
                </button>
                <button
                  type="button"
                  className="btn danger"
                  disabled={disabled || busy === approval.approval_id}
                  onClick={() => decide(approval.approval_id, false)}
                >
                  Decline
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}

      {settled.length > 0 ? (
        <div style={{ marginTop: "1.2rem" }}>
          <h3 style={{ fontSize: "0.78rem", textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--fg-muted)" }}>
            Recently decided
          </h3>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Tool</th>
                  <th scope="col">State</th>
                  <th scope="col">Reviewer</th>
                  <th scope="col">When</th>
                </tr>
              </thead>
              <tbody>
                {settled.map((approval) => (
                  <tr key={approval.approval_id}>
                    <td>
                      <code className="chip">{approval.tool_name}</code>
                    </td>
                    <td>
                      <span className={`pill ${approval.state === "consumed" ? "allow" : approval.state === "declined" ? "deny" : "neutral"}`}>
                        {approval.state}
                      </span>
                    </td>
                    <td>{approval.decided_by ?? "—"}</td>
                    <td>{relativeTime(approval.decided_at ?? approval.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </div>
  );
}
