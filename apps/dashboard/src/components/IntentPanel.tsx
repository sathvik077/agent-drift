/**
 * Intent versus action: the juxtaposition that AD-13 is about.
 *
 * Three panels, visually distinct on purpose:
 *
 * - **Trusted intent** (teal, left border): what the user approved. Immutable.
 * - **Untrusted content** (amber): material that came from outside the trust boundary --
 *   a tool result, an issue comment, a retrieved page. Never authorization.
 * - **Attempted action and enforcement** (blue): what the agent tried and what happened.
 *
 * The colour and border language is carried by `.panel.trusted` / `.panel.untrusted` so
 * the distinction survives a screenshot and does not depend on reading the heading.
 */

import type { DecisionPayload, Scenario, TaskSummary } from "../types";
import { KeyValues, Meter, StatusPill, TagRow } from "./primitives";

export function IntentPanel({
  task,
  latest,
  scenario,
}: {
  task: TaskSummary;
  latest: DecisionPayload | null;
  scenario: Scenario | null;
}) {
  const untrusted =
    scenario?.untrusted_content ??
    "No untrusted content is associated with the selected view. Tool results, issue text and retrieved documents all land here when a scenario supplies them.";

  const evidence = (latest?.evidence ?? {}) as Record<string, unknown>;
  const resource = evidence["resource"] as { normalized_path?: string; matched_scope?: string } | undefined;
  const destination = evidence["destination"] as { normalized?: string; host?: string } | undefined;

  return (
    <div className="intent-grid">
      <div className="panel trusted">
        <h3>
          <span className="pill trusted">Trusted</span> Approved intent
        </h3>
        <p>{task.user_goal}</p>
        <KeyValues
          entries={[
            ["Task", <code className="chip">{task.task_id}</code>],
            ["Approved by", task.approved_by],
            ["Source", <code className="chip">{task.source}</code>],
            ["Revision", `#${task.policy_revision}`],
            [
              "Contract hash",
              <code className="chip" title={task.contract_hash}>
                {task.contract_hash.slice(0, 16)}…
              </code>,
            ],
            ["Allowed tools", <TagRow items={task.allowed_tools} />],
            ["Scopes", <TagRow items={task.resource_scopes} />],
            [
              "Destinations",
              task.allowed_destinations.length === 0 ? (
                <span className="pill deny">all egress denied</span>
              ) : (
                <TagRow items={task.allowed_destinations} />
              ),
            ],
            ["Denied actions", <TagRow items={task.denied_actions} />],
            [
              "Approval required",
              task.approval_rules.length === 0 ? (
                <span className="footnote">none</span>
              ) : (
                <TagRow items={task.approval_rules} />
              ),
            ],
          ]}
        />
        <div style={{ marginTop: "0.7rem", display: "grid", gap: "0.5rem" }}>
          <Meter used={task.budget.writes_used} max={task.max_writes} label="Writes used" />
          <Meter used={task.budget.calls_used} max={task.max_calls} label="Calls used" />
        </div>
        {task.expired ? (
          <p className="footnote" style={{ color: "var(--deny)", fontWeight: 600 }}>
            This contract has expired. Nothing can be authorized under it.
          </p>
        ) : null}
      </div>

      <div style={{ display: "grid", gap: "0.85rem", alignContent: "start" }}>
        <div className="panel untrusted">
          <h3>
            <span className="pill untrusted">Untrusted</span> Content the agent read
          </h3>
          <p style={{ whiteSpace: "pre-wrap", fontSize: "0.86rem" }}>{untrusted}</p>
          <p className="provenance">
            Untrusted content is data, never authorization. Nothing in this panel can change
            the task, the contract, the trust tier or an approval.
          </p>
        </div>

        <div className="panel action">
          <h3>
            <span className="pill accent">Action</span> Attempted call and enforcement
          </h3>
          {latest ? (
            <KeyValues
              entries={[
                ["Decision", <StatusPill status={latest.status} />],
                ["Rules fired", <TagRow items={latest.rule_ids} />],
                ["Reason codes", <TagRow items={latest.reason_codes} />],
                ["Risk", <span className={`risk-${latest.risk}`}>{latest.risk}</span>],
                [
                  "Upstream executed",
                  latest.upstream_executed === "unknown" ? (
                    <span className="pill needs_approval" title="timed out or cancelled">
                      unknown
                    </span>
                  ) : latest.upstream_executed === "yes" || latest.upstream_executed === true ? (
                    <span className="pill allow">yes</span>
                  ) : (
                    <span className="pill neutral">no</span>
                  ),
                ],
                ["Target", resource?.normalized_path ? <code className="chip">{resource.normalized_path}</code> : "—"],
                ["Matched scope", resource?.matched_scope ? <code className="chip">{resource.matched_scope}</code> : "—"],
                ["Destination", destination?.normalized ? <code className="chip">{destination.normalized}</code> : "—"],
                ["Decision latency", `${latest.elapsed_ms.toFixed(2)} ms`],
              ]}
            />
          ) : (
            <p className="footnote">
              No decision recorded yet for this task. Run <code className="chip">make demo</code> or
              drive a tool call through the gateway to populate this panel.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
