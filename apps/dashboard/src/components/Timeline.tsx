/**
 * Live decision timeline, grouped by run.
 *
 * Rows arrive over SSE and are rendered from the persisted event payload, never from
 * client-side sample data: if the backend has no decision, this list is empty. Expanding
 * a row shows the rule IDs, the reason codes with their catalogue explanations, and the
 * raw redacted evidence, so the UI never paraphrases a reason code it does not have.
 */

import { useMemo, useState } from "react";
import type { DecisionPayload, ReasonCatalog } from "../types";
import { EmptyState, StatusPill, TagRow, relativeTime } from "./primitives";

export function Timeline({
  decisions,
  catalog,
  highlightIds,
}: {
  decisions: DecisionPayload[];
  catalog: ReasonCatalog | null;
  highlightIds: ReadonlySet<string>;
}) {
  const [open, setOpen] = useState<string | null>(null);

  const explain = useMemo(() => {
    const map = new Map<string, string>();
    for (const entry of catalog?.reasons ?? []) {
      map.set(entry.code, entry.explanation);
    }
    return map;
  }, [catalog]);

  if (decisions.length === 0) {
    return (
      <EmptyState title="No decisions recorded yet">
        Every tool call that reaches the gateway appears here within a moment of being
        decided. Start the demo with <code className="chip">make demo</code>, or point an MCP
        host at the gateway.
      </EmptyState>
    );
  }

  return (
    <ul className="timeline">
      {decisions.map((decision) => {
        const expanded = open === decision.attempt_id;
        const evidence = decision.evidence ?? {};
        const resource = evidence["resource"] as { normalized_path?: string } | undefined;
        const destination = evidence["destination"] as { normalized?: string } | undefined;
        const target = resource?.normalized_path ?? destination?.normalized ?? null;
        return (
          <li
            key={decision.attempt_id}
            className={highlightIds.has(decision.attempt_id) ? "new-flash" : undefined}
          >
            <button
              type="button"
              className="tl-row"
              aria-expanded={expanded}
              onClick={() => setOpen(expanded ? null : decision.attempt_id)}
            >
              <span className={`tl-rail ${decision.status}`} aria-hidden="true" />
              <span className="tl-main">
                <span className="tl-tool">{decision.tool_name ?? decision.attempt_id}</span>
                <span className="tl-meta">
                  <span>{relativeTime(decision.timestamp)}</span>
                  <span>·</span>
                  <span>{decision.rule_ids[0] ?? "R0-fail-closed"}</span>
                  {target ? (
                    <>
                      <span>·</span>
                      <span className="mono">{target}</span>
                    </>
                  ) : null}
                  <span>·</span>
                  <span>{decision.elapsed_ms.toFixed(2)} ms</span>
                  {decision.upstream_executed ? (
                    <>
                      <span>·</span>
                      <span>upstream ran</span>
                    </>
                  ) : null}
                </span>
              </span>
              <StatusPill status={decision.status} />
            </button>

            {expanded ? (
              <div className="tl-detail">
                <div>
                  <strong style={{ fontSize: "0.8rem" }}>Why</strong>
                  <ul style={{ margin: "0.3rem 0 0", paddingLeft: "1.1rem", fontSize: "0.85rem" }}>
                    {decision.reason_codes.map((code) => (
                      <li key={code}>
                        <code className="chip">{code}</code>{" "}
                        {explain.get(code) ?? "(no catalogue entry for this code)"}
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <strong style={{ fontSize: "0.8rem" }}>Rules evaluated</strong>
                  <div style={{ marginTop: "0.3rem" }}>
                    <TagRow items={decision.rule_ids} />
                  </div>
                </div>
                <div style={{ fontSize: "0.82rem" }}>
                  <span className="footnote">
                    attempt <code className="chip">{decision.attempt_id}</code> · contract{" "}
                    <code className="chip">{(decision.contract_hash ?? "none").slice(0, 12)}</code> ·
                    revision #{decision.policy_revision ?? "—"}
                  </span>
                </div>
                <details>
                  <summary>Raw redacted evidence</summary>
                  <pre>{JSON.stringify(evidence, null, 2)}</pre>
                </details>
              </div>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}
