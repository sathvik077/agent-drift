/**
 * Replay Lab: observed guarded reality beside a simulated unguarded baseline.
 *
 * AD-16 is a labelling requirement, so labelling is the whole design here. Every row
 * carries its `source` as a visible badge, the simulated column is explicitly marked as
 * a counterfactual computed from recorded attempts, and the summary bar states each
 * metric's definition inline rather than in a tooltip a screenshot would lose.
 *
 * Nothing in the simulated column is evidence that an incident was prevented in the
 * wild, and the panel says that in plain words.
 */

import type { ReplayComparison, ReplayRow } from "../types";
import { EmptyState, Stat, StatusPill } from "./primitives";

/** What a call was aimed at: its resource, its destination, or an em dash. */
function targetOf(row: ReplayRow): string {
  return row.resource ?? row.destination ?? "\u2014";
}

/**
 * Whether the upstream tool ran. "unknown" is a real answer, not a missing one: a timed-out
 * call was delivered and may have completed, and the receipt must not claim otherwise.
 */
function executionLabel(state: ReplayRow["upstream_executed"]): string {
  if (state === "unknown") return "unknown";
  if (state === "yes") return "yes";
  return "no";
}

export function ReplayLab({ replay }: { replay: ReplayComparison | null }) {
  if (!replay) {
    return (
      <EmptyState title="Select a run to compare">
        Pick a run from the selector. Agent Drift will show the decisions it actually
        recorded next to what an unguarded passthrough would have attempted.
      </EmptyState>
    );
  }

  if (replay.guarded.length === 0) {
    return (
      <EmptyState title="This run has no recorded attempts">
        A run appears here once at least one tool call has traversed the gateway.
      </EmptyState>
    );
  }

  return (
    <div>
      <div className="stat-row" style={{ marginBottom: "1rem" }}>
        <Stat value={replay.summary.attempts} label="Attempts" detail={replay.metric_definitions["attempts"]} />
        <Stat value={replay.summary.blocked} label="Blocked" detail={replay.metric_definitions["blocked"]} />
        <Stat value={replay.summary.executed} label="Executed" detail={replay.metric_definitions["executed"]} />
        {replay.summary.execution_unknown > 0 ? (
          <Stat
            value={replay.summary.execution_unknown}
            label="Outcome unknown"
            detail={replay.metric_definitions["execution_unknown"]}
          />
        ) : null}
        <Stat
          value={replay.summary.would_execute_unguarded}
          label="Unguarded (sim.)"
          detail={replay.metric_definitions["would_execute_unguarded"]}
        />
      </div>

      <div className="replay-cols">
        <section className="panel" id="replay-observed-panel" aria-labelledby="replay-observed">
          <h3 id="replay-observed">
            <span className="pill allow">Observed</span> {replay.labels.observed}
          </h3>
          <p className="provenance">
            Real recorded decisions from this gateway session, including whether the upstream
            tool confirmed it ran.
          </p>
          <div className="table-wrap" style={{ marginTop: "0.5rem" }}>
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Tool</th>
                  <th scope="col">Target</th>
                  <th scope="col">Decision</th>
                  <th scope="col">Ran</th>
                </tr>
              </thead>
              <tbody>
                {replay.guarded.map((row) => (
                  <tr key={`g-${row.attempt_id}`}>
                    <td>
                      <code className="chip">{row.tool}</code>
                      {row.reason_codes && row.reason_codes.length > 0 ? (
                        <div className="footnote">{row.reason_codes.join(", ")}</div>
                      ) : null}
                    </td>
                    <td className="mono">{targetOf(row)}</td>
                    <td>
                      <StatusPill status={row.status} />
                    </td>
                    <td>{executionLabel(row.upstream_executed)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel untrusted" id="replay-simulated-panel" aria-labelledby="replay-simulated">
          <h3 id="replay-simulated">
            <span className="pill untrusted">Simulated</span> {replay.labels.simulated}
          </h3>
          <p className="provenance">
            Hypothetical. Computed from the same recorded attempts to show what a gateway-less
            setup would have forwarded. No tool was run to produce this column, and no row
            here represents a real prevented incident.
          </p>
          <div className="table-wrap" style={{ marginTop: "0.5rem" }}>
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Tool</th>
                  <th scope="col">Target</th>
                  <th scope="col">Outcome</th>
                </tr>
              </thead>
              <tbody>
                {replay.unguarded_simulated.map((row) => (
                  <tr key={`s-${row.attempt_id}`}>
                    <td>
                      <code className="chip">{row.tool}</code>
                    </td>
                    <td className="mono">{targetOf(row)}</td>
                    <td>
                      <span className="pill untrusted">would execute</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}
