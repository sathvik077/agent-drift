/**
 * Bundled scenario catalogue.
 *
 * Shows each demo's narrative, the untrusted content that drives it, and the decision
 * each step is *expected* to produce. The expectations shown here are the same JSON the
 * test harness asserts against, so a scenario that the UI describes and the suite does
 * not actually check cannot exist.
 */

import type { Scenario } from "../types";
import { EmptyState, StatusPill, TagRow } from "./primitives";

export function Scenarios({ scenarios }: { scenarios: Scenario[] }) {
  if (scenarios.length === 0) {
    return (
      <EmptyState title="No scenarios bundled">
        Scenario definitions live in <code className="chip">examples/scenarios/*.json</code>.
      </EmptyState>
    );
  }

  const adversarial = scenarios.filter((s) => s.category === "adversarial");
  const benign = scenarios.filter((s) => s.category === "benign");

  return (
    <div style={{ display: "grid", gap: "1rem" }}>
      <div className="banner info">
        <span>
          {scenarios.length} bundled scenarios &mdash; {benign.length} benign, {adversarial.length}{" "}
          adversarial. Reset and re-run them with <code className="chip">make demo</code>. Each
          expected decision below is asserted by{" "}
          <code className="chip">tests/integration/test_scenarios.py</code>.
        </span>
      </div>
      {scenarios.map((scenario) => (
        <article className="panel" key={scenario.id}>
          <h3>
            <span className={`pill ${scenario.category === "adversarial" ? "deny" : "allow"}`}>
              {scenario.category}
            </span>
            {scenario.attack_label ? <span className="pill neutral">{scenario.attack_label}</span> : null}
            <span style={{ textTransform: "none", letterSpacing: 0, color: "var(--fg)", fontSize: "0.9rem", fontWeight: 600 }}>
              {scenario.name}
            </span>
          </h3>
          <p style={{ fontSize: "0.87rem" }}>{scenario.narrative}</p>
          <p className="footnote">
            Task <code className="chip">{scenario.task_id}</code>
          </p>
          {scenario.untrusted_content ? (
            <details>
              <summary>Untrusted content that drives this scenario</summary>
              <pre>{scenario.untrusted_content}</pre>
            </details>
          ) : null}
          <div className="table-wrap" style={{ marginTop: "0.6rem" }}>
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Step</th>
                  <th scope="col">Tool</th>
                  <th scope="col">Arguments</th>
                  <th scope="col">Expected</th>
                </tr>
              </thead>
              <tbody>
                {scenario.steps.map((step, index) => (
                  <tr key={`${scenario.id}-${index}`}>
                    <td>{index + 1}</td>
                    <td>
                      <code className="chip">{step.tool}</code>
                    </td>
                    <td className="mono" style={{ fontSize: "0.76rem" }}>
                      {JSON.stringify(step.args)}
                    </td>
                    <td>
                      <StatusPill status={step.expected_decision} />
                      {step.expected_reason ? <TagRow items={[step.expected_reason]} /> : null}
                      {step.note ? <div className="footnote">{step.note}</div> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </article>
      ))}
    </div>
  );
}
