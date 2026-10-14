/**
 * Agent Drift dashboard shell.
 *
 * Every panel is driven by the control plane. There is no client-side sample data
 * anywhere in this application: if the backend has recorded nothing, the UI shows an
 * empty state that explains how to produce data, which is a deliberate choice so a
 * screenshot of this dashboard can never show a decision that did not happen.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent } from "react";
import { ApiError, api, getToken, setToken } from "./api";
import { ApprovalInbox } from "./components/ApprovalInbox";
import { IntentPanel } from "./components/IntentPanel";
import { ReplayLab } from "./components/ReplayLab";
import { Scenarios } from "./components/Scenarios";
import { Timeline } from "./components/Timeline";
import { Card, ErrorState, LoadingState, Stat } from "./components/primitives";
import { useLiveEvents } from "./useLiveEvents";
import type {
  Approval,
  DecisionPayload,
  Health,
  ReasonCatalog,
  ReplayComparison,
  RunSummary,
  Scenario,
  TaskSummary,
} from "./types";

type TabId = "overview" | "timeline" | "approvals" | "replay" | "scenarios";

const TABS: Array<{ id: TabId; label: string }> = [
  { id: "overview", label: "Intent vs action" },
  { id: "timeline", label: "Live trace" },
  { id: "approvals", label: "Approvals" },
  { id: "replay", label: "Replay Lab" },
  { id: "scenarios", label: "Scenarios" },
];

export function App() {
  const [tab, setTab] = useState<TabId>("overview");
  const [health, setHealth] = useState<Health | null>(null);
  const [fatal, setFatal] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [tasks, setTasks] = useState<TaskSummary[]>([]);
  const [selectedTask, setSelectedTask] = useState<string>("");
  const [decisions, setDecisions] = useState<DecisionPayload[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [selectedRun, setSelectedRun] = useState<string>("");
  const [replay, setReplay] = useState<ReplayComparison | null>(null);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [catalog, setCatalog] = useState<ReasonCatalog | null>(null);

  const [token, setTokenState] = useState<string>(getToken());
  const [reviewer, setReviewer] = useState("local-reviewer");
  const [highlights, setHighlights] = useState<Set<string>>(new Set());
  const highlightTimers = useRef<number[]>([]);

  const refreshCore = useCallback(async () => {
    const [taskPage, approvalPage, runPage] = await Promise.all([
      api.tasks(),
      api.approvals(),
      api.runs(),
    ]);
    setTasks(taskPage.tasks);
    setApprovals(approvalPage.approvals);
    setRuns(runPage.runs);
    setSelectedTask((current) => current || taskPage.tasks[0]?.task_id || "");
    setSelectedRun((current) => current || runPage.runs[0]?.run_id || "");
  }, []);

  // Initial load.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const [healthResult, catalogResult, scenarioResult] = await Promise.all([
          api.health(),
          api.reasons(),
          api.scenarios(),
        ]);
        if (cancelled) return;
        setHealth(healthResult);
        setCatalog(catalogResult);
        setScenarios(scenarioResult.scenarios);
        await refreshCore();
      } catch (cause) {
        if (!cancelled) {
          setFatal(
            cause instanceof ApiError
              ? `${cause.message}${cause.detail ? ` — ${cause.detail}` : ""}`
              : String(cause),
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [refreshCore]);

  // Decisions for the selected task.
  const refreshDecisions = useCallback(async (taskId: string) => {
    if (!taskId) {
      setDecisions([]);
      return;
    }
    const page = await api.decisions({ taskId, limit: 150 });
    setDecisions(page.decisions);
  }, []);

  useEffect(() => {
    void refreshDecisions(selectedTask).catch(() => undefined);
  }, [selectedTask, refreshDecisions]);

  // Live events drive a refresh of the panels that can change.
  const onLiveEvent = useCallback(
    (event: { kind: string; attempt_id: string | null; task_id: string | null }) => {
      if (event.kind.startsWith("DECISION_") && event.attempt_id) {
        const id = event.attempt_id;
        setHighlights((prev) => new Set(prev).add(id));
        const timer = window.setTimeout(() => {
          setHighlights((prev) => {
            const next = new Set(prev);
            next.delete(id);
            return next;
          });
        }, 2000);
        highlightTimers.current.push(timer);
      }
      if (
        event.kind.startsWith("DECISION_") ||
        event.kind.startsWith("APPROVAL") ||
        event.kind === "CONTRACT_REGISTERED" ||
        event.kind === "UPSTREAM_RESULT"
      ) {
        void refreshCore().catch(() => undefined);
        void refreshDecisions(selectedTask).catch(() => undefined);
      }
    },
    [refreshCore, refreshDecisions, selectedTask],
  );

  const live = useLiveEvents(onLiveEvent);

  useEffect(
    () => () => {
      for (const timer of highlightTimers.current) window.clearTimeout(timer);
    },
    [],
  );

  // Replay for the selected run.
  useEffect(() => {
    let cancelled = false;
    if (!selectedRun) {
      setReplay(null);
      return;
    }
    void api
      .replay(selectedRun)
      .then((value) => {
        if (!cancelled) setReplay(value);
      })
      .catch(() => {
        if (!cancelled) setReplay(null);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedRun, decisions.length]);

  const task = useMemo(
    () => tasks.find((candidate) => candidate.task_id === selectedTask) ?? null,
    [tasks, selectedTask],
  );

  const latestDecision = decisions[0] ?? null;

  const scenarioForTask = useMemo(
    () => scenarios.find((candidate) => candidate.task_id === selectedTask) ?? null,
    [scenarios, selectedTask],
  );

  const totals = useMemo(() => {
    let allowed = 0;
    let blocked = 0;
    let review = 0;
    let executed = 0;
    for (const decision of decisions) {
      if (decision.status === "allow") allowed += 1;
      else if (decision.status === "deny") blocked += 1;
      else review += 1;
      if (decision.upstream_executed) executed += 1;
    }
    const latencies = decisions.map((d) => d.elapsed_ms).filter((v) => v > 0).sort((a, b) => a - b);
    const p95 =
      latencies.length === 0
        ? 0
        : latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * 0.95))] ?? 0;
    return { allowed, blocked, review, executed, p95 };
  }, [decisions]);

  const pendingCount = approvals.filter((a) => a.state === "pending").length;

  const applyToken = useCallback((value: string) => {
    setToken(value);
    setTokenState(value);
  }, []);

  const decide = useCallback(
    async (approvalId: string, approve: boolean) => {
      if (approve) {
        await api.approve(approvalId, reviewer);
      } else {
        await api.decline(approvalId, reviewer, "declined from the dashboard");
      }
      await refreshCore();
      await refreshDecisions(selectedTask);
    },
    [reviewer, refreshCore, refreshDecisions, selectedTask],
  );

  if (fatal) {
    return (
      <div className="content">
        <ErrorState
          message="Cannot reach the Agent Drift control plane"
          detail={`${fatal}. Start it with \`make dev\` (or \`agent-drift api\`) and reload.`}
          onRetry={() => window.location.reload()}
        />
      </div>
    );
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            AD
          </span>
          <span>
            Agent Drift
            <span className="brand-sub">
              {health
                ? `v${health.version} · MCP ${health.mcp_protocol_revision} · SDK ${health.mcp_sdk_version}`
                : "connecting…"}
            </span>
          </span>
        </div>
        <div className="topbar-stats">
          <span className="pill neutral" title={`Live updates: ${live.mode}`}>
            <span
              className={`live-dot ${live.mode === "stream" ? "" : live.mode === "error" ? "error" : "off"}`}
              aria-hidden="true"
            />
            {live.mode === "stream"
              ? "live"
              : live.mode === "polling"
                ? "polling"
                : live.mode === "error"
                  ? "offline"
                  : "connecting"}
          </span>
          {pendingCount > 0 ? (
            <span className="pill needs_approval">{pendingCount} awaiting review</span>
          ) : null}
          <span className="pill neutral">{live.lastSeq} events</span>
        </div>
      </header>

      <main className="content">
        {loading ? (
          <Card title="Loading">
            <LoadingState rows={4} label="Loading control plane state" />
          </Card>
        ) : (
          <>
            {health?.status === "degraded" ? (
              <div className="banner error" role="alert">
                <span>
                  The control plane reports a degraded decision store. Agent Drift fails
                  closed, so tool calls will be denied until the store is reachable.
                </span>
              </div>
            ) : null}

            <div className="banner info">
              <label htmlFor="task-select" style={{ margin: 0 }}>
                Task
              </label>
              <select
                id="task-select"
                value={selectedTask}
                onChange={(event: ChangeEvent<HTMLSelectElement>) => setSelectedTask(event.target.value)}
                style={{ maxWidth: "20rem" }}
              >
                {tasks.length === 0 ? <option value="">no tasks registered</option> : null}
                {tasks.map((candidate) => (
                  <option key={candidate.task_id} value={candidate.task_id}>
                    {candidate.task_id}
                    {candidate.expired ? " (expired)" : ""}
                  </option>
                ))}
              </select>
              {selectedTask ? (
                <a className="btn small" href={api.exportUrl(selectedTask)} download>
                  Download audit JSON
                </a>
              ) : null}
            </div>

            <div className="tabs" role="tablist" aria-label="Dashboard sections">
              {TABS.map((entry) => (
                <button
                  key={entry.id}
                  type="button"
                  role="tab"
                  id={`tab-${entry.id}`}
                  aria-selected={tab === entry.id}
                  aria-controls={`panel-${entry.id}`}
                  className="tab"
                  onClick={() => setTab(entry.id)}
                >
                  {entry.label}
                  {entry.id === "approvals" && pendingCount > 0 ? ` (${pendingCount})` : ""}
                </button>
              ))}
            </div>

            {tab === "overview" ? (
              <div id="panel-overview" role="tabpanel" aria-labelledby="tab-overview" className="grid">
                <div className="stat-row">
                  <Stat value={totals.blocked} label="Blocked" detail="denied before the tool ran" />
                  <Stat value={totals.allowed} label="Allowed" detail="matched the approved contract" />
                  <Stat value={totals.review} label="Needs review" detail="paused for a human" />
                  <Stat value={totals.executed} label="Upstream ran" detail="confirmed by the tool server" />
                  <Stat
                    value={`${totals.p95.toFixed(1)} ms`}
                    label="p95 decision"
                    detail="policy time, excluding the upstream call"
                  />
                </div>
                <Card
                  title="Intent versus action"
                  hint="Trusted, user-approved intent on the left; untrusted content and the attempted action on the right."
                >
                  {task ? (
                    <IntentPanel task={task} latest={latestDecision} scenario={scenarioForTask} />
                  ) : (
                    <ErrorState
                      message="No task registered"
                      detail="Run `make seed` to create the demo contracts, then reload."
                      onRetry={() => window.location.reload()}
                    />
                  )}
                </Card>
              </div>
            ) : null}

            {tab === "timeline" ? (
              <div id="panel-timeline" role="tabpanel" aria-labelledby="tab-timeline">
                <Card
                  title="Live decision trace"
                  hint={
                    live.mode === "stream"
                      ? "Streaming over server-sent events. New decisions appear without a refresh."
                      : live.mode === "polling"
                        ? "The event stream is unavailable, so this panel is polling every 1.5 s instead."
                        : "Waiting for the event stream."
                  }
                  flush
                >
                  <Timeline decisions={decisions} catalog={catalog} highlightIds={highlights} />
                </Card>
              </div>
            ) : null}

            {tab === "approvals" ? (
              <div id="panel-approvals" role="tabpanel" aria-labelledby="tab-approvals" className="grid split">
                <Card
                  title="Approval inbox"
                  hint="Each grant authorizes exactly one set of canonical arguments, once, under one contract revision."
                >
                  <ApprovalInbox
                    approvals={approvals}
                    reviewer={reviewer}
                    onDecide={decide}
                    disabled={!token}
                  />
                </Card>
                <Card
                  title="Reviewer credentials"
                  hint="The admin token is kept in this browser session only and sent as a bearer header."
                >
                  <div style={{ display: "grid", gap: "0.7rem" }}>
                    <div>
                      <label htmlFor="token-input">Admin token (AD_ADMIN_TOKEN from .env)</label>
                      <input
                        id="token-input"
                        type="password"
                        value={token}
                        placeholder="paste the token generated by make setup"
                        onChange={(event: ChangeEvent<HTMLInputElement>) => applyToken(event.target.value)}
                        autoComplete="off"
                      />
                    </div>
                    <div>
                      <label htmlFor="reviewer-input">Reviewer name recorded on the decision</label>
                      <input
                        id="reviewer-input"
                        type="text"
                        value={reviewer}
                        onChange={(event: ChangeEvent<HTMLInputElement>) => setReviewer(event.target.value)}
                      />
                    </div>
                    <p className="footnote">
                      Reads are unauthenticated in this single-user development control plane;
                      every mutating request requires the token. Loopback binding and the CORS
                      allowlist are defence in depth, not authentication.
                    </p>
                  </div>
                </Card>
              </div>
            ) : null}

            {tab === "replay" ? (
              <div id="panel-replay" role="tabpanel" aria-labelledby="tab-replay">
                <Card
                  title="Replay Lab"
                  hint="Observed guarded decisions beside a clearly labelled simulated unguarded baseline."
                  actions={
                    <select
                      value={selectedRun}
                      onChange={(event: ChangeEvent<HTMLSelectElement>) => setSelectedRun(event.target.value)}
                      aria-label="Select a run to replay"
                      style={{ maxWidth: "18rem" }}
                    >
                      {runs.length === 0 ? <option value="">no runs recorded</option> : null}
                      {runs.map((run) => (
                        <option key={run.run_id} value={run.run_id}>
                          {run.run_id} — {run.decisions} decisions ({run.denied} blocked)
                        </option>
                      ))}
                    </select>
                  }
                >
                  <ReplayLab replay={replay} />
                </Card>
              </div>
            ) : null}

            {tab === "scenarios" ? (
              <div id="panel-scenarios" role="tabpanel" aria-labelledby="tab-scenarios">
                <Scenarios scenarios={scenarios} />
              </div>
            ) : null}

            <p className="footnote" style={{ marginTop: "1.5rem" }}>
              Agent Drift enforces only on tool calls that traverse its MCP gateway. Calls made
              by an agent that bypasses the gateway, and non-MCP tool use, are outside its
              coverage. See <code className="chip">docs/THREAT_MODEL.md</code>.
            </p>
          </>
        )}
      </main>
    </div>
  );
}
