#!/usr/bin/env python3
"""Run every bundled scenario through a real gateway and report observed decisions.

This is the demo driver and also the data source for the dashboard screenshots. It is
deliberately *not* the test suite: the assertions live in
``tests/integration/test_scenarios.py``, which imports the same runner so the demo and
the test cannot diverge.

Each scenario gets a fresh fixture state directory and a fresh gateway process, so the
budget and approval preconditions of one scenario cannot leak into another.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "packages"))

from mcp import Client, StdioServerParameters  # noqa: E402

from agent_drift.seed import build_contract, load_scenarios  # noqa: E402
from agent_drift.store import Store  # noqa: E402

#: Scenario id -> seed contract name.
CONTRACT_FOR_TASK = {
    "demo-repo-review": "readonly",
    "demo-docs-edit": "docswrite",
    "demo-cleanup": "delete_review",
    "demo-report-upload": "egress_allowed",
    "demo-expired": "expired",
}


@dataclass
class StepOutcome:
    """One observed step."""

    tool: str
    args: dict[str, Any]
    expected: str
    observed: str
    reason_codes: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    upstream_delta: int = 0
    sink_delta: int = 0
    matched: bool = False
    detail: str = ""
    pending_observed: bool = False


@dataclass
class ScenarioOutcome:
    """One observed scenario."""

    scenario_id: str
    name: str
    category: str
    task_id: str
    run_id: str | None
    steps: list[StepOutcome] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when every step's observed decision matched its expectation."""
        return all(step.matched for step in self.steps)


def _counters(state: Path) -> dict[str, int]:
    try:
        return {str(k): int(v) for k, v in json.loads((state / "counters.json").read_text()).items()}
    except (OSError, ValueError):
        return {}


def _sink(state: Path) -> int:
    try:
        return sum(1 for line in (state / "egress_sink.jsonl").read_text().splitlines() if line.strip())
    except OSError:
        return 0


def _decision_from(result: Any) -> tuple[str, list[str], list[str]]:
    """Extract (decision, reason_codes, rule_ids) from a CallToolResult."""
    if not getattr(result, "is_error", False):
        return "allow", [], []
    structured = getattr(result, "structured_content", None)
    payload: dict[str, Any] | None = None
    if isinstance(structured, dict) and "agent_drift" in structured:
        payload = structured["agent_drift"]
    else:
        for block in getattr(result, "content", []) or []:
            text = getattr(block, "text", "")
            if "agent_drift" in text:
                try:
                    payload = json.loads(text)["agent_drift"]
                except (ValueError, KeyError, TypeError):
                    payload = None
                break
    if payload is None:
        return "error", [], []
    return (
        str(payload.get("decision", "deny")),
        [str(c) for c in payload.get("reason_codes", [])],
        [str(r) for r in payload.get("rule_ids", [])],
    )


async def run_one(
    scenario: dict[str, Any],
    *,
    db_path: Path,
    approval_timeout_s: float = 3.0,
) -> ScenarioOutcome:
    """Run one scenario end to end against a fresh fixture and gateway.

    Each scenario gets a fresh temporary fixture state directory and an explicit,
    deterministic reset of the task's budget counters. The database is shared so the
    dashboard can show every run together, which means the reset has to be explicit --
    the blueprint requires exactly that ("isolated fresh fixture state and database, or
    an explicit deterministic reset"). Without it, writes performed by an earlier
    scenario leak into a later one's budget, which is a bug this runner found.

    Per-step ``review_action`` drives the approval story: ``"none"`` lets the bounded
    wait elapse, ``"approve"`` has a reviewer approve the pending grant, ``"decline"``
    declines it.
    """
    task_id = scenario["task_id"]
    contract_name = CONTRACT_FOR_TASK.get(task_id, "readonly")
    state = Path(tempfile.mkdtemp(prefix=f"ad-{scenario['id']}-"))

    outcome = ScenarioOutcome(
        scenario_id=scenario["id"],
        name=scenario["name"],
        category=scenario["category"],
        task_id=task_id,
        run_id=None,
    )

    store = Store(db_path)
    try:
        contract = build_contract(contract_name)
        store.put_contract(contract)
        # Explicit deterministic reset: budgets are per-scenario even though the
        # decision database is shared across scenarios for the dashboard's benefit.
        store.set_budget_used(contract.task_id, contract.policy_revision, calls=0, writes=0)

        env = {
            **os.environ,
            "AD_FIXTURE_STATE": str(state),
            "AD_LOG_LEVEL": "WARNING",
        }
        # Attack F needs the upstream to genuinely re-advertise mutated metadata.
        if scenario["id"] == "attack-f-manifest-rug-pull":
            env["AD_FIXTURE_MUTATE_MANIFEST"] = "1"
            # Pin the *unmutated* manifest first, as approval time would have seen it.
            pin_env = {**env}
            pin_env.pop("AD_FIXTURE_MUTATE_MANIFEST")
            await _pin_manifest(task_id, db_path, state, pin_env)

        params = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "agent_drift.cli",
                "gateway",
                "--task-id",
                task_id,
                "--db",
                str(db_path),
                "--sandbox-root",
                str(state / "workspace"),
                "--approval-timeout",
                str(approval_timeout_s),
                "--log-level",
                "WARNING",
            ],
            env=env,
            cwd=str(REPO_ROOT),
        )

        async with Client(params, read_timeout_seconds=60.0) as client:
            await client.list_tools()
            for step in scenario["steps"]:
                before = _counters(state)
                sink_before = _sink(state)

                review_action = step.get("review_action", "none")
                task = asyncio.create_task(client.call_tool(step["tool"], step["args"]))
                pending_seen = False
                if review_action != "none":
                    pending_seen = await _act_on_approval(store, task_id, review_action)
                result = await task

                after = _counters(state)
                decision, reasons, rules = _decision_from(result)
                tool = step["tool"]
                delta = after.get(tool, 0) - before.get(tool, 0)

                expected = step["expected_decision"]
                # A `needs_approval` expectation is observed at the wire as a denial that
                # carries AD-A005: the gateway resolves the bounded pause before it
                # replies, so the host never sees an intermediate state. The pending
                # record itself is asserted from the database in the test suite.
                matched = decision == expected or (
                    expected == "needs_approval" and decision == "deny" and "AD-A005" in reasons
                )
                expected_reason = step.get("expected_reason")
                if matched and expected_reason and decision == "deny":
                    matched = expected_reason in reasons
                outcome.steps.append(
                    StepOutcome(
                        tool=tool,
                        args=step["args"],
                        expected=expected,
                        observed=decision,
                        reason_codes=reasons,
                        rule_ids=rules,
                        upstream_delta=delta,
                        sink_delta=_sink(state) - sink_before,
                        matched=matched,
                        detail=step.get("note", ""),
                        pending_observed=pending_seen,
                    )
                )

        runs = store.list_runs(task_id=task_id)
        outcome.run_id = runs[0]["run_id"] if runs else None
    finally:
        store.close()
        shutil.rmtree(state, ignore_errors=True)

    return outcome


async def _pin_manifest(task_id: str, db_path: Path, state: Path, env: dict[str, str]) -> None:
    """Connect to the unmutated upstream once and pin its manifest for the task."""
    from agent_drift.manifest import fingerprint_tools

    params = StdioServerParameters(
        command=sys.executable,
        args=[str(REPO_ROOT / "examples" / "upstream_mcp" / "server.py")],
        env=env,
        cwd=str(REPO_ROOT),
    )
    async with Client(params, read_timeout_seconds=30.0) as client:
        listed = await client.list_tools()
    pin = fingerprint_tools("sandbox", list(listed.tools))
    store = Store(db_path)
    try:
        store.set_manifest_pin(task_id, pin.to_dict())
    finally:
        store.close()


async def _act_on_approval(store: Store, task_id: str, action: str) -> bool:
    """Approve or decline the newest pending approval for a task, once it appears.

    Returns whether a pending approval was actually observed, which is the evidence that
    the call really did pause for review rather than sailing through.
    """
    for _ in range(120):
        await asyncio.sleep(0.05)
        pending = store.list_approvals(state="pending", task_id=task_id)
        if pending:
            approval_id = pending[0]["approval_id"]
            store.decide_approval(approval_id, approve=(action == "approve"), reviewer="scenario-runner")
            return True
    return False


async def main_async(args: argparse.Namespace) -> int:
    """Run all (or one) scenario and print a report."""
    scenarios = load_scenarios()
    if args.only:
        scenarios = [s for s in scenarios if s["id"] == args.only]
        if not scenarios:
            print(f"no scenario with id {args.only!r}", file=sys.stderr)
            return 2

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if args.fresh:
        for stale in (db_path, Path(f"{db_path}-wal"), Path(f"{db_path}-shm")):
            if stale.exists():
                stale.unlink()

    outcomes: list[ScenarioOutcome] = []
    for scenario in scenarios:
        outcomes.append(await run_one(scenario, db_path=db_path, approval_timeout_s=args.approval_timeout))

    if args.json:
        print(
            json.dumps(
                [
                    {
                        "scenario_id": o.scenario_id,
                        "name": o.name,
                        "category": o.category,
                        "task_id": o.task_id,
                        "run_id": o.run_id,
                        "ok": o.ok,
                        "steps": [vars(step) for step in o.steps],
                    }
                    for o in outcomes
                ],
                indent=2,
            )
        )
    else:
        for outcome in outcomes:
            marker = "ok  " if outcome.ok else "FAIL"
            print(f"[{marker}] {outcome.scenario_id} — {outcome.name}")
            for step in outcome.steps:
                flag = " " if step.matched else "!"
                print(
                    f"      {flag} {step.tool:<20} expected={step.expected:<15} "
                    f"observed={step.observed:<15} reasons={','.join(step.reason_codes) or '-':<10} "
                    f"upstream_delta={step.upstream_delta} sink_delta={step.sink_delta}"
                )
        failed = [o for o in outcomes if not o.ok]
        print()
        print(f"{len(outcomes) - len(failed)}/{len(outcomes)} scenarios matched their expected decisions")
        if failed:
            print("failed: " + ", ".join(o.scenario_id for o in failed), file=sys.stderr)

    return 1 if any(not o.ok for o in outcomes) else 0


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=str(REPO_ROOT / "var" / "agent_drift.db"))
    parser.add_argument("--only", default=None, help="run a single scenario by id")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fresh", action="store_true", help="delete the database first")
    parser.add_argument("--approval-timeout", type=float, default=3.0)
    args = parser.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
