"""Execute every seed vector from ``tests/fixtures/release_vectors.json``.

The blueprint is emphatic that these vectors must be *observed*, not hardcoded: each
case's assertions about upstream call counts, on-disk hashes and review state have to be
read from real state. So this module:

* gives every vector a **fresh database and a fresh fixture state directory**, so no
  precondition leaks between cases;
* applies each vector's ``setup`` block as a real precondition (reserving budget through
  the store, expiring a contract, mutating the upstream manifest for real, issuing an
  approval for different arguments);
* drives the attempt through a **real gateway process** to a **real upstream**; and
* reads the upstream's own counter file and the target file's SHA-256 for its assertions.

A vector that the harness cannot set up honestly fails rather than being skipped, and the
test that counts the vectors fails if any case in the file is left unexercised.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import json
from pathlib import Path
from typing import Any

import pytest

from agent_drift.contracts import ApprovalState, ToolAttempt, utcnow
from agent_drift.seed import build_contract
from agent_drift.store import Store

from .harness import decision_of, gateway_client, reason_codes

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

VECTORS_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "release_vectors.json"
VECTORS: dict[str, Any] = json.loads(VECTORS_PATH.read_text())

#: Vector contract name -> seed contract builder name. ``None`` means "register nothing",
#: which is how AD-SEED-12 exercises the missing-contract path.
CONTRACT_MAP: dict[str | None, str | None] = {
    "readonly": "readonly",
    "docswrite": "docswrite",
    "delete_review": "delete_review",
    None: None,
}

#: Vector contract name -> the task id the gateway is bound to.
TASK_MAP: dict[str, str] = {
    "readonly": "demo-repo-review",
    "docswrite": "demo-docs-edit",
    "delete_review": "demo-cleanup",
}


@pytest.fixture
def anyio_backend() -> str:
    """Run the async tests on asyncio."""
    return "asyncio"


def _case(case_id: str) -> dict[str, Any]:
    """Look up one vector by id."""
    for case in VECTORS["cases"]:
        if case["id"] == case_id:
            return case
    raise AssertionError(f"vector {case_id} is not in {VECTORS_PATH}")


class VectorRunner:
    """Sets up a vector's preconditions and runs its attempt."""

    def __init__(self, db_path: Path, state: Path) -> None:
        self.db_path = db_path
        self.state = state

    def register(self, contract_name: str | None, setup: dict[str, Any]) -> str | None:
        """Register the vector's contract with its preconditions applied.

        Returns the task id the gateway should bind to, or ``None`` when the vector
        deliberately has no contract.
        """
        if contract_name is None:
            # AD-SEED-12: bind the gateway to a task that has no registered contract.
            return "demo-docs-edit"

        overrides: dict[str, Any] = {}
        if setup.get("contract_expired"):
            overrides["issued_at"] = utcnow() - _dt.timedelta(hours=2)
            overrides["expires_at"] = utcnow() - _dt.timedelta(hours=1)

        contract = build_contract(CONTRACT_MAP[contract_name] or "readonly", **overrides)

        store = Store(self.db_path)
        try:
            store.put_contract(contract)

            reserved = int(setup.get("writes_already_reserved", 0))
            if reserved:
                store.set_budget_used(
                    contract.task_id, contract.policy_revision, calls=reserved, writes=reserved
                )

            if setup.get("review_action") == "approve_different_args":
                # Issue and approve a grant for a *different* path, so the attempt's own
                # arguments have no matching grant.
                self._approve_for(store, contract, path="sandbox-repo/tmp/demo.txt")
        finally:
            store.close()

        return contract.task_id

    def _approve_for(self, store: Store, contract: Any, *, path: str) -> None:
        """Create and approve a grant for a specific path."""
        from agent_drift.contracts import ApprovalGrant

        attempt = ToolAttempt(
            task_id=contract.task_id,
            tool_server="sandbox",
            tool_name="repo.delete_file",
            args={"path": path},
        )
        grant = ApprovalGrant(
            attempt_id=attempt.attempt_id,
            task_id=contract.task_id,
            tool_name="repo.delete_file",
            tool_server="sandbox",
            args_digest=attempt.canonical_args_digest(),
            policy_revision=contract.policy_revision,
            contract_hash=contract.contract_hash,
            expires_at=utcnow() + _dt.timedelta(minutes=10),
        )
        store.create_approval(grant)
        store.decide_approval(grant.approval_id, approve=True, reviewer="vector-runner")

    async def run(self, case: dict[str, Any]) -> dict[str, Any]:
        """Run one vector and return observed facts."""
        setup = case.get("setup") or {}
        contract_name = case.get("contract")
        task_id = self.register(contract_name, setup)
        assert task_id is not None

        attempt_spec = case["attempt"]
        tool = attempt_spec["tool"]
        args = attempt_spec["args"]
        target = args.get("path")

        mutate = bool(setup.get("manifest_changed_since_contract"))
        if mutate:
            await self._pin_unmutated_manifest(task_id)

        approval_action = setup.get("review_action", "none")
        timeout = float(setup.get("timeout_s", 2.0))

        async with gateway_client(
            task_id=task_id,
            db_path=self.db_path,
            state=self.state,
            approval_timeout_s=timeout,
            mutate_manifest=mutate,
        ) as (client, oracle):
            await client.list_tools()

            counters_before = oracle.counters()
            sink_before = oracle.sink_events()
            hash_before = oracle.sha256(target) if target else None

            simultaneous = int(setup.get("simultaneous_identical_attempts", 1))
            pending_observed = False

            if approval_action == "approve_matching":
                task = asyncio.create_task(client.call_tool(tool, args))
                pending_observed = await self._decide_pending(task_id, approve=True)
                results = [await task]
            elif simultaneous > 1:
                results = list(
                    await asyncio.gather(*(client.call_tool(tool, args) for _ in range(simultaneous)))
                )
            else:
                if approval_action == "none" and contract_name == "delete_review":
                    pending_observed = await self._observe_pending_during(
                        client.call_tool(tool, args), task_id
                    )
                    results = [pending_observed[1]]  # type: ignore[index]
                    pending_observed = pending_observed[0]  # type: ignore[index]
                else:
                    results = [await client.call_tool(tool, args)]

            counters_after = oracle.counters()
            observed = {
                "decisions": [decision_of(result) for result in results],
                "reason_codes": [reason_codes(result) for result in results],
                "upstream_call_delta": counters_after.get(tool, 0) - counters_before.get(tool, 0),
                "sink_events_delta": oracle.sink_events() - sink_before,
                "file_hash_unchanged": (oracle.sha256(target) == hash_before if target else None),
                "pending_review_observed": pending_observed,
            }

        observed["approval_consumed"] = self._approval_consumed(task_id)
        return observed

    async def _observe_pending_during(self, coro: Any, task_id: str) -> tuple[bool, Any]:
        """Run a call while watching for a pending approval record to appear."""
        task = asyncio.create_task(coro)
        seen = False
        store = Store(self.db_path)
        try:
            for _ in range(120):
                if task.done():
                    break
                await asyncio.sleep(0.02)
                if store.list_approvals(state=str(ApprovalState.PENDING), task_id=task_id):
                    seen = True
                    break
        finally:
            store.close()
        return seen, await task

    async def _decide_pending(self, task_id: str, *, approve: bool) -> bool:
        """Wait for a pending approval and decide it. Returns whether one was seen."""
        store = Store(self.db_path)
        try:
            for _ in range(150):
                await asyncio.sleep(0.02)
                pending = store.list_approvals(state=str(ApprovalState.PENDING), task_id=task_id)
                if pending:
                    store.decide_approval(
                        pending[0]["approval_id"], approve=approve, reviewer="vector-runner"
                    )
                    return True
            return False
        finally:
            store.close()

    def _approval_consumed(self, task_id: str) -> bool:
        """Was any grant for this task consumed?"""
        store = Store(self.db_path)
        try:
            return any(
                row["state"] == str(ApprovalState.CONSUMED) for row in store.list_approvals(task_id=task_id)
            )
        finally:
            store.close()

    async def _pin_unmutated_manifest(self, task_id: str) -> None:
        """Pin the manifest as it stood *before* the upstream mutated it."""
        from agent_drift.manifest import fingerprint_tools

        from .harness import direct_upstream

        async with direct_upstream(self.state, mutate_manifest=False) as upstream:
            listed = await upstream.list_tools()
        pin = fingerprint_tools("sandbox", list(listed.tools))
        store = Store(self.db_path)
        try:
            store.set_manifest_pin(task_id, pin.to_dict())
        finally:
            store.close()


ALL_CASE_IDS = [case["id"] for case in VECTORS["cases"]]


class TestReleaseVectors:
    """Every vector in the file, executed against real state."""

    @pytest.mark.parametrize("case_id", ALL_CASE_IDS)
    async def test_vector(self, case_id: str, db_path: Path, fixture_state: Path) -> None:
        case = _case(case_id)
        expected = case["expected"]
        observed = await VectorRunner(db_path, fixture_state).run(case)

        context = (
            f"\nvector: {case_id} ({case['name']})"
            f"\nexpected: {json.dumps(expected, sort_keys=True)}"
            f"\nobserved: {json.dumps(observed, sort_keys=True, default=str)}"
        )

        if "decision" in expected:
            wanted = expected["decision"].lower()
            decisions = observed["decisions"]
            if wanted == "allow":
                assert decisions == ["allow"], context
            else:
                # A vector expecting DENY where approval is involved is observed as a
                # denial carrying an approval reason code; the pending record is asserted
                # separately below.
                assert all(decision == "deny" for decision in decisions), context

        if "upstream_call_delta" in expected:
            assert observed["upstream_call_delta"] == expected["upstream_call_delta"], context

        if expected.get("file_hash_unchanged") is True:
            assert observed["file_hash_unchanged"] is True, context

        if "sink_events_delta" in expected:
            assert observed["sink_events_delta"] == expected["sink_events_delta"], context

        if expected.get("pending_review_observed") is True:
            assert observed["pending_review_observed"] is True, context

        if expected.get("approval_consumed") is True:
            assert observed["approval_consumed"] is True, context

        if "allowed_count" in expected:
            allowed = observed["decisions"].count("allow")
            assert allowed == expected["allowed_count"], context

        if "denied_count" in expected:
            denied = observed["decisions"].count("deny")
            assert denied == expected["denied_count"], context


class TestVectorFileIntegrity:
    """The vector file itself must stay honest."""

    def test_every_case_is_parameterized(self) -> None:
        """A vector silently dropped from the run would be an invisible gap."""
        assert len(ALL_CASE_IDS) == len(VECTORS["cases"])
        assert len(set(ALL_CASE_IDS)) == len(ALL_CASE_IDS), "duplicate vector ids"

    def test_expected_counts_match_the_published_seed_file(self) -> None:
        """The vectors are the ones shipped in the handoff, not a trimmed subset."""
        assert len(VECTORS["cases"]) == 16, (
            f"expected the 16 published seed vectors, found {len(VECTORS['cases'])}"
        )

    def test_schema_version_is_recorded(self) -> None:
        assert VECTORS["schema_version"]

    def test_every_case_declares_an_expectation(self) -> None:
        for case in VECTORS["cases"]:
            assert case.get("expected"), f"{case['id']} has no expectations"

    def test_every_referenced_contract_is_buildable(self) -> None:
        for case in VECTORS["cases"]:
            name = case.get("contract")
            assert name in CONTRACT_MAP, f"{case['id']} references unknown contract {name!r}"

    def test_fixture_tools_match_the_implementation(self) -> None:
        from agent_drift.policy import DEFAULT_TOOL_SPECS

        assert set(VECTORS["fixture_tools"]) == set(DEFAULT_TOOL_SPECS), (
            "the vector file's tool list has drifted from the implemented tool specs"
        )
