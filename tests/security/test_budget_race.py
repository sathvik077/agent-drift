"""Concurrency: budget reservation and decision recording under real threads (AD-21).

These tests actually race threads rather than reasoning about the SQL. The property is
that a budget of N admits exactly N allows no matter how many callers arrive at once --
which is what ``BEGIN IMMEDIATE`` around the read-compare-increment buys.
"""

from __future__ import annotations

import threading

import pytest

from agent_drift.contracts import ContractSource, DecisionStatus, IntentContract, Operation, ToolAttempt


@pytest.fixture
def docs_contract(store):
    """A docs-write contract whose budget the tests vary."""

    def make(max_writes: int, max_calls: int = 100) -> IntentContract:
        contract = IntentContract(
            principal="dev",
            task_id="t",
            user_goal="edit docs",
            approved_by="dev",
            source=ContractSource.TRUSTED_CONFIG,
            allowed_tools=["repo.write_file", "repo.read_file"],
            allowed_operations=[Operation.WRITE, Operation.READ],
            resource_scopes=["sandbox-repo/docs/**"],
            max_writes=max_writes,
            max_calls=max_calls,
        )
        store.put_contract(contract)
        return contract

    return make


def race(worker, count: int) -> list:
    """Run ``worker`` in ``count`` threads released simultaneously."""
    results: list = []
    lock = threading.Lock()
    barrier = threading.Barrier(count)

    def run(index: int) -> None:
        barrier.wait()
        outcome = worker(index)
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=run, args=(index,)) for index in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert len(results) == count, "a worker thread did not finish"
    return results


class TestBudgetReservationRace:
    """Reservation is atomic."""

    @pytest.mark.parametrize("budget", [1, 2, 3])
    def test_exactly_budget_many_reservations_succeed(self, store, docs_contract, budget: int) -> None:
        contract = docs_contract(budget)
        attempts = 12

        def worker(_index: int) -> bool:
            reserved, _reason, _usage = store.reserve_budget(
                "t",
                contract.policy_revision,
                max_calls=1000,
                max_writes=budget,
                is_write=True,
            )
            return reserved

        results = race(worker, attempts)
        assert sum(results) == budget, f"budget {budget} admitted {sum(results)} reservations"
        assert store.get_budget("t", contract.policy_revision)["writes_used"] == budget

    def test_engine_level_race_admits_one(self, store, engine, docs_contract) -> None:
        """AD-SEED-16: two simultaneous identical writes with one write remaining."""
        contract = docs_contract(2)
        store.set_budget_used("t", contract.policy_revision, calls=0, writes=1)

        def worker(index: int) -> str:
            attempt = ToolAttempt(
                tool_server="sandbox",
                tool_name="repo.write_file",
                args={"path": "sandbox-repo/docs/README.md", "content": "race"},
            )
            return str(engine.evaluate(attempt, bound_task_id="t").status)

        results = race(worker, 2)
        allowed = results.count(str(DecisionStatus.ALLOW))
        denied = results.count(str(DecisionStatus.DENY))
        assert allowed == 1, f"expected exactly one allow, got {allowed}: {results}"
        assert denied == 1, f"expected exactly one deny, got {denied}: {results}"

    def test_call_budget_race(self, store, docs_contract) -> None:
        contract = docs_contract(100, max_calls=4)

        def worker(_index: int) -> bool:
            reserved, _r, _u = store.reserve_budget(
                "t", contract.policy_revision, max_calls=4, max_writes=100, is_write=False
            )
            return reserved

        assert sum(race(worker, 16)) == 4

    def test_zero_budget_admits_nothing(self, store, docs_contract) -> None:
        contract = docs_contract(0)

        def worker(_index: int) -> bool:
            reserved, _r, _u = store.reserve_budget(
                "t", contract.policy_revision, max_calls=100, max_writes=0, is_write=True
            )
            return reserved

        assert sum(race(worker, 8)) == 0


class TestConcurrentWrites:
    """The store stays consistent under concurrent recording."""

    def test_concurrent_attempt_recording_is_consistent(self, store, docs_contract) -> None:
        docs_contract(100)
        attempts = [
            ToolAttempt(
                tool_server="sandbox",
                tool_name="repo.read_file",
                args={"path": f"sandbox-repo/docs/{index}.md"},
                task_id="t",
            )
            for index in range(16)
        ]

        def worker(index: int) -> bool:
            store.record_attempt(attempts[index])
            return True

        race(worker, 16)
        rows = store.conn.execute("SELECT COUNT(*) AS n FROM attempts").fetchone()
        assert rows["n"] == 16

    def test_event_sequence_numbers_are_unique_and_monotonic(self, store, docs_contract) -> None:
        docs_contract(100)

        def worker(index: int) -> int:
            return store.append_event("TEST_EVENT", payload={"index": index})

        sequences = race(worker, 24)
        assert len(set(sequences)) == 24, "duplicate event sequence numbers"
        events = store.events_since(0, limit=1000)
        observed = [event["seq"] for event in events if event["kind"] == "TEST_EVENT"]
        assert observed == sorted(observed), "events are not in monotonic order"
