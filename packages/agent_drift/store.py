"""Durable decision and event store (SQLite, WAL, single serialized writer).

Everything security-relevant about this module is about *ordering* and *atomicity*:

* A decision row is committed **before** the gateway forwards anything upstream. If the
  process dies between the commit and the forward, the record says ``allow`` with
  ``upstream_executed = 0`` -- an honest "we authorized it and do not know if it ran" --
  rather than losing the authorization entirely.
* Budget reservation and approval consumption happen inside ``BEGIN IMMEDIATE``
  transactions through a single writer connection guarded by a process lock. Two
  concurrent identical attempts against a budget of one therefore produce exactly one
  allow, which ``tests/security/test_budget_race.py`` asserts by actually racing threads.
* Every event carries a monotonic ``seq`` from an ``AUTOINCREMENT`` column, so the
  dashboard can page and replay in a stable order even when timestamps collide.
* An optional HMAC chain links each event to its predecessor. This is **tamper-evidence
  under a separately held key**, not a guarantee: whoever can write the database can
  usually also read the key, which is stated in the README rather than implied away.
* Store failure is never a pass. Callers receive an exception and the policy engine maps
  it to ``deny / AD-E998``.
"""

from __future__ import annotations

import datetime as _dt
import hmac
import json
import os
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Final

from .canonical import canonical_text, keyed_digest, redact
from .contracts import (
    SCHEMA_VERSION,
    ApprovalGrant,
    ApprovalState,
    DecisionStatus,
    IntentContract,
    PolicyDecision,
    ToolAttempt,
    utcnow,
)

__all__ = ["DEFAULT_DB_PATH", "Store", "StoreUnavailable"]

DEFAULT_DB_PATH: Final[str] = "var/agent_drift.db"

#: How the ``decisions.upstream_executed`` column is interpreted. ``unknown`` exists
#: because a timed-out or cancelled call may or may not have run, and a receipt must not
#: claim otherwise.
UPSTREAM_EXECUTION_STATES: Final[dict[int, str]] = {0: "no", 1: "yes", 2: "unknown"}

_SCHEMA: Final[str] = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contracts (
    id               TEXT PRIMARY KEY,
    task_id          TEXT NOT NULL,
    policy_revision  INTEGER NOT NULL,
    contract_hash    TEXT NOT NULL,
    active           INTEGER NOT NULL DEFAULT 1,
    payload          TEXT NOT NULL,
    manifest_pin     TEXT,
    created_at       TEXT NOT NULL,
    -- HMAC over the contract's semantic fields under the separately held signing key.
    -- The plain contract_hash is an unkeyed SHA-256 whose algorithm ships in this
    -- repository, so anyone who can write this table can recompute it; an independent
    -- review used exactly that to install a fully permissive contract without the admin
    -- token. This column raises the bar to "can also read the signing key".
    contract_mac     TEXT,
    UNIQUE (task_id, policy_revision)
);
CREATE INDEX IF NOT EXISTS idx_contracts_task ON contracts (task_id, active, policy_revision DESC);

CREATE TABLE IF NOT EXISTS budgets (
    task_id          TEXT NOT NULL,
    policy_revision  INTEGER NOT NULL,
    calls_used       INTEGER NOT NULL DEFAULT 0,
    writes_used      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (task_id, policy_revision)
);

CREATE TABLE IF NOT EXISTS attempts (
    attempt_id   TEXT PRIMARY KEY,
    task_id      TEXT,
    run_id       TEXT NOT NULL,
    trace_id     TEXT NOT NULL,
    request_id   TEXT NOT NULL,
    tool_server  TEXT NOT NULL,
    tool_name    TEXT NOT NULL,
    operation    TEXT NOT NULL,
    args_digest  TEXT NOT NULL,
    payload      TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_run ON attempts (run_id);
CREATE INDEX IF NOT EXISTS idx_attempts_task ON attempts (task_id);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id       TEXT PRIMARY KEY,
    attempt_id        TEXT NOT NULL,
    task_id           TEXT,
    run_id            TEXT NOT NULL,
    status            TEXT NOT NULL,
    reason_codes      TEXT NOT NULL,
    rule_ids          TEXT NOT NULL,
    risk              TEXT NOT NULL,
    contract_hash     TEXT,
    policy_revision   INTEGER,
    elapsed_ms        REAL NOT NULL DEFAULT 0,
    upstream_executed INTEGER NOT NULL DEFAULT 0,
    upstream_error    TEXT,
    approval_id       TEXT,
    payload           TEXT NOT NULL,
    created_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_run ON decisions (run_id);
CREATE INDEX IF NOT EXISTS idx_decisions_task ON decisions (task_id, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_decisions_attempt ON decisions (attempt_id);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id      TEXT PRIMARY KEY,
    attempt_id       TEXT NOT NULL,
    task_id          TEXT NOT NULL,
    tool_name        TEXT NOT NULL,
    tool_server      TEXT NOT NULL,
    args_digest      TEXT NOT NULL,
    policy_revision  INTEGER NOT NULL,
    contract_hash    TEXT NOT NULL,
    nonce            TEXT NOT NULL,
    state            TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    decided_at       TEXT,
    decided_by       TEXT,
    consumed_at      TEXT,
    payload          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_state ON approvals (state, task_id);
CREATE INDEX IF NOT EXISTS idx_approvals_lookup
    ON approvals (task_id, tool_name, args_digest, policy_revision, state);

CREATE TABLE IF NOT EXISTS events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,
    task_id     TEXT,
    run_id      TEXT,
    attempt_id  TEXT,
    payload     TEXT NOT NULL,
    prev_hmac   TEXT,
    hmac        TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_task ON events (task_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_run ON events (run_id, seq);

CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT PRIMARY KEY,
    task_id     TEXT,
    scenario    TEXT,
    label       TEXT,
    started_at  TEXT NOT NULL,
    ended_at    TEXT
);
"""


class ContractIntegrityError(RuntimeError):
    """A stored contract failed an integrity check.

    Raised rather than returned so it cannot be mistaken for "no contract". The policy
    engine converts it to a denial; there is no path where it becomes an allow.
    """


class StoreUnavailable(RuntimeError):
    """Raised when the decision store cannot be used.

    The policy engine converts this to ``deny / AD-E998``. It is never swallowed, because
    "the database is down" must not become "the call is allowed".
    """


class Store:
    """SQLite-backed store for contracts, attempts, decisions, approvals and events."""

    def __init__(self, path: str | Path = DEFAULT_DB_PATH, *, hmac_key: bytes | None = None) -> None:
        self.path = Path(path)
        self._hmac_key = hmac_key
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        try:
            if str(self.path) != ":memory:":
                self.path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = self._connect()
            self._migrate()
        except sqlite3.Error as exc:  # pragma: no cover - environment failure
            raise StoreUnavailable(f"could not open decision store at {self.path}: {exc}") from exc

    # ------------------------------------------------------------------ plumbing

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.path),
            timeout=15.0,
            isolation_level=None,  # explicit transaction control
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        """The single writer connection."""
        if self._conn is None:
            raise StoreUnavailable("decision store is closed")
        return self._conn

    def _migrate(self) -> None:
        with self._lock:
            self.conn.executescript(_SCHEMA)
            self.conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (SCHEMA_VERSION,),
            )

    @contextmanager
    def immediate(self) -> Iterator[sqlite3.Connection]:
        """A ``BEGIN IMMEDIATE`` transaction on the serialized writer.

        ``IMMEDIATE`` takes the write lock up front, which is what makes
        read-check-then-write sequences (budget reservation, approval consumption)
        actually atomic instead of merely usually-atomic.
        """
        with self._lock:
            conn = self.conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    def close(self) -> None:
        """Close the writer connection."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    # ----------------------------------------------------------------- contracts

    def put_contract(self, contract: IntentContract, *, manifest_pin: dict[str, Any] | None = None) -> None:
        """Store a contract and deactivate earlier revisions for the same task.

        Deactivating prior revisions is what makes an approval grant issued against an
        old revision useless: the grant carries ``policy_revision``, and the live lookup
        returns only the active one.
        """
        payload = contract.model_dump(mode="json")
        with self.immediate() as conn:
            conn.execute("UPDATE contracts SET active = 0 WHERE task_id = ?", (contract.task_id,))
            conn.execute(
                "INSERT INTO contracts (id, task_id, policy_revision, contract_hash, active, payload, "
                "manifest_pin, created_at, contract_mac) VALUES (?,?,?,?,1,?,?,?,?) "
                "ON CONFLICT(task_id, policy_revision) DO UPDATE SET "
                "contract_hash=excluded.contract_hash, active=1, payload=excluded.payload, "
                "manifest_pin=excluded.manifest_pin, contract_mac=excluded.contract_mac",
                (
                    contract.id,
                    contract.task_id,
                    contract.policy_revision,
                    contract.contract_hash,
                    json.dumps(payload),
                    json.dumps(manifest_pin) if manifest_pin is not None else None,
                    utcnow().isoformat(),
                    self.contract_mac(contract),
                ),
            )
            conn.execute(
                "INSERT INTO budgets (task_id, policy_revision, calls_used, writes_used) VALUES (?,?,0,0) "
                "ON CONFLICT(task_id, policy_revision) DO NOTHING",
                (contract.task_id, contract.policy_revision),
            )
        self.append_event(
            "CONTRACT_REGISTERED",
            task_id=contract.task_id,
            payload={
                "contract_id": contract.id,
                "policy_revision": contract.policy_revision,
                "contract_hash": contract.contract_hash,
                "user_goal": contract.user_goal,
                "source": str(contract.source),
                "semantic": contract.semantic_fields(),
            },
        )

    def contract_mac(self, contract: IntentContract) -> str | None:
        """Keyed MAC over a contract's semantic fields, when a signing key is configured."""
        if self._hmac_key is None:
            return None
        return keyed_digest(contract.semantic_fields(), self._hmac_key)

    def get_contract(self, task_id: str) -> IntentContract | None:
        """Return the active contract for a task, or ``None`` when there is none.

        When a signing key is configured, the stored MAC is verified before the contract
        is returned. A contract written directly into the database by something that did
        not hold the key fails here, which is the control that an unkeyed
        ``contract_hash`` alone cannot provide.
        """
        try:
            row = self.conn.execute(
                "SELECT payload, contract_mac FROM contracts WHERE task_id = ? AND active = 1 "
                "ORDER BY policy_revision DESC LIMIT 1",
                (task_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise StoreUnavailable(str(exc)) from exc
        if row is None:
            return None

        raw = json.loads(row["payload"])
        # A contract whose declared source is not a trusted one is refused before pydantic
        # can coerce it, so a tampered row cannot reach the policy engine at all.
        if raw.get("source") not in ("trusted_ui", "trusted_config"):
            raise ContractIntegrityError(
                f"contract for {task_id!r} declares untrusted source {raw.get('source')!r}"
            )

        try:
            contract = IntentContract.model_validate(raw)
        except Exception as exc:  # pydantic validation, including the hash consistency check
            raise ContractIntegrityError(f"stored contract for {task_id!r} failed validation: {exc}") from exc

        if self._hmac_key is not None:
            expected = self.contract_mac(contract)
            stored = row["contract_mac"]
            if stored is None:
                raise ContractIntegrityError(
                    f"contract for {task_id!r} carries no signature, but this store is "
                    "configured with a signing key. It was written by something that did "
                    "not hold the key; re-register it through the control plane."
                )
            if not hmac.compare_digest(str(stored), str(expected)):
                raise ContractIntegrityError(
                    f"contract for {task_id!r} fails signature verification; its stored "
                    "permissions do not match what was signed"
                )
        return contract

    def get_manifest_pin(self, task_id: str) -> dict[str, Any] | None:
        """Return the manifest fingerprint pinned with the task's active contract."""
        row = self.conn.execute(
            "SELECT manifest_pin FROM contracts WHERE task_id = ? AND active = 1 "
            "ORDER BY policy_revision DESC LIMIT 1",
            (task_id,),
        ).fetchone()
        if row is None or row["manifest_pin"] is None:
            return None
        parsed: dict[str, Any] = json.loads(row["manifest_pin"])
        return parsed

    def set_manifest_pin(self, task_id: str, pin: dict[str, Any]) -> None:
        """Pin (or re-pin, after review) the manifest for a task's active contract."""
        with self.immediate() as conn:
            conn.execute(
                "UPDATE contracts SET manifest_pin = ? WHERE task_id = ? AND active = 1",
                (json.dumps(pin), task_id),
            )

    def list_tasks(self) -> list[dict[str, Any]]:
        """Summarize every task with a contract, for the dashboard task selector."""
        rows = self.conn.execute(
            "SELECT task_id, policy_revision, contract_hash, payload, created_at "
            "FROM contracts WHERE active = 1 ORDER BY created_at DESC"
        ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            contract = IntentContract.model_validate(json.loads(row["payload"]))
            budget = self.get_budget(contract.task_id, contract.policy_revision)
            counts = self.conn.execute(
                "SELECT status, COUNT(*) AS n FROM decisions WHERE task_id = ? GROUP BY status",
                (contract.task_id,),
            ).fetchall()
            out.append(
                {
                    "task_id": contract.task_id,
                    "user_goal": contract.user_goal,
                    "policy_revision": contract.policy_revision,
                    "contract_hash": contract.contract_hash,
                    "source": str(contract.source),
                    "principal": contract.principal,
                    "approved_by": contract.approved_by,
                    "expires_at": contract.expires_at.isoformat() if contract.expires_at else None,
                    "expired": contract.is_expired(),
                    "allowed_tools": contract.allowed_tools,
                    "denied_actions": [str(op) for op in contract.denied_actions],
                    "resource_scopes": contract.resource_scopes,
                    "allowed_destinations": contract.allowed_destinations,
                    "max_writes": contract.max_writes,
                    "max_calls": contract.max_calls,
                    "approval_rules": contract.approval_rules,
                    "budget": budget,
                    "decision_counts": {r["status"]: r["n"] for r in counts},
                    "created_at": row["created_at"],
                }
            )
        return out

    # ------------------------------------------------------------------- budgets

    def get_budget(self, task_id: str, policy_revision: int) -> dict[str, int]:
        """Current budget consumption for a task revision."""
        row = self.conn.execute(
            "SELECT calls_used, writes_used FROM budgets WHERE task_id = ? AND policy_revision = ?",
            (task_id, policy_revision),
        ).fetchone()
        if row is None:
            return {"calls_used": 0, "writes_used": 0}
        return {"calls_used": row["calls_used"], "writes_used": row["writes_used"]}

    def reserve_budget(
        self,
        task_id: str,
        policy_revision: int,
        *,
        max_calls: int,
        max_writes: int,
        is_write: bool,
    ) -> tuple[bool, str | None, dict[str, int]]:
        """Atomically reserve one call (and one write, when ``is_write``).

        Returns ``(reserved, reason_code, usage_after)``. The whole read-compare-increment
        happens inside one ``BEGIN IMMEDIATE`` transaction, which is why two threads
        racing for the last write produce exactly one success.
        """
        from .reasons import Reason

        try:
            with self.immediate() as conn:
                conn.execute(
                    "INSERT INTO budgets (task_id, policy_revision, calls_used, writes_used) "
                    "VALUES (?,?,0,0) ON CONFLICT(task_id, policy_revision) DO NOTHING",
                    (task_id, policy_revision),
                )
                row = conn.execute(
                    "SELECT calls_used, writes_used FROM budgets WHERE task_id = ? AND policy_revision = ?",
                    (task_id, policy_revision),
                ).fetchone()
                calls_used = int(row["calls_used"])
                writes_used = int(row["writes_used"])

                if calls_used + 1 > max_calls:
                    return (
                        False,
                        str(Reason.CALL_BUDGET_EXCEEDED),
                        {
                            "calls_used": calls_used,
                            "writes_used": writes_used,
                            "max_calls": max_calls,
                            "max_writes": max_writes,
                        },
                    )
                if is_write and writes_used + 1 > max_writes:
                    return (
                        False,
                        str(Reason.WRITE_BUDGET_EXCEEDED),
                        {
                            "calls_used": calls_used,
                            "writes_used": writes_used,
                            "max_calls": max_calls,
                            "max_writes": max_writes,
                        },
                    )

                conn.execute(
                    "UPDATE budgets SET calls_used = calls_used + 1, "
                    "writes_used = writes_used + ? WHERE task_id = ? AND policy_revision = ?",
                    (1 if is_write else 0, task_id, policy_revision),
                )
                return (
                    True,
                    None,
                    {
                        "calls_used": calls_used + 1,
                        "writes_used": writes_used + (1 if is_write else 0),
                        "max_calls": max_calls,
                        "max_writes": max_writes,
                    },
                )
        except sqlite3.Error as exc:
            raise StoreUnavailable(f"budget reservation failed: {exc}") from exc

    def release_budget(self, task_id: str, policy_revision: int, *, is_write: bool) -> None:
        """Return a reservation only when the tool provably never received the call.

        "Provably" is doing real work here. An independent review found that this was
        being called on a **timeout**, which is precisely the case where the request was
        delivered and the tool may be running: a slow upstream could therefore exceed its
        write budget indefinitely, each timed-out write refunding itself. A timeout is
        *unknown*, not *did not happen*, and unknown must not refund.

        Callers must only use this for failures that happened before delivery -- the
        upstream process was already gone, or the transport was never established. See
        ``gateway._forward_once``, which classifies the failure before deciding.
        """
        with self.immediate() as conn:
            conn.execute(
                "UPDATE budgets SET calls_used = MAX(calls_used - 1, 0), "
                "writes_used = MAX(writes_used - ?, 0) WHERE task_id = ? AND policy_revision = ?",
                (1 if is_write else 0, task_id, policy_revision),
            )

    def set_budget_used(self, task_id: str, policy_revision: int, *, calls: int, writes: int) -> None:
        """Set consumption directly. Test and fixture-setup helper only."""
        with self.immediate() as conn:
            conn.execute(
                "INSERT INTO budgets (task_id, policy_revision, calls_used, writes_used) VALUES (?,?,?,?) "
                "ON CONFLICT(task_id, policy_revision) DO UPDATE SET "
                "calls_used=excluded.calls_used, writes_used=excluded.writes_used",
                (task_id, policy_revision, calls, writes),
            )

    # ---------------------------------------------------- attempts and decisions

    def record_attempt(self, attempt: ToolAttempt) -> None:
        """Persist an attempt. Arguments are redacted before they are written."""
        try:
            with self.immediate() as conn:
                conn.execute(
                    "INSERT INTO runs (run_id, task_id, started_at) VALUES (?,?,?) "
                    "ON CONFLICT(run_id) DO NOTHING",
                    (attempt.run_id, attempt.task_id, utcnow().isoformat()),
                )
                conn.execute(
                    "INSERT INTO attempts (attempt_id, task_id, run_id, trace_id, request_id, tool_server, "
                    "tool_name, operation, args_digest, payload, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(attempt_id) DO NOTHING",
                    (
                        attempt.attempt_id,
                        attempt.task_id,
                        attempt.run_id,
                        attempt.trace_id,
                        attempt.request_id,
                        attempt.tool_server,
                        attempt.tool_name,
                        str(attempt.operation),
                        attempt.canonical_args_digest(),
                        json.dumps(attempt.redacted()),
                        attempt.timestamp.isoformat(),
                    ),
                )
        except sqlite3.Error as exc:
            raise StoreUnavailable(f"could not record attempt: {exc}") from exc
        self.append_event(
            "ATTEMPT",
            task_id=attempt.task_id,
            run_id=attempt.run_id,
            attempt_id=attempt.attempt_id,
            payload=attempt.redacted(),
        )

    def record_decision(self, decision: PolicyDecision, *, run_id: str) -> None:
        """Persist a decision **before** any upstream side effect can occur."""
        payload = decision.model_dump(mode="json")
        payload["evidence"] = redact(payload.get("evidence", {}))
        try:
            with self.immediate() as conn:
                conn.execute(
                    "INSERT INTO decisions (decision_id, attempt_id, task_id, run_id, status, reason_codes, "
                    "rule_ids, risk, contract_hash, policy_revision, elapsed_ms, upstream_executed, "
                    "upstream_error, approval_id, payload, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(attempt_id) DO UPDATE SET status=excluded.status, "
                    "reason_codes=excluded.reason_codes, rule_ids=excluded.rule_ids, "
                    "upstream_executed=excluded.upstream_executed, upstream_error=excluded.upstream_error, "
                    "approval_id=excluded.approval_id, payload=excluded.payload, elapsed_ms=excluded.elapsed_ms",
                    (
                        decision.decision_id,
                        decision.attempt_id,
                        decision.task_id,
                        run_id,
                        str(decision.status),
                        json.dumps(decision.reason_codes),
                        json.dumps(decision.rule_ids),
                        str(decision.risk),
                        decision.contract_hash,
                        decision.policy_revision,
                        decision.elapsed_ms,
                        1 if decision.upstream_executed else 0,
                        decision.upstream_error,
                        decision.approval_id,
                        json.dumps(payload),
                        decision.timestamp.isoformat(),
                    ),
                )
        except sqlite3.Error as exc:
            raise StoreUnavailable(f"could not record decision: {exc}") from exc
        self.append_event(
            f"DECISION_{str(decision.status).upper()}",
            task_id=decision.task_id,
            run_id=run_id,
            attempt_id=decision.attempt_id,
            payload=payload,
        )

    def mark_upstream_executed(
        self, attempt_id: str, *, executed: bool | None, error: str | None = None
    ) -> None:
        """Record whether the upstream tool ran: yes, no, or **unknown**.

        ``executed=None`` means the gateway cannot tell -- a timeout or a cancellation,
        where the request was delivered and the tool may have completed. Collapsing that
        into "did not execute" produces a receipt asserting something the gateway does not
        know, which an independent review identified as a real evidence failure: a write
        that happened was being recorded as not having happened.

        Stored as ``2`` so existing ``0``/``1`` rows keep their meaning; readers map it
        back through :data:`UPSTREAM_EXECUTION_STATES`.
        """
        state = 2 if executed is None else (1 if executed else 0)
        with self.immediate() as conn:
            conn.execute(
                "UPDATE decisions SET upstream_executed = ?, upstream_error = ? WHERE attempt_id = ?",
                (state, error, attempt_id),
            )
        self.append_event(
            "UPSTREAM_RESULT",
            attempt_id=attempt_id,
            payload={
                "attempt_id": attempt_id,
                "executed": UPSTREAM_EXECUTION_STATES[state],
                "error": error,
            },
        )

    # ----------------------------------------------------------------- approvals

    def create_approval(self, grant: ApprovalGrant) -> None:
        """Persist a pending approval request."""
        try:
            with self.immediate() as conn:
                conn.execute(
                    "INSERT INTO approvals (approval_id, attempt_id, task_id, tool_name, tool_server, "
                    "args_digest, policy_revision, contract_hash, nonce, state, created_at, expires_at, "
                    "decided_at, decided_by, consumed_at, payload) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        grant.approval_id,
                        grant.attempt_id,
                        grant.task_id,
                        grant.tool_name,
                        grant.tool_server,
                        grant.args_digest,
                        grant.policy_revision,
                        grant.contract_hash,
                        grant.nonce,
                        str(grant.state),
                        grant.created_at.isoformat(),
                        grant.expires_at.isoformat(),
                        None,
                        None,
                        None,
                        json.dumps(grant.model_dump(mode="json")),
                    ),
                )
        except sqlite3.Error as exc:
            raise StoreUnavailable(f"could not create approval: {exc}") from exc
        self.append_event(
            "APPROVAL_REQUESTED",
            task_id=grant.task_id,
            attempt_id=grant.attempt_id,
            payload=grant.model_dump(mode="json"),
        )

    def get_approval(self, approval_id: str) -> ApprovalGrant | None:
        """Fetch one approval by id."""
        row = self.conn.execute(
            "SELECT payload, state, decided_at, decided_by, consumed_at FROM approvals WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        if row is None:
            return None
        data = json.loads(row["payload"])
        data["state"] = row["state"]
        data["decided_at"] = row["decided_at"]
        data["decided_by"] = row["decided_by"]
        data["consumed_at"] = row["consumed_at"]
        return ApprovalGrant.model_validate(data)

    def decide_approval(self, approval_id: str, *, approve: bool, reviewer: str) -> tuple[bool, str | None]:
        """Record a reviewer's decision. Only a ``pending`` approval can be decided."""
        from .reasons import Reason

        now = utcnow().isoformat()
        new_state = ApprovalState.APPROVED if approve else ApprovalState.DECLINED
        with self.immediate() as conn:
            row = conn.execute(
                "SELECT state, expires_at FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if row is None:
                return False, str(Reason.APPROVAL_NOT_FOUND)
            if row["state"] != str(ApprovalState.PENDING):
                return False, str(Reason.APPROVAL_ALREADY_CONSUMED)
            if _dt.datetime.fromisoformat(row["expires_at"]) <= utcnow():
                conn.execute(
                    "UPDATE approvals SET state = ? WHERE approval_id = ?",
                    (str(ApprovalState.EXPIRED), approval_id),
                )
                return False, str(Reason.APPROVAL_EXPIRED)
            conn.execute(
                "UPDATE approvals SET state = ?, decided_at = ?, decided_by = ? WHERE approval_id = ?",
                (str(new_state), now, reviewer, approval_id),
            )
        self.append_event(
            "APPROVAL_APPROVED" if approve else "APPROVAL_DECLINED",
            payload={"approval_id": approval_id, "reviewer": reviewer, "decided_at": now},
        )
        return True, None

    def find_consumable_grant(
        self, attempt: ToolAttempt, *, policy_revision: int, contract_hash: str
    ) -> ApprovalGrant | None:
        """Find an approved, unexpired, unconsumed grant that exactly matches an attempt."""
        rows = self.conn.execute(
            "SELECT payload, state, decided_at, decided_by, consumed_at, expires_at FROM approvals "
            "WHERE task_id = ? AND tool_name = ? AND args_digest = ? AND policy_revision = ? "
            "AND state = ? ORDER BY created_at DESC",
            (
                attempt.task_id,
                attempt.tool_name,
                attempt.canonical_args_digest(),
                policy_revision,
                str(ApprovalState.APPROVED),
            ),
        ).fetchall()
        for row in rows:
            data = json.loads(row["payload"])
            data["state"] = row["state"]
            data["decided_at"] = row["decided_at"]
            data["decided_by"] = row["decided_by"]
            data["consumed_at"] = row["consumed_at"]
            grant = ApprovalGrant.model_validate(data)
            if grant.is_expired():
                continue
            if grant.matches(attempt, policy_revision=policy_revision, contract_hash=contract_hash):
                return grant
        return None

    def consume_grant(self, approval_id: str) -> bool:
        """Atomically consume an approved grant exactly once.

        The ``WHERE state = 'approved'`` clause inside a ``BEGIN IMMEDIATE`` transaction
        is what makes this single-use: a second caller sees ``rowcount == 0``.
        """
        with self.immediate() as conn:
            cursor = conn.execute(
                "UPDATE approvals SET state = ?, consumed_at = ? WHERE approval_id = ? AND state = ?",
                (str(ApprovalState.CONSUMED), utcnow().isoformat(), approval_id, str(ApprovalState.APPROVED)),
            )
            consumed = cursor.rowcount == 1
        if consumed:
            self.append_event("APPROVAL_CONSUMED", payload={"approval_id": approval_id})
        return consumed

    def expire_stale_approvals(self) -> int:
        """Mark pending approvals whose TTL has elapsed as expired."""
        with self.immediate() as conn:
            cursor = conn.execute(
                "UPDATE approvals SET state = ? WHERE state = ? AND expires_at <= ?",
                (str(ApprovalState.EXPIRED), str(ApprovalState.PENDING), utcnow().isoformat()),
            )
            return int(cursor.rowcount or 0)

    def list_approvals(self, *, state: str | None = None, task_id: str | None = None) -> list[dict[str, Any]]:
        """List approvals for the dashboard inbox."""
        query = "SELECT payload, state, decided_at, decided_by, consumed_at FROM approvals WHERE 1=1"
        params: list[Any] = []
        if state:
            query += " AND state = ?"
            params.append(state)
        if task_id:
            query += " AND task_id = ?"
            params.append(task_id)
        query += " ORDER BY created_at DESC LIMIT 200"
        rows = self.conn.execute(query, params).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            data = json.loads(row["payload"])
            data["state"] = row["state"]
            data["decided_at"] = row["decided_at"]
            data["decided_by"] = row["decided_by"]
            data["consumed_at"] = row["consumed_at"]
            out.append(data)
        return out

    # -------------------------------------------------------------------- events

    def append_event(
        self,
        kind: str,
        *,
        payload: dict[str, Any],
        task_id: str | None = None,
        run_id: str | None = None,
        attempt_id: str | None = None,
    ) -> int:
        """Append an ordered, redacted, optionally HMAC-chained event.

        Returns the assigned sequence number. Raises :class:`StoreUnavailable` on
        failure; callers must not treat a lost audit record as a successful operation.
        """
        safe_payload = redact(payload)
        event_id = f"ev_{uuid.uuid4().hex[:16]}"
        created = utcnow().isoformat()
        try:
            with self.immediate() as conn:
                prev = conn.execute("SELECT hmac FROM events ORDER BY seq DESC LIMIT 1").fetchone()
                prev_hmac = prev["hmac"] if prev else None
                chain_hmac: str | None = None
                if self._hmac_key is not None:
                    chain_hmac = keyed_digest(
                        {
                            "event_id": event_id,
                            "kind": kind,
                            "task_id": task_id,
                            "run_id": run_id,
                            "attempt_id": attempt_id,
                            "payload": safe_payload,
                            "prev": prev_hmac,
                            "created_at": created,
                        },
                        self._hmac_key,
                    )
                cursor = conn.execute(
                    "INSERT INTO events (event_id, kind, task_id, run_id, attempt_id, payload, "
                    "prev_hmac, hmac, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        event_id,
                        kind,
                        task_id,
                        run_id,
                        attempt_id,
                        canonical_text(safe_payload),
                        prev_hmac,
                        chain_hmac,
                        created,
                    ),
                )
                return int(cursor.lastrowid or 0)
        except sqlite3.Error as exc:
            raise StoreUnavailable(f"could not append event: {exc}") from exc

    def events_since(
        self, seq: int = 0, *, task_id: str | None = None, run_id: str | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        """Page events in monotonic order."""
        query = (
            "SELECT seq, event_id, kind, task_id, run_id, attempt_id, payload, hmac, created_at "
            "FROM events WHERE seq > ?"
        )
        params: list[Any] = [seq]
        if task_id:
            query += " AND task_id = ?"
            params.append(task_id)
        if run_id:
            query += " AND run_id = ?"
            params.append(run_id)
        query += " ORDER BY seq ASC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        rows = self.conn.execute(query, params).fetchall()
        return [
            {
                "seq": row["seq"],
                "event_id": row["event_id"],
                "kind": row["kind"],
                "task_id": row["task_id"],
                "run_id": row["run_id"],
                "attempt_id": row["attempt_id"],
                "payload": json.loads(row["payload"]),
                "hmac": row["hmac"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def latest_seq(self) -> int:
        """Highest assigned event sequence number."""
        row = self.conn.execute("SELECT COALESCE(MAX(seq), 0) AS s FROM events").fetchone()
        return int(row["s"])

    @property
    def audit_chain_configured(self) -> bool:
        """Is this store writing and able to verify an integrity chain?

        A caller must consult **this store**, not the environment. An independent review
        found the control plane reading ``AD_AUDIT_HMAC_KEY`` from the environment while
        constructing its store without the key, so it reported ``verified: true`` over a
        log whose every HMAC was NULL -- an assurance it had not performed.
        """
        return self._hmac_key is not None

    def verify_chain(self) -> tuple[bool | None, str | None]:
        """Recompute the HMAC chain.

        Returns ``(None, reason)`` when there is no chain to verify, ``(True, None)`` when
        the chain is intact, and ``(False, problem)`` when it is not. The three-state
        return exists so "no key" cannot be rendered as "verified" by a caller that
        treats the result as a boolean.
        """
        if self._hmac_key is None:
            return None, "no signing key is configured, so there is no chain to verify"
        prev_hmac: str | None = None
        rows = self.conn.execute(
            "SELECT seq, event_id, kind, task_id, run_id, attempt_id, payload, prev_hmac, hmac, created_at "
            "FROM events ORDER BY seq ASC"
        ).fetchall()
        for row in rows:
            expected = keyed_digest(
                {
                    "event_id": row["event_id"],
                    "kind": row["kind"],
                    "task_id": row["task_id"],
                    "run_id": row["run_id"],
                    "attempt_id": row["attempt_id"],
                    "payload": json.loads(row["payload"]),
                    "prev": prev_hmac,
                    "created_at": row["created_at"],
                },
                self._hmac_key,
            )
            if row["prev_hmac"] != prev_hmac:
                return False, f"event seq={row['seq']} has a broken prev_hmac link"
            if row["hmac"] != expected:
                return False, f"event seq={row['seq']} hmac does not match its contents"
            prev_hmac = row["hmac"]
        return True, None

    # ---------------------------------------------------------------------- runs

    def list_runs(self, *, task_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Summarize runs for the dashboard run selector."""
        query = (
            "SELECT r.run_id, r.task_id, r.scenario, r.label, r.started_at, r.ended_at, "
            "COUNT(d.decision_id) AS decisions, "
            "SUM(CASE WHEN d.status='allow' THEN 1 ELSE 0 END) AS allowed, "
            "SUM(CASE WHEN d.status='deny' THEN 1 ELSE 0 END) AS denied, "
            "SUM(CASE WHEN d.status='needs_approval' THEN 1 ELSE 0 END) AS pending "
            "FROM runs r LEFT JOIN decisions d ON d.run_id = r.run_id WHERE 1=1"
        )
        params: list[Any] = []
        if task_id:
            query += " AND r.task_id = ?"
            params.append(task_id)
        query += " GROUP BY r.run_id ORDER BY r.started_at DESC LIMIT ?"
        params.append(limit)
        return [dict(row) for row in self.conn.execute(query, params).fetchall()]

    def set_run_metadata(
        self,
        run_id: str,
        *,
        task_id: str | None = None,
        scenario: str | None = None,
        label: str | None = None,
    ) -> None:
        """Attach a scenario name and label to a run."""
        with self.immediate() as conn:
            conn.execute(
                "INSERT INTO runs (run_id, task_id, scenario, label, started_at) VALUES (?,?,?,?,?) "
                "ON CONFLICT(run_id) DO UPDATE SET scenario=COALESCE(excluded.scenario, runs.scenario), "
                "label=COALESCE(excluded.label, runs.label), task_id=COALESCE(excluded.task_id, runs.task_id)",
                (run_id, task_id, scenario, label, utcnow().isoformat()),
            )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        """Full detail for one run: attempts joined to their decisions, in order."""
        run = self.conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if run is None:
            return None
        rows = self.conn.execute(
            "SELECT a.attempt_id, a.payload AS attempt_payload, a.created_at AS attempt_at, "
            "d.payload AS decision_payload, d.status, d.upstream_executed "
            "FROM attempts a LEFT JOIN decisions d ON d.attempt_id = a.attempt_id "
            "WHERE a.run_id = ? ORDER BY a.created_at ASC",
            (run_id,),
        ).fetchall()
        return {
            "run_id": run["run_id"],
            "task_id": run["task_id"],
            "scenario": run["scenario"],
            "label": run["label"],
            "started_at": run["started_at"],
            "ended_at": run["ended_at"],
            "steps": [
                {
                    "attempt": json.loads(row["attempt_payload"]),
                    "decision": json.loads(row["decision_payload"]) if row["decision_payload"] else None,
                    "status": row["status"],
                    "upstream_executed": UPSTREAM_EXECUTION_STATES.get(int(row["upstream_executed"]), "no"),
                    "at": row["attempt_at"],
                }
                for row in rows
            ],
        }

    def decision_latencies(self, *, task_id: str | None = None) -> list[float]:
        """All recorded decision latencies in ms, for percentile reporting."""
        query = "SELECT elapsed_ms FROM decisions WHERE elapsed_ms > 0"
        params: list[Any] = []
        if task_id:
            query += " AND task_id = ?"
            params.append(task_id)
        return [float(row["elapsed_ms"]) for row in self.conn.execute(query, params).fetchall()]

    def counts(self) -> dict[str, int]:
        """Aggregate counters used by the dashboard header and by ``make smoke``."""
        out: dict[str, int] = {}
        for status in (DecisionStatus.ALLOW, DecisionStatus.DENY, DecisionStatus.NEEDS_APPROVAL):
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM decisions WHERE status = ?", (str(status),)
            ).fetchone()
            out[str(status)] = int(row["n"])
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM decisions WHERE status = 'deny' AND upstream_executed IN (1, 2)"
        ).fetchone()
        out["denied_but_executed"] = int(row["n"])
        row = self.conn.execute("SELECT COUNT(*) AS n FROM decisions WHERE upstream_executed = 2").fetchone()
        out["execution_unknown"] = int(row["n"])
        out["events"] = self.latest_seq()
        return out


def open_default_store() -> Store:
    """Open the store at ``AD_DB_PATH`` (default ``var/agent_drift.db``).

    The HMAC chain is enabled only when ``AD_AUDIT_HMAC_KEY`` is set, because an
    integrity chain keyed by a value sitting in the same repository would be theatre.
    """
    key = os.environ.get("AD_AUDIT_HMAC_KEY")
    return Store(
        os.environ.get("AD_DB_PATH", DEFAULT_DB_PATH),
        hmac_key=key.encode("utf-8") if key else None,
    )
