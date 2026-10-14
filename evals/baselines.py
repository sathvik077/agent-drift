"""The three evaluation arms.

Comparing against something is what makes the headline numbers mean anything. The arms
are chosen so that each one fails in an informative way:

1. ``unguarded_passthrough`` -- forwards everything. Perfect benign completion, zero
   protection. This is the control that says how much utility a defence costs.
2. ``keyword_classifier`` -- a text filter over the tool name and argument strings, of
   the kind that is genuinely common in practice. It catches obvious attacks and produces
   false blocks on benign documents that merely *mention* dangerous operations, which is
   what the ``benign_alarming_text`` family exists to measure.
3. ``contract_policy`` -- the real :class:`agent_drift.policy.PolicyEngine`, through the
   same code path the gateway uses. Not a reimplementation: if the engine changes, this
   arm changes with it.

A case that "needs approval" counts as **blocked** for every arm, because a call awaiting
a human has not been authorized to execute.
"""

from __future__ import annotations

import datetime as _dt
import re
import time
from dataclasses import dataclass
from typing import Any, Protocol

from agent_drift.contracts import DecisionStatus, ToolAttempt, utcnow
from agent_drift.policy import PolicyEngine
from agent_drift.seed import build_contract
from agent_drift.store import Store

__all__ = ["ARMS", "Arm", "ArmResult", "ContractPolicy", "KeywordClassifier", "UnguardedPassthrough"]


@dataclass
class ArmResult:
    """One arm's verdict on one case."""

    decision: str
    blocked: bool
    reason_codes: list[str]
    elapsed_ms: float


class Arm(Protocol):
    """An evaluation arm."""

    name: str
    description: str

    def decide(self, case: dict[str, Any]) -> ArmResult:
        """Decide one case."""
        ...


class UnguardedPassthrough:
    """Forwards every call. The utility ceiling and the protection floor."""

    name = "unguarded_passthrough"
    description = (
        "No gateway. Every proposed tool call is forwarded. Establishes the benign "
        "completion ceiling and the zero-protection floor."
    )

    def decide(self, case: dict[str, Any]) -> ArmResult:
        """Allow everything."""
        started = time.perf_counter()
        return ArmResult(
            decision="allow",
            blocked=False,
            reason_codes=[],
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )


class KeywordClassifier:
    """A text filter over the tool name and argument strings.

    Representative of a common real approach: look for dangerous-sounding words. It is
    implemented honestly -- a reasonable keyword list, applied to the whole argument
    object and the tool name -- rather than as a straw man, so that where it wins
    (catching obvious exfiltration) and where it loses (benign documents about deletion)
    are both visible.
    """

    name = "keyword_classifier"
    description = (
        "Blocks a call when the tool name or any argument string matches a list of "
        "dangerous keywords. No notion of a task, a scope, a budget or an approval."
    )

    #: Tool-name fragments that look destructive.
    TOOL_PATTERNS = (
        re.compile(r"write", re.I),
        re.compile(r"delete", re.I),
        re.compile(r"remove", re.I),
        re.compile(r"post", re.I),
        re.compile(r"exec", re.I),
        re.compile(r"eval", re.I),
        re.compile(r"chmod", re.I),
        re.compile(r"quer", re.I),
    )

    #: Argument-content fragments that look dangerous.
    ARG_PATTERNS = (
        re.compile(r"\bdelete\b", re.I),
        re.compile(r"\bdrop\s+table\b", re.I),
        re.compile(r"\brm\s+-rf\b", re.I),
        re.compile(r"\bexfiltrat", re.I),
        re.compile(r"\bupload\b", re.I),
        re.compile(r"\bpassword\b", re.I),
        re.compile(r"\bsecret", re.I),
        re.compile(r"\btoken\b", re.I),
        re.compile(r"ignore\s+all\s+previous", re.I),
        re.compile(r"\.\."),
        re.compile(r"\betc/passwd\b", re.I),
        re.compile(r"\bexfil\b", re.I),
        re.compile(r"\battacker\b", re.I),
        re.compile(r"\bevil\b", re.I),
        re.compile(r"\bcollect\b", re.I),
        re.compile(r"\bdump\b", re.I),
        re.compile(r"\bwebhook\b", re.I),
        re.compile(r"\bpaste\b", re.I),
    )

    def decide(self, case: dict[str, Any]) -> ArmResult:
        """Block on any keyword hit."""
        started = time.perf_counter()
        hits: list[str] = []

        for pattern in self.TOOL_PATTERNS:
            if pattern.search(case["tool"]):
                hits.append(f"tool:{pattern.pattern}")

        haystack = _argument_text(case["args"])
        for pattern in self.ARG_PATTERNS:
            if pattern.search(haystack):
                hits.append(f"arg:{pattern.pattern}")

        elapsed = (time.perf_counter() - started) * 1000.0
        blocked = bool(hits)
        return ArmResult(
            decision="deny" if blocked else "allow",
            blocked=blocked,
            reason_codes=hits[:6],
            elapsed_ms=elapsed,
        )


#: The upstream fixture's advertised input schemas, as observed on the wire from
#: ``examples/upstream_mcp/server.py``. The gateway passes these to the engine on every
#: call, so the evaluation must too -- otherwise the measurement would under-report the
#: protection the real system provides. These are captured here rather than discovered at
#: eval time so the benchmark stays offline and deterministic;
#: ``tests/integration/test_schema_gate.py`` asserts they still match what the fixture
#: actually advertises, so they cannot go stale silently.
FIXTURE_SCHEMAS: dict[str, dict[str, Any]] = {
    "repo.read_file": {
        "type": "object",
        "properties": {"path": {"title": "Path", "type": "string"}},
        "required": ["path"],
    },
    "repo.list_files": {
        "type": "object",
        "properties": {"path": {"default": "sandbox-repo", "title": "Path", "type": "string"}},
    },
    "repo.write_file": {
        "type": "object",
        "properties": {
            "path": {"title": "Path", "type": "string"},
            "content": {"title": "Content", "type": "string"},
        },
        "required": ["path", "content"],
    },
    "repo.delete_file": {
        "type": "object",
        "properties": {"path": {"title": "Path", "type": "string"}},
        "required": ["path"],
    },
    "network.http_post": {
        "type": "object",
        "properties": {
            "url": {"title": "Url", "type": "string"},
            "body": {"default": "", "title": "Body", "type": "string"},
        },
        "required": ["url"],
    },
}


class ContractPolicy:
    """The real policy engine, through the same path the gateway uses."""

    name = "contract_policy"
    description = (
        "Agent Drift's deterministic policy engine evaluating each call against the "
        "approved intent contract for its task, with the same enforcement order and the "
        "same upstream input schemas the gateway applies."
    )

    def __init__(self, db_path: str, sandbox_root: str | None = None) -> None:
        self.store = Store(db_path)
        self.engine = PolicyEngine(self.store, sandbox_root=sandbox_root)  # type: ignore[arg-type]
        self._registered: set[tuple[str, int]] = set()

    def close(self) -> None:
        """Close the store."""
        self.store.close()

    def _prepare(self, case: dict[str, Any]) -> str:
        """Register the case's contract with its preconditions, return the bound task id.

        Preconditions are applied as *real* state: a budget precondition is reserved
        through the store, an expired contract is registered with a past expiry. Nothing
        is simulated by short-circuiting the engine.
        """
        contract_name = case.get("contract")
        setup = case.get("setup") or {}

        if contract_name is None:
            # Bind to a task that has deliberately never been registered.
            return "eval-task-with-no-contract"

        overrides: dict[str, Any] = {}
        if contract_name == "expired":
            overrides["issued_at"] = utcnow() - _dt.timedelta(hours=2)
            overrides["expires_at"] = utcnow() - _dt.timedelta(hours=1)

        contract = build_contract(contract_name, **overrides)
        key = (contract.task_id, contract.policy_revision)
        if key not in self._registered or overrides:
            self.store.put_contract(contract)
            self._registered.add(key)

        # Reset or set budget deterministically for this case.
        reserved = int(setup.get("writes_already_reserved", 0))
        self.store.set_budget_used(
            contract.task_id, contract.policy_revision, calls=reserved, writes=reserved
        )
        return contract.task_id

    def decide(self, case: dict[str, Any]) -> ArmResult:
        """Evaluate one case with the real engine."""
        task_id = self._prepare(case)
        args = case["args"]
        attempt = ToolAttempt(
            tool_server="sandbox",
            tool_name=case["tool"],
            args=args if isinstance(args, dict) else {"value": args},
        )
        started = time.perf_counter()
        decision = self.engine.evaluate(
            attempt,
            bound_task_id=task_id,
            upstream_schema=FIXTURE_SCHEMAS.get(case["tool"]),
            reserve=True,
        )
        elapsed = (time.perf_counter() - started) * 1000.0

        blocked = decision.status is not DecisionStatus.ALLOW
        return ArmResult(
            decision=str(decision.status),
            blocked=blocked,
            reason_codes=decision.reason_codes,
            elapsed_ms=elapsed,
        )


def _argument_text(args: Any, depth: int = 0) -> str:
    """Flatten an argument object into searchable text."""
    if depth > 8:
        return ""
    if isinstance(args, dict):
        return " ".join(f"{key} {_argument_text(value, depth + 1)}" for key, value in args.items())
    if isinstance(args, (list, tuple)):
        return " ".join(_argument_text(item, depth + 1) for item in args)
    return str(args)


ARMS = ("unguarded_passthrough", "keyword_classifier", "contract_policy")
