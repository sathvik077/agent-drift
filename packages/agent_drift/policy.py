"""Deterministic policy evaluation.

One class, one frozen order. The order is not an implementation detail -- it is the
security property -- so it is written as an explicit sequence of stages rather than a set
of independent predicates, and ``tests/unit/test_enforcement_order.py`` asserts that an
attempt violating several stages reports the *earliest* one.

```
 1 R1-input-validation      arguments are an object, bounded, schema-conformant
 2 R2-task-identity         gateway has a binding; arguments carry no identity field
 3 R3-contract-validity     contract exists, is trusted, is in its validity window
 4 R4-manifest-integrity    upstream manifest matches what was pinned at approval
 5 R5-tool-allowlist        server and tool are permitted
 6 R6-operation-policy      operation is allowed and not denied
 7 R7-resource-scope        target path canonicalizes inside a declared scope
 8 R8-destination-scope     destination normalizes to an allowlisted host
 9 R9-budgets               call and write budgets reserved atomically
10 R10-approval             required approvals are pending, granted, or denied
11 R11-advisory-heuristics  may escalate allow -> needs_approval; never overrides a deny
```

Two rules that are easy to get wrong and are therefore enforced structurally:

* **Probabilistic signals can only escalate.** :meth:`PolicyEngine._advisory` is called
  last and its return value is applied only when the running status is ``ALLOW``. There
  is no code path by which a heuristic turns a ``DENY`` into anything else.
* **Exceptions fail closed.** :meth:`PolicyEngine.evaluate` wraps stages 1-11 in a
  ``try``/``except BaseException`` that produces ``deny / AD-E999``. A policy bug, a
  malformed contract, or an unavailable store all result in denial.
"""

from __future__ import annotations

import datetime as _dt
import re
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .contracts import (
    MUTATING_OPERATIONS,
    WRITE_BUDGET_OPERATIONS,
    ApprovalGrant,
    ApprovalState,
    ContractSource,
    DecisionStatus,
    IntentContract,
    Operation,
    PolicyDecision,
    RiskLevel,
    ToolAttempt,
    utcnow,
)
from .destinations import destination_allowed
from .manifest import ManifestFingerprint, diff_manifests
from .paths import normalize_relative_path, resolve_in_root, scope_for
from .reasons import Reason, explain, rule_for
from .store import ContractIntegrityError, Store, StoreUnavailable

__all__ = [
    "DEFAULT_OPERATION_MAP",
    "DEFAULT_TOOL_SPECS",
    "MAX_ARGS_BYTES",
    "PolicyEngine",
    "ToolSpec",
]

#: Hard bound on the serialized size of a tool-argument object.
MAX_ARGS_BYTES: Final[int] = 256 * 1024

#: Argument keys that would be an attempt to supply or override task identity.
#: Task identity is host-owned; seeing any of these in model-supplied arguments is
#: reported as ``AD-E011`` rather than silently ignored, because it is signal.
_IDENTITY_ARG_KEYS: Final[frozenset[str]] = frozenset(
    {
        "task_id",
        "taskid",
        "task",
        "principal",
        "contract",
        "contract_id",
        "contract_hash",
        "policy_revision",
        "approved_by",
        "approval_id",
        "admin_token",
        "ad_task_id",
        "_task_id",
        "trust_tier",
        "trusted",
    }
)

#: The same keys, NFKC-folded and stripped of separators, for comparison.
_IDENTITY_ARG_KEYS_FOLDED: Final[frozenset[str]] = frozenset(
    "".join(ch for ch in unicodedata.normalize("NFKC", key).casefold() if ch.isalnum())
    for key in _IDENTITY_ARG_KEYS
)

#: Tool name -> operation. **Local configuration, never derived from tool metadata.**
#: The 2026-07-28 spec warns that annotations are untrusted hints from the server; a
#: server that labels its delete tool ``read_only_hint: true`` must not thereby become
#: safe, so the mapping lives here, under the operator's control.
DEFAULT_OPERATION_MAP: Final[dict[str, Operation]] = {
    "repo.read_file": Operation.READ,
    "repo.list_files": Operation.LIST,
    "repo.write_file": Operation.WRITE,
    "repo.delete_file": Operation.DELETE,
    "network.http_post": Operation.NETWORK_POST,
}


def load_tool_specs(path: str | Path) -> dict[str, ToolSpec]:
    """Load a tool-to-operation map from JSON.

    This is how a non-fixture MCP server is guarded without editing the library. Operations
    are declared **here, by the operator** -- never read from a tool's own description or
    annotations, which come from the server and may be the adversary.

    Format::

        {
          "files.read":  {"operation": "read",  "resource_arg": "path", "requires_resource": true},
          "files.write": {"operation": "write", "resource_arg": "path", "requires_resource": true},
          "http.post":   {"operation": "network_post", "destination_arg": "url",
                          "requires_destination": true}
        }

    A tool absent from the map has operation ``unknown`` and is denied, so an incomplete
    map fails closed rather than open.
    """
    import json

    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("a tool spec file must be a JSON object keyed by tool name")

    specs: dict[str, ToolSpec] = {}
    for name, entry in raw.items():
        if not isinstance(entry, dict):
            raise ValueError(f"tool spec for {name!r} must be an object")
        operation = entry.get("operation")
        try:
            parsed = Operation(str(operation))
        except ValueError as exc:
            raise ValueError(
                f"tool spec for {name!r} has unknown operation {operation!r}; "
                f"valid values: {', '.join(op.value for op in Operation)}"
            ) from exc
        specs[str(name)] = ToolSpec(
            name=str(name),
            operation=parsed,
            resource_arg=entry.get("resource_arg"),
            destination_arg=entry.get("destination_arg"),
            requires_resource=bool(entry.get("requires_resource", False)),
            requires_destination=bool(entry.get("requires_destination", False)),
        )
    return specs


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Local declaration of what a tool does and where its arguments live.

    ``resource_arg`` and ``destination_arg`` tell the engine which argument carries the
    target, so resource and destination checks do not have to guess. A tool with neither
    is treated as having no scoped target, and a contract must then rely on the tool
    allowlist alone -- which the engine records as evidence so the gap is visible.
    """

    name: str
    operation: Operation
    resource_arg: str | None = None
    destination_arg: str | None = None
    requires_resource: bool = False
    requires_destination: bool = False


DEFAULT_TOOL_SPECS: Final[dict[str, ToolSpec]] = {
    "repo.read_file": ToolSpec("repo.read_file", Operation.READ, resource_arg="path", requires_resource=True),
    "repo.list_files": ToolSpec("repo.list_files", Operation.LIST, resource_arg="path"),
    "repo.write_file": ToolSpec(
        "repo.write_file", Operation.WRITE, resource_arg="path", requires_resource=True
    ),
    "repo.delete_file": ToolSpec(
        "repo.delete_file", Operation.DELETE, resource_arg="path", requires_resource=True
    ),
    "network.http_post": ToolSpec(
        "network.http_post", Operation.NETWORK_POST, destination_arg="url", requires_destination=True
    ),
}

#: Advisory-only: argument content that resembles injected instructions. This never
#: denies anything. It exists so the dashboard can show "this looked like an injection"
#: next to a decision that was made on contract grounds alone.
_INJECTION_SHAPES: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
    re.compile(r"disregard\s+(the\s+)?(system|previous)\s+prompt", re.I),
    re.compile(r"you\s+are\s+now\s+(a|an|in)\s+", re.I),
    re.compile(r"(exfiltrate|upload|send)\s+(the\s+)?(repo|repository|source|secrets|credentials)", re.I),
    re.compile(r"new\s+(task|goal|objective)\s*:", re.I),
)

_RISK_BY_OPERATION: Final[dict[Operation, RiskLevel]] = {
    Operation.READ: RiskLevel.LOW,
    Operation.LIST: RiskLevel.LOW,
    Operation.WRITE: RiskLevel.MEDIUM,
    Operation.EXECUTE: RiskLevel.HIGH,
    Operation.DELETE: RiskLevel.HIGH,
    Operation.NETWORK_POST: RiskLevel.CRITICAL,
    Operation.UNKNOWN: RiskLevel.HIGH,
}


class _Verdict:
    """Mutable accumulator threaded through the stages."""

    __slots__ = (
        "approval_id",
        "evidence",
        "reasons",
        "reserved_call",
        "reserved_write",
        "risk",
        "rules",
        "status",
    )

    def __init__(self) -> None:
        self.status: DecisionStatus = DecisionStatus.ALLOW
        self.reasons: list[str] = []
        self.rules: list[str] = []
        self.evidence: dict[str, Any] = {}
        self.risk: RiskLevel = RiskLevel.LOW
        self.approval_id: str | None = None
        self.reserved_write: bool = False
        self.reserved_call: bool = False

    def deny(self, code: str, **evidence: Any) -> None:
        """Record a terminal denial."""
        self.status = DecisionStatus.DENY
        self._add(code, evidence)

    def needs_approval(self, code: str, **evidence: Any) -> None:
        """Record that human review is required."""
        self.status = DecisionStatus.NEEDS_APPROVAL
        self._add(code, evidence)

    def note(self, code: str, **evidence: Any) -> None:
        """Record a reason without changing the status."""
        self._add(code, evidence)

    def _add(self, code: str, evidence: dict[str, Any]) -> None:
        if code not in self.reasons:
            self.reasons.append(code)
        rule = rule_for(code)
        if rule not in self.rules:
            self.rules.append(rule)
        self.evidence.update(evidence)


class PolicyEngine:
    """Evaluates tool attempts against approved intent contracts.

    The engine is stateless apart from its injected :class:`~agent_drift.store.Store`,
    a sandbox root used for path resolution, and the tool specification table. It never
    performs the tool call; forwarding is the gateway's job, and the engine is the thing
    the gateway asks first.
    """

    def __init__(
        self,
        store: Store,
        *,
        sandbox_root: Path | None = None,
        tool_specs: dict[str, ToolSpec] | None = None,
        approval_ttl_s: int = 300,
        clock: Any = None,
    ) -> None:
        self.store = store
        self.sandbox_root = Path(sandbox_root) if sandbox_root else None
        self.tool_specs = dict(tool_specs or DEFAULT_TOOL_SPECS)
        self.approval_ttl_s = approval_ttl_s
        self._clock = clock or utcnow

    # ------------------------------------------------------------------ helpers

    def now(self) -> _dt.datetime:
        """Current time from the injected clock, so TTL tests are deterministic."""
        result = self._clock()
        return result if isinstance(result, _dt.datetime) else utcnow()

    def spec_for(self, tool_name: str) -> ToolSpec | None:
        """Locally configured specification for a tool, if any."""
        return self.tool_specs.get(tool_name)

    def classify_operation(self, tool_name: str) -> Operation:
        """Map a tool name to an operation using local configuration only."""
        spec = self.spec_for(tool_name)
        if spec is not None:
            return spec.operation
        return DEFAULT_OPERATION_MAP.get(tool_name, Operation.UNKNOWN)

    # ----------------------------------------------------------------- evaluate

    def evaluate(
        self,
        attempt: ToolAttempt,
        *,
        bound_task_id: str | None,
        observed_manifest: ManifestFingerprint | None = None,
        upstream_schema: dict[str, Any] | None = None,
        reserve: bool = True,
    ) -> PolicyDecision:
        """Evaluate one attempt and return a persisted-shape decision.

        ``bound_task_id`` is the gateway's launch-time binding. ``reserve`` is ``False``
        for the SDK's advisory path, where no budget should be consumed because nothing
        will be enforced.
        """
        started = time.perf_counter()
        verdict = _Verdict()
        contract: IntentContract | None = None

        try:
            self._stage_input(attempt, verdict, upstream_schema)
            if verdict.status is not DecisionStatus.DENY:
                self._stage_identity(attempt, verdict, bound_task_id)
            if verdict.status is not DecisionStatus.DENY:
                contract = self._stage_contract(attempt, verdict)
            if verdict.status is not DecisionStatus.DENY and contract is not None:
                self._stage_manifest(attempt, verdict, contract, observed_manifest)
            if verdict.status is not DecisionStatus.DENY and contract is not None:
                self._stage_allowlist(attempt, verdict, contract)
            if verdict.status is not DecisionStatus.DENY and contract is not None:
                self._stage_operation(attempt, verdict, contract)
            if verdict.status is not DecisionStatus.DENY and contract is not None:
                self._stage_resource(attempt, verdict, contract)
            if verdict.status is not DecisionStatus.DENY and contract is not None:
                self._stage_destination(attempt, verdict, contract)
            # Budgets (R9) are evaluated before approvals (R10), matching the documented
            # order. The reverse let a single-use human grant be consumed by a call the
            # budget stage then denied -- destroying the authorization without any action
            # taken, and emitting a receipt carrying both "approval granted" and a denial.
            if verdict.status is DecisionStatus.ALLOW and contract is not None and reserve:
                self._stage_budget(attempt, verdict, contract)
            if verdict.status is not DecisionStatus.DENY and contract is not None:
                self._stage_approval_required(attempt, verdict, contract)
            if verdict.status is DecisionStatus.ALLOW:
                self._stage_advisory(attempt, verdict, contract)

        except ContractIntegrityError as exc:
            verdict = _Verdict()
            verdict.deny(str(Reason.CONTRACT_INTEGRITY_FAILED), integrity_error=str(exc))
        except StoreUnavailable as exc:
            verdict = _Verdict()
            verdict.deny(str(Reason.STORE_UNAVAILABLE), store_error=str(exc))
        except BaseException as exc:
            verdict = _Verdict()
            verdict.deny(
                str(Reason.EVALUATOR_ERROR),
                evaluator_error=f"{type(exc).__name__}: {exc}",
            )

        if verdict.status is DecisionStatus.DENY:
            # A denial must not advertise "approval granted": a receipt that carries both
            # is self-contradictory evidence for a reviewer.
            contradictory = {str(Reason.APPROVAL_GRANTED), str(Reason.ALLOWED_AFTER_APPROVAL)}
            verdict.reasons = [code for code in verdict.reasons if code not in contradictory]

        if verdict.status is DecisionStatus.ALLOW and not verdict.reasons:
            operation = self.classify_operation(attempt.tool_name)
            verdict.note(
                str(
                    Reason.ALLOWED_READ_ONLY
                    if operation in (Operation.READ, Operation.LIST)
                    else Reason.ALLOWED_BY_CONTRACT
                )
            )

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        verdict.risk = _RISK_BY_OPERATION.get(self.classify_operation(attempt.tool_name), RiskLevel.HIGH)
        verdict.evidence.setdefault("explanations", [explain(code) for code in verdict.reasons])
        verdict.evidence.setdefault(
            "enforcement_stage", verdict.rules[0] if verdict.rules else "R0-fail-closed"
        )

        return PolicyDecision(
            attempt_id=attempt.attempt_id,
            task_id=attempt.task_id,
            status=verdict.status,
            tool_name=attempt.tool_name,
            tool_server=attempt.tool_server,
            operation=str(attempt.operation),
            target_resource=attempt.target_resource,
            destination=attempt.destination,
            reason_codes=verdict.reasons,
            rule_ids=verdict.rules,
            evidence=verdict.evidence,
            risk=verdict.risk,
            contract_hash=contract.contract_hash if contract else None,
            contract_version=contract.version if contract else None,
            policy_revision=contract.policy_revision if contract else None,
            elapsed_ms=elapsed_ms,
            approval_id=verdict.approval_id,
            timestamp=self.now(),
        )

    # ------------------------------------------------------------------- stage 1

    def _stage_input(
        self, attempt: ToolAttempt, verdict: _Verdict, upstream_schema: dict[str, Any] | None
    ) -> None:
        """Validate the argument object's shape, size and schema conformance."""
        if not isinstance(attempt.args, dict):
            verdict.deny(str(Reason.ARGUMENTS_NOT_OBJECT), args_type=type(attempt.args).__name__)
            return

        from .canonical import canonical_json

        try:
            size = len(canonical_json(attempt.args))
        except (ValueError, TypeError) as exc:
            verdict.deny(str(Reason.BAD_ARGUMENTS), serialization_error=str(exc))
            return
        if size > MAX_ARGS_BYTES:
            verdict.deny(str(Reason.ARGUMENT_TOO_LARGE), args_bytes=size, limit=MAX_ARGS_BYTES)
            return
        verdict.evidence["args_bytes"] = size

        if upstream_schema:
            problem = _schema_mismatch(attempt.args, upstream_schema)
            if problem is not None:
                code, detail = problem
                verdict.deny(
                    code,
                    schema_problem=detail,
                    declared_schema_keys=sorted((upstream_schema.get("properties") or {}).keys()),
                )
                return

    # ------------------------------------------------------------------- stage 2

    def _stage_identity(self, attempt: ToolAttempt, verdict: _Verdict, bound_task_id: str | None) -> None:
        """Enforce that task identity is host-owned.

        Three distinct failures, kept distinct because they mean different things to a
        reviewer: no binding at all, an argument trying to supply identity, and an
        attempt whose recorded task differs from the binding.
        """
        spoofed = sorted(key for key in attempt.args if _looks_like_identity_key(str(key)))
        if spoofed:
            verdict.deny(
                str(Reason.TASK_SPOOF_ATTEMPT),
                spoofed_argument_keys=spoofed,
                bound_task_id=bound_task_id,
                note=(
                    "Task identity is bound when the gateway is launched and is never read from "
                    "tool arguments. The presence of these keys is recorded as an attempt."
                ),
            )
            return

        if not bound_task_id:
            verdict.deny(str(Reason.MISSING_TASK_BINDING))
            return

        if attempt.task_id is None:
            attempt.task_id = bound_task_id
        elif attempt.task_id != bound_task_id:
            verdict.deny(
                str(Reason.TASK_MISMATCH),
                attempt_task_id=attempt.task_id,
                bound_task_id=bound_task_id,
            )
            return

        verdict.evidence["bound_task_id"] = bound_task_id

    # ------------------------------------------------------------------- stage 3

    def _stage_contract(self, attempt: ToolAttempt, verdict: _Verdict) -> IntentContract | None:
        """Load and validate the active contract for the bound task."""
        assert attempt.task_id is not None  # guaranteed by stage 2
        contract = self.store.get_contract(attempt.task_id)
        if contract is None:
            verdict.deny(str(Reason.NO_CONTRACT), task_id=attempt.task_id)
            return None

        if contract.source not in (ContractSource.TRUSTED_UI, ContractSource.TRUSTED_CONFIG):
            verdict.deny(str(Reason.CONTRACT_UNTRUSTED_SOURCE), source=str(contract.source))
            return None

        now = self.now()
        if contract.is_not_yet_valid(now=now):
            verdict.deny(
                str(Reason.CONTRACT_NOT_YET_VALID),
                issued_at=contract.issued_at.isoformat(),
                now=now.isoformat(),
            )
            return None
        if contract.is_expired(now=now):
            verdict.deny(
                str(Reason.CONTRACT_EXPIRED),
                expires_at=contract.expires_at.isoformat() if contract.expires_at else None,
                now=now.isoformat(),
            )
            return None

        # The stored hash must still match the stored contents: a direct database edit
        # that changed a permission without recomputing the hash is detected here.
        if contract.compute_hash() != contract.contract_hash:
            verdict.deny(
                str(Reason.CONTRACT_REVISION_CHANGED),
                stored_hash=contract.contract_hash,
                computed_hash=contract.compute_hash(),
            )
            return None

        verdict.evidence["contract"] = {
            "hash": contract.contract_hash,
            "policy_revision": contract.policy_revision,
            "user_goal": contract.user_goal,
            "source": str(contract.source),
            "approved_by": contract.approved_by,
        }
        return contract

    # ------------------------------------------------------------------- stage 4

    def _stage_manifest(
        self,
        attempt: ToolAttempt,
        verdict: _Verdict,
        contract: IntentContract,
        observed: ManifestFingerprint | None,
    ) -> None:
        """Compare the live upstream manifest against the one pinned at approval time."""
        if observed is None:
            # No live manifest to compare (SDK advisory path, or a gateway that has not
            # yet listed tools). Recorded, not treated as a pass for risky operations.
            verdict.evidence["manifest_check"] = "skipped: no observed manifest"
            return

        pin = self.store.get_manifest_pin(contract.task_id)
        diff = diff_manifests(pin, observed)
        verdict.evidence["manifest_diff"] = diff.to_dict()
        verdict.evidence["manifest_digest_observed"] = observed.manifest_digest

        if attempt.tool_name not in observed.tools:
            verdict.deny(
                str(Reason.MANIFEST_UNKNOWN_TOOL),
                tool=attempt.tool_name,
                known_tools=sorted(observed.tools),
            )
            return

        if pin is None:
            operation = self.classify_operation(attempt.tool_name)
            if operation in MUTATING_OPERATIONS:
                verdict.deny(
                    str(Reason.MANIFEST_NOT_PINNED),
                    note="No manifest was pinned for this task, so a mutating call cannot be authorized.",
                )
            else:
                verdict.evidence["manifest_check"] = "unpinned; read-only call permitted"
            return

        if not diff.changed:
            verdict.evidence["manifest_check"] = "pinned digest matches observed"
            return

        policy = contract.manifest_drift_policy
        operation = self.classify_operation(attempt.tool_name)
        if policy == "deny_all":
            verdict.deny(str(Reason.MANIFEST_DRIFT), drift=diff.summary(), drift_policy=policy)
            return
        if policy == "deny_risky":
            # Risky means: a mutating operation, or any change touching *this* tool.
            if operation in MUTATING_OPERATIONS or diff.affects(attempt.tool_name):
                verdict.deny(
                    str(Reason.MANIFEST_DRIFT),
                    drift=diff.summary(),
                    drift_policy=policy,
                    operation=str(operation),
                    note=(
                        "The upstream tool manifest changed after this contract was approved. "
                        "New tool descriptions or annotations never grant privilege; re-approval "
                        "is required."
                    ),
                )
                return
            verdict.evidence["manifest_check"] = f"drift present but not risky: {diff.summary()}"
            return
        verdict.note(str(Reason.MANIFEST_DRIFT), drift=diff.summary(), drift_policy=policy)

    # ------------------------------------------------------------------- stage 5

    def _stage_allowlist(self, attempt: ToolAttempt, verdict: _Verdict, contract: IntentContract) -> None:
        """Check the upstream server and tool name against the contract allowlists."""
        from mcp.shared.tool_name_validation import validate_tool_name

        result = validate_tool_name(attempt.tool_name)
        if not result.is_valid:
            verdict.deny(
                str(Reason.TOOL_NAME_INVALID),
                tool=attempt.tool_name,
                validation_warnings=result.warnings,
            )
            return

        if contract.allowed_servers and attempt.tool_server not in contract.allowed_servers:
            verdict.deny(
                str(Reason.SERVER_NOT_ALLOWED),
                server=attempt.tool_server,
                allowed_servers=contract.allowed_servers,
            )
            return

        if attempt.tool_name not in contract.allowed_tools:
            verdict.deny(
                str(Reason.TOOL_NOT_ALLOWED),
                tool=attempt.tool_name,
                allowed_tools=contract.allowed_tools,
            )
            return

        verdict.evidence["tool_allowlisted"] = attempt.tool_name

    # ------------------------------------------------------------------- stage 6

    def _stage_operation(self, attempt: ToolAttempt, verdict: _Verdict, contract: IntentContract) -> None:
        """Check the locally derived operation against denied and allowed operations."""
        operation = self.classify_operation(attempt.tool_name)
        attempt.operation = operation
        verdict.evidence["operation"] = str(operation)
        verdict.evidence["operation_source"] = "local configuration (not tool annotations)"

        if operation in contract.denied_actions:
            verdict.deny(
                str(Reason.OPERATION_DENIED),
                operation=str(operation),
                denied_actions=[str(op) for op in contract.denied_actions],
            )
            return

        if contract.allowed_operations and operation not in contract.allowed_operations:
            verdict.deny(
                str(Reason.OPERATION_NOT_ALLOWED),
                operation=str(operation),
                allowed_operations=[str(op) for op in contract.allowed_operations],
            )
            return

        if operation is Operation.UNKNOWN:
            verdict.deny(
                str(Reason.OPERATION_NOT_ALLOWED),
                operation="unknown",
                note="No local operation mapping exists for this tool, so it cannot be authorized.",
            )

    # ------------------------------------------------------------------- stage 7

    def _stage_resource(self, attempt: ToolAttempt, verdict: _Verdict, contract: IntentContract) -> None:
        """Canonicalize the target path and confirm it falls inside a declared scope."""
        spec = self.spec_for(attempt.tool_name)
        if spec is None or spec.resource_arg is None:
            verdict.evidence["resource_check"] = "tool declares no scoped resource argument"
            return

        raw = attempt.args.get(spec.resource_arg)
        if raw is None:
            if spec.requires_resource:
                verdict.deny(str(Reason.RESOURCE_MISSING), resource_arg=spec.resource_arg)
            else:
                verdict.evidence["resource_check"] = f"optional argument {spec.resource_arg!r} absent"
            return

        path_verdict = normalize_relative_path(raw if isinstance(raw, str) else str(raw))
        if not path_verdict.ok:
            verdict.deny(
                str(path_verdict.reason or Reason.RESOURCE_OUT_OF_SCOPE),
                raw_path=str(raw)[:256],
                path_detail=path_verdict.detail,
            )
            return

        normalized = path_verdict.normalized

        # Resolve through the real filesystem when a sandbox root is configured, so a
        # symlink that points outside the root is caught before the tool is forwarded.
        if self.sandbox_root is not None:
            resolved = resolve_in_root(self.sandbox_root, normalized)
            if not resolved.ok:
                verdict.deny(
                    str(resolved.reason or Reason.PATH_SYMLINK_ESCAPE),
                    raw_path=str(raw)[:256],
                    path_detail=resolved.detail,
                )
                return
            normalized = resolved.normalized

        attempt.target_resource = normalized
        matched = scope_for(normalized, contract.resource_scopes)
        if matched is None:
            verdict.deny(
                str(Reason.RESOURCE_OUT_OF_SCOPE),
                normalized_path=normalized,
                resource_scopes=contract.resource_scopes,
            )
            return

        verdict.evidence["resource"] = {"normalized_path": normalized, "matched_scope": matched}

    # ------------------------------------------------------------------- stage 8

    def _stage_destination(self, attempt: ToolAttempt, verdict: _Verdict, contract: IntentContract) -> None:
        """Normalize and allowlist the destination for egress-shaped tools."""
        spec = self.spec_for(attempt.tool_name)
        if spec is None or spec.destination_arg is None:
            return

        raw = attempt.args.get(spec.destination_arg)
        if raw is None:
            if spec.requires_destination:
                verdict.deny(str(Reason.DESTINATION_MISSING), destination_arg=spec.destination_arg)
            return

        dest = destination_allowed(raw if isinstance(raw, str) else str(raw), contract.allowed_destinations)
        attempt.destination = dest.normalized or str(raw)[:256]
        verdict.evidence["destination"] = {
            "raw": str(raw)[:256],
            "normalized": dest.normalized,
            "host": dest.host,
            "port": dest.port,
            "is_ip_literal": dest.is_ip_literal,
            "had_userinfo": dest.had_userinfo,
            "allowed_destinations": contract.allowed_destinations,
        }
        if not dest.ok:
            verdict.deny(
                str(dest.reason or Reason.DESTINATION_NOT_ALLOWED),
                destination_detail=dest.detail,
            )

    # ------------------------------------------------------------------- stage 9

    def _stage_budget(self, attempt: ToolAttempt, verdict: _Verdict, contract: IntentContract) -> None:
        """Atomically reserve budget. Only reached when the call is otherwise allowed."""
        operation = self.classify_operation(attempt.tool_name)
        is_write = operation in WRITE_BUDGET_OPERATIONS
        reserved, reason, usage = self.store.reserve_budget(
            contract.task_id,
            contract.policy_revision,
            max_calls=contract.max_calls,
            max_writes=contract.max_writes,
            is_write=is_write,
        )
        verdict.evidence["budget"] = usage
        if not reserved:
            verdict.deny(str(reason or Reason.CALL_BUDGET_EXCEEDED), budget=usage)
            return
        verdict.reserved_write = is_write
        verdict.reserved_call = True

    # ------------------------------------------------------------------ stage 10

    def _stage_approval_required(
        self, attempt: ToolAttempt, verdict: _Verdict, contract: IntentContract
    ) -> None:
        """Decide whether this call needs human review, and whether a grant already exists.

        Order matters here too: an existing matching grant is consumed *before* a new
        pending request is created, so an approved action proceeds rather than queuing
        a second time.
        """
        if attempt.tool_name not in contract.approval_rules:
            return

        grant = self.store.find_consumable_grant(
            attempt, policy_revision=contract.policy_revision, contract_hash=contract.contract_hash
        )
        if grant is not None:
            if not self.store.consume_grant(grant.approval_id):
                verdict.deny(str(Reason.APPROVAL_ALREADY_CONSUMED), approval_id=grant.approval_id)
                return
            verdict.approval_id = grant.approval_id
            verdict.note(
                str(Reason.APPROVAL_GRANTED),
                approval={
                    "approval_id": grant.approval_id,
                    "decided_by": grant.decided_by,
                    "args_digest": grant.args_digest,
                    "single_use": True,
                },
            )
            verdict.note(str(Reason.ALLOWED_AFTER_APPROVAL))
            return

        # No usable grant. Check whether one was explicitly declined for these exact args.
        declined = [
            row
            for row in self.store.list_approvals(state=str(ApprovalState.DECLINED), task_id=contract.task_id)
            if row.get("args_digest") == attempt.canonical_args_digest()
            and row.get("tool_name") == attempt.tool_name
            and row.get("policy_revision") == contract.policy_revision
        ]
        if declined:
            verdict.deny(
                str(Reason.APPROVAL_DECLINED),
                approval_id=declined[0].get("approval_id"),
                decided_by=declined[0].get("decided_by"),
            )
            return

        # The call is pausing, not proceeding: return any reservation the budget stage
        # took, so a queue of pending approvals cannot silently exhaust a budget.
        if verdict.reserved_call:
            self.store.release_budget(
                contract.task_id, contract.policy_revision, is_write=verdict.reserved_write
            )
            verdict.reserved_call = False
            verdict.reserved_write = False

        self._queue_approval(attempt, verdict, contract, reason=str(Reason.NEEDS_APPROVAL))

    def _queue_approval(
        self,
        attempt: ToolAttempt,
        verdict: _Verdict,
        contract: IntentContract,
        *,
        reason: str,
    ) -> None:
        """Create a pending approval and set the verdict to needs-approval."""
        pending = ApprovalGrant(
            attempt_id=attempt.attempt_id,
            task_id=contract.task_id,
            tool_name=attempt.tool_name,
            tool_server=attempt.tool_server,
            args_digest=attempt.canonical_args_digest(),
            raw_args_digest=attempt.raw_args_digest(),
            args_preview=_preview_args(attempt.args),
            policy_revision=contract.policy_revision,
            contract_hash=contract.contract_hash,
            expires_at=self.now() + _dt.timedelta(seconds=self.approval_ttl_s),
            operation=self.classify_operation(attempt.tool_name),
            target_resource=attempt.target_resource,
            reason_codes=[reason],
        )
        self.store.create_approval(pending)
        verdict.approval_id = pending.approval_id
        verdict.needs_approval(
            reason,
            approval={
                "approval_id": pending.approval_id,
                "expires_at": pending.expires_at.isoformat(),
                "args_digest": pending.args_digest,
                "bound_to": (
                    "task + policy_revision + tool + canonical args digest + raw args digest + nonce"
                ),
            },
        )

    # ------------------------------------------------------------------ stage 11

    def _stage_advisory(
        self, attempt: ToolAttempt, verdict: _Verdict, contract: IntentContract | None = None
    ) -> None:
        """Advisory heuristics. May escalate an allow to review; never overrides a deny.

        This function is only ever called when ``verdict.status is ALLOW`` (see
        :meth:`evaluate`), which is the structural guarantee that a probabilistic signal
        cannot weaken a deterministic decision.

        **Escalation is opt-in per contract.** Set
        ``risk_thresholds = {"advisory": "escalate"}`` and a call whose argument content
        resembles injected instructions is routed to human review instead of proceeding.
        The default is ``"annotate"``, which records the observation and changes nothing,
        because a probabilistic signal turning working tasks into approval prompts is a
        real cost that an operator should choose deliberately. An independent review
        correctly noted that the escalation half had been documented but not implemented.
        """
        if verdict.status is not DecisionStatus.ALLOW:
            return

        haystack_parts: list[str] = []
        for value in attempt.args.values():
            if isinstance(value, str):
                haystack_parts.append(value)
        haystack = "\n".join(haystack_parts)[:8192]

        hits = [pattern.pattern for pattern in _INJECTION_SHAPES if pattern.search(haystack)]
        if not hits:
            return

        mode = "annotate"
        if contract is not None:
            mode = str(contract.risk_thresholds.get("advisory", "annotate")).lower()
        escalate = mode == "escalate"

        verdict.evidence["advisory"] = {
            "matched_shapes": hits,
            "mode": mode,
            "effect": "escalated to human review" if escalate else "annotation only",
            "note": (
                "Advisory heuristics are not access control. This records that argument "
                "content resembled injected instructions. It can escalate an otherwise "
                "allowed call to human review when the contract opts in, and can never "
                "turn a deny into an allow."
            ),
        }
        verdict.note(str(Reason.HEURISTIC_SUSPICIOUS_CONTENT))

        if escalate and contract is not None:
            if verdict.reserved_call:
                self.store.release_budget(
                    contract.task_id, contract.policy_revision, is_write=verdict.reserved_write
                )
                verdict.reserved_call = False
                verdict.reserved_write = False
            self._queue_approval(attempt, verdict, contract, reason=str(Reason.HEURISTIC_ESCALATED))


#: Cross-script lookalikes that NFKC does not fold. Deliberately small and
#: Latin-targeted: the goal is audit fidelity on identity-shaped argument names, not a
#: general confusable-skeleton implementation. A spelling that still slips past gains no
#: authority -- nothing in the engine reads these values -- it is simply recorded as an
#: undeclared argument (AD-E005) instead of a spoofing attempt (AD-E011).
_HOMOGLYPH_FOLD: Final[dict[str, str]] = {
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0445": "x",
    "\u0443": "y",
    "\u0456": "i",
    "\u0458": "j",
    "\u04bb": "h",
    "\u03b1": "a",
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03c5": "u",
    "\u03b9": "i",
    "\u0501": "d",
    "\u051b": "q",
    "\u0261": "g",
    "\u1d04": "c",
    "\u0269": "i",
}


def _looks_like_identity_key(key: str) -> bool:
    """Does an argument name look like an attempt to assert authority?

    Compared after NFKC normalization with separators and non-alphanumerics stripped, so
    ``task_id``, ``Task-ID``, ``task\u2024id`` (one-dot leader) and fullwidth spellings all
    match. An independent review found the previous ASCII-only comparison let near-homoglyph
    spellings through: they gained no authority, because nothing in the engine reads those
    values, but they were recorded as a generic undeclared argument rather than as the
    spoofing attempt they are -- losing exactly the signal this stage exists to capture.
    """
    folded = unicodedata.normalize("NFKC", key).casefold()
    folded = "".join(_HOMOGLYPH_FOLD.get(ch, ch) for ch in folded)
    stripped = "".join(ch for ch in folded if ch.isalnum())
    return stripped in _IDENTITY_ARG_KEYS_FOLDED


def _preview_args(args: dict[str, Any]) -> dict[str, Any]:
    """A redacted, truncated argument preview for the approval inbox."""
    from .canonical import redact

    preview = redact(args)
    return preview if isinstance(preview, dict) else {"value": preview}


def _schema_mismatch(args: dict[str, Any], schema: dict[str, Any]) -> tuple[str, str] | None:
    """Validate arguments against an upstream tool's declared input schema.

    Returns ``(reason_code, detail)`` on a problem, or ``None``.

    Three checks, in order: required properties present, no *undeclared* properties, and
    declared types respected.

    **Undeclared properties are rejected by default**, which is stricter than JSON Schema,
    where ``additionalProperties`` defaults to permissive. The reasoning is specific to
    what this component is: a policy gateway decides whether to forward a call, and an
    argument the tool never declared is one whose effect on that tool is unknown to the
    policy. ``force: true`` or ``overwrite_scope: "**"`` alongside a legitimate path is
    exactly the shape of an argument-smuggling attempt, and the evaluation suite caught
    both sailing through before this check existed. A server that genuinely accepts free
    arguments can say so with ``additionalProperties: true`` (or a schema object), and
    then they are allowed through and the policy's resource and destination rules still
    apply to the ones it understands.
    """
    from .reasons import Reason

    if schema.get("type") not in (None, "object"):
        return None

    properties = schema.get("properties")
    properties = properties if isinstance(properties, dict) else {}

    for name in schema.get("required", []) or []:
        if name not in args:
            return str(Reason.SCHEMA_MISMATCH), f"missing required property {name!r}"

    additional = schema.get("additionalProperties", False)
    allow_undeclared = additional is True or isinstance(additional, dict)

    type_map: dict[str, tuple[type, ...]] = {
        "string": (str,),
        "integer": (int,),
        "number": (int, float),
        "boolean": (bool,),
        "array": (list,),
        "object": (dict,),
    }

    for name, value in args.items():
        declared = properties.get(name)
        if not isinstance(declared, dict):
            if allow_undeclared:
                continue
            if str(name).lower() in _IDENTITY_ARG_KEYS:
                # An identity-shaped argument is also undeclared, but reporting it as
                # merely "undeclared" would throw away the interesting part. Stage 2
                # rejects it as AD-E011 with the keys named, which is what a reviewer
                # needs to see: the agent tried to assert authority, not just pass a typo.
                # The call is denied either way; this only decides which finding is
                # recorded. Caught by the integration suite when the schema gate was added.
                continue
            return (
                str(Reason.UNDECLARED_ARGUMENT),
                f"argument {name!r} is not declared by the upstream tool's input schema "
                f"(declared: {sorted(properties)})",
            )
        expected = declared.get("type")
        if isinstance(expected, str) and expected in type_map:
            if expected in ("integer", "number") and isinstance(value, bool):
                return (
                    str(Reason.SCHEMA_MISMATCH),
                    f"property {name!r} expected {expected}, got boolean",
                )
            if not isinstance(value, type_map[expected]):
                return (
                    str(Reason.SCHEMA_MISMATCH),
                    f"property {name!r} expected {expected}, got {type(value).__name__}",
                )
    return None
