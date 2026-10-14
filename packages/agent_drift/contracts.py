"""Versioned schemas for intent contracts, tool attempts, decisions and approvals.

These are the interface every other module agrees on. Three invariants are enforced
here rather than being left to callers:

* **Task identity is host-owned.** :class:`ToolAttempt` carries ``task_id`` as an explicit
  field that the *gateway* fills from its launch-time binding. The model-supplied argument
  dictionary is stored separately in ``args`` and is never consulted for identity.
* **A contract is only trusted if it says where it came from.** ``source`` must be
  ``trusted_ui`` or ``trusted_config``; anything else fails validation, so a contract
  reconstructed from untrusted input cannot impersonate an approved one.
* **Hashes are evidence, not authentication.** ``contract_hash`` is a SHA-256 over the
  canonical form of the contract's semantic fields. It detects modification; it does not
  prove a human approved it. An optional HMAC chain (see :mod:`agent_drift.store`) adds
  tamper-evidence under a separately held key, and is defeated by host compromise.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .canonical import canonical_text, digest, digest_raw

__all__ = [
    "SCHEMA_VERSION",
    "ApprovalGrant",
    "ApprovalState",
    "ContractSource",
    "Decision",
    "DecisionStatus",
    "IntentContract",
    "Operation",
    "PolicyDecision",
    "RiskLevel",
    "ToolAttempt",
    "utcnow",
]

#: Schema version for every record persisted or returned by the API.
SCHEMA_VERSION = "2026-10-14.v1"


def utcnow() -> _dt.datetime:
    """Timezone-aware current UTC time. Never use naive datetimes in records."""
    return _dt.datetime.now(_dt.UTC)


class Operation(StrEnum):
    """The coarse action category a tool call performs.

    Derived from the tool's declared behaviour in the gateway's operation map -- never
    from a tool *description* or *annotation*, both of which are untrusted input. The
    2026-07-28 tools specification warns specifically that annotations are hints from a
    possibly untrusted server; Agent Drift therefore maps operations by configuration.
    """

    READ = "read"
    LIST = "list"
    WRITE = "write"
    DELETE = "delete"
    NETWORK_POST = "network_post"
    EXECUTE = "execute"
    UNKNOWN = "unknown"


class DecisionStatus(StrEnum):
    """Outcome of a policy evaluation."""

    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


class RiskLevel(StrEnum):
    """Advisory severity shown in the UI. Does not affect enforcement."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ContractSource(StrEnum):
    """Where a contract came from. Both values are inside the trust boundary."""

    TRUSTED_UI = "trusted_ui"
    TRUSTED_CONFIG = "trusted_config"


class ApprovalState(StrEnum):
    """Lifecycle of a pending approval."""

    PENDING = "pending"
    APPROVED = "approved"
    DECLINED = "declined"
    CONSUMED = "consumed"
    EXPIRED = "expired"


#: Operations that change state outside the agent. Used for risk classification and to
#: decide whether a failed forward may release its budget reservation.
MUTATING_OPERATIONS: frozenset[Operation] = frozenset(
    {Operation.WRITE, Operation.DELETE, Operation.NETWORK_POST, Operation.EXECUTE}
)

#: Operations that consume the contract's ``max_writes`` budget.
#:
#: Deliberately narrower than :data:`MUTATING_OPERATIONS`. ``max_writes`` exists to bound
#: *resource mutation* -- "you may edit at most two files" -- which is what CLAUDE.md
#: section 2 means by "excessive file mutations". Network egress is bounded by the
#: destination allowlist (default deny) and by ``max_calls``, not by the write budget:
#: charging a permitted POST against a file-write budget of zero would deny a task its
#: own approved purpose, which is exactly what the ``benign-approved-egress`` scenario
#: caught. See docs/DECISIONS.md D-011.
WRITE_BUDGET_OPERATIONS: frozenset[Operation] = frozenset({Operation.WRITE, Operation.DELETE})


class _Base(BaseModel):
    """Strict base: unknown fields are rejected, values are validated on assignment.

    ``extra="forbid"`` matters for security, not tidiness: it means a crafted payload
    cannot smuggle an unexpected authority field past validation and have it survive
    into a stored record.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True, frozen=False)


class IntentContract(_Base):
    """An immutable, user-approved statement of what a task is permitted to do.

    Created only through the trusted control plane (authenticated admin token) or trusted
    local config. Once stored it is never mutated: a change produces a new
    ``policy_revision`` and therefore a new ``contract_hash``, which invalidates every
    approval grant issued against the old revision.
    """

    schema_version: str = SCHEMA_VERSION
    id: str = Field(default_factory=lambda: f"ic_{uuid.uuid4().hex[:16]}")
    version: int = Field(default=1, ge=1)
    policy_revision: int = Field(default=1, ge=1)

    principal: str = Field(min_length=1, max_length=256, description="Who approved this task.")
    task_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    user_goal: str = Field(min_length=1, max_length=4096)

    issued_at: _dt.datetime = Field(default_factory=utcnow)
    expires_at: _dt.datetime | None = None
    approved_by: str = Field(min_length=1, max_length=256)
    source: ContractSource

    allowed_tools: list[str] = Field(default_factory=list)
    allowed_servers: list[str] = Field(default_factory=lambda: ["sandbox"])
    allowed_operations: list[Operation] = Field(default_factory=list)
    resource_scopes: list[str] = Field(default_factory=list)
    allowed_destinations: list[str] = Field(default_factory=list)
    denied_actions: list[Operation] = Field(default_factory=list)

    max_writes: int = Field(default=0, ge=0)
    max_calls: int = Field(default=100, ge=0)

    risk_thresholds: dict[str, str] = Field(default_factory=dict)
    approval_rules: list[str] = Field(
        default_factory=list,
        description="Tool names that always require human approval, even when otherwise allowed.",
    )

    manifest_fingerprint: str | None = Field(
        default=None,
        description="Fingerprint of the upstream tool manifest as it stood at approval time.",
    )
    manifest_drift_policy: Literal["deny_risky", "deny_all", "warn"] = "deny_risky"

    contract_hash: str = ""

    @field_validator("allowed_tools", "allowed_servers", "resource_scopes", "allowed_destinations")
    @classmethod
    def _no_blank_entries(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or not item.strip():
                raise ValueError("list entries must be non-empty")
        return value

    @field_validator("expires_at", "issued_at")
    @classmethod
    def _must_be_aware(cls, value: _dt.datetime | None) -> _dt.datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("datetimes must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _finalize(self) -> Self:
        """Derive the operation allowlist if omitted, then compute the contract hash."""
        if not self.allowed_operations and self.allowed_tools:
            # A contract that lists tools but no operations is read-shaped by default.
            object.__setattr__(self, "allowed_operations", [Operation.READ, Operation.LIST])
        computed = self.compute_hash()
        if self.contract_hash and self.contract_hash != computed:
            raise ValueError(
                "contract_hash does not match contract contents; refusing to construct a "
                "contract whose integrity identifier is inconsistent"
            )
        object.__setattr__(self, "contract_hash", computed)
        return self

    def semantic_fields(self) -> dict[str, Any]:
        """The fields the hash covers: everything that changes what is permitted.

        Deliberately excludes ``contract_hash`` itself and excludes ``id``, so that two
        contracts granting identical authority hash identically and a reviewer can see
        that an "updated" contract did not actually change any permission.
        """
        return {
            "schema_version": self.schema_version,
            "version": self.version,
            "policy_revision": self.policy_revision,
            "principal": self.principal,
            "task_id": self.task_id,
            "user_goal": self.user_goal,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "approved_by": self.approved_by,
            "source": str(self.source),
            "allowed_tools": sorted(self.allowed_tools),
            "allowed_servers": sorted(self.allowed_servers),
            "allowed_operations": sorted(str(op) for op in self.allowed_operations),
            "resource_scopes": sorted(self.resource_scopes),
            "allowed_destinations": sorted(self.allowed_destinations),
            "denied_actions": sorted(str(op) for op in self.denied_actions),
            "max_writes": self.max_writes,
            "max_calls": self.max_calls,
            "risk_thresholds": self.risk_thresholds,
            "approval_rules": sorted(self.approval_rules),
            "manifest_fingerprint": self.manifest_fingerprint,
            "manifest_drift_policy": self.manifest_drift_policy,
        }

    def compute_hash(self) -> str:
        """SHA-256 over the canonical form of :meth:`semantic_fields`."""
        return digest(self.semantic_fields())

    def canonical_text(self) -> str:
        """Canonical JSON text of the semantic fields, for display and receipts."""
        return canonical_text(self.semantic_fields())

    def is_expired(self, *, now: _dt.datetime | None = None) -> bool:
        """True when the contract has an expiry and it has passed."""
        if self.expires_at is None:
            return False
        return (now or utcnow()) >= self.expires_at

    def is_not_yet_valid(self, *, now: _dt.datetime | None = None) -> bool:
        """True when ``issued_at`` is in the future (clock skew or a staged contract)."""
        return (now or utcnow()) < self.issued_at


class ToolAttempt(_Base):
    """One observed attempt to invoke a tool, as the gateway saw it.

    ``task_id`` is filled by the gateway from its launch-time binding. ``args`` is the
    raw model-supplied argument object. The two are never allowed to influence each
    other: :class:`agent_drift.policy.PolicyEngine` rejects an attempt whose ``args``
    contain a task-identity-shaped key.
    """

    schema_version: str = SCHEMA_VERSION
    request_id: str = Field(default_factory=lambda: f"req_{uuid.uuid4().hex[:16]}")
    trace_id: str = Field(default_factory=lambda: f"tr_{uuid.uuid4().hex[:16]}")
    attempt_id: str = Field(default_factory=lambda: f"att_{uuid.uuid4().hex[:16]}")
    run_id: str = Field(default_factory=lambda: f"run_{uuid.uuid4().hex[:12]}")

    task_id: str | None = Field(
        default=None,
        description="Host-owned task binding. None means the gateway had no binding, which fails closed.",
    )
    tool_server: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=128)
    args: dict[str, Any] = Field(default_factory=dict)

    operation: Operation = Operation.UNKNOWN
    target_resource: str | None = None
    destination: str | None = None

    #: Optional reference to the untrusted content that preceded this attempt. Used by the
    #: dashboard to show "trusted goal vs untrusted trigger"; never used in enforcement.
    untrusted_context_ref: str | None = None

    timestamp: _dt.datetime = Field(default_factory=utcnow)

    def canonical_args_digest(self) -> str:
        """Digest of the arguments in canonical form.

        Covers the *whole* argument object, so approving ``{"path": "tmp/a.txt"}`` cannot
        authorize ``{"path": "tmp/a.txt", "force": true}``.

        Canonicalization deliberately folds away differences that are *not* semantic --
        key order, insignificant whitespace, unicode composition. The last of those is a
        hazard for filesystem arguments, where two compositions are two different files,
        so an approval binds :meth:`raw_args_digest` as well and both must match.
        """
        return digest(self.args)

    def raw_args_digest(self) -> str:
        """Digest of the arguments exactly as received, with no normalization at all.

        Byte-exact: key order is still sorted so a reordered-but-identical object matches,
        but no unicode normalization is applied. Together with
        :meth:`canonical_args_digest` this makes an approval bind the literal argument a
        reviewer saw, not merely something that canonicalizes to it.
        """
        return digest_raw(self.args)

    def redacted(self) -> dict[str, Any]:
        """A representation safe to persist and display."""
        from .canonical import redact

        return {
            "attempt_id": self.attempt_id,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "tool_server": self.tool_server,
            "tool_name": self.tool_name,
            "args": redact(self.args),
            "args_digest": self.canonical_args_digest(),
            "operation": str(self.operation),
            "target_resource": self.target_resource,
            "destination": self.destination,
            "untrusted_context_ref": self.untrusted_context_ref,
            "timestamp": self.timestamp.isoformat(),
        }


class PolicyDecision(_Base):
    """The result of evaluating one :class:`ToolAttempt` against one contract."""

    schema_version: str = SCHEMA_VERSION
    decision_id: str = Field(default_factory=lambda: f"dec_{uuid.uuid4().hex[:16]}")
    attempt_id: str
    task_id: str | None
    status: DecisionStatus

    #: Denormalized from the attempt so a decision record is self-describing: the
    #: dashboard and any exported receipt can name the tool without a second lookup.
    tool_name: str | None = None
    tool_server: str | None = None
    operation: str | None = None
    target_resource: str | None = None
    destination: str | None = None

    reason_codes: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    risk: RiskLevel = RiskLevel.LOW

    contract_hash: str | None = None
    contract_version: int | None = None
    policy_revision: int | None = None

    elapsed_ms: float = 0.0

    #: True when the denial is returned to the agent as a tool-execution error (see D-006).
    denial_forwarded_to_agent: bool = True

    #: Set when a reviewer acted. Carries who and when, never their credentials.
    reviewer: dict[str, Any] | None = None

    #: Set once the gateway knows whether the upstream tool actually ran.
    upstream_executed: bool = False
    upstream_error: str | None = None

    approval_id: str | None = None
    timestamp: _dt.datetime = Field(default_factory=utcnow)

    @property
    def allowed(self) -> bool:
        """True only for a terminal allow."""
        return self.status is DecisionStatus.ALLOW

    def primary_reason(self) -> str:
        """First reason code, or a sentinel when none was recorded."""
        return self.reason_codes[0] if self.reason_codes else "AD-E999"


class ApprovalGrant(_Base):
    """A single-use human authorization bound to exact arguments.

    The key is ``(task_id, policy_revision, tool_name, args_digest, nonce)``. It
    deliberately excludes the JSON-RPC request id: the 2026-07-28 revision removed SSE
    resumability and requires a *new* request id when a stream breaks and a request is
    re-issued, so a grant keyed on request id would be wrong by construction.
    """

    schema_version: str = SCHEMA_VERSION
    approval_id: str = Field(default_factory=lambda: f"apr_{uuid.uuid4().hex[:16]}")
    attempt_id: str
    task_id: str
    tool_name: str
    tool_server: str
    args_digest: str
    #: Digest of the un-normalized arguments. Empty on grants created before this field
    #: existed, in which case the canonical digest alone is checked and a warning is
    #: recorded -- an old grant is not silently treated as satisfying a stronger binding.
    raw_args_digest: str = ""
    args_preview: dict[str, Any] = Field(default_factory=dict)
    policy_revision: int
    contract_hash: str

    nonce: str = Field(default_factory=lambda: uuid.uuid4().hex)
    state: ApprovalState = ApprovalState.PENDING
    created_at: _dt.datetime = Field(default_factory=utcnow)
    expires_at: _dt.datetime
    decided_at: _dt.datetime | None = None
    decided_by: str | None = None
    consumed_at: _dt.datetime | None = None

    operation: Operation = Operation.UNKNOWN
    target_resource: str | None = None
    reason_codes: list[str] = Field(default_factory=list)

    def is_expired(self, *, now: _dt.datetime | None = None) -> bool:
        """True when the grant's TTL has elapsed."""
        return (now or utcnow()) >= self.expires_at

    def matches(self, attempt: ToolAttempt, *, policy_revision: int, contract_hash: str) -> bool:
        """Exact-match predicate used before consuming a grant.

        Tool name, server, canonical args digest, raw args digest, task and contract
        revision must all agree, and the contract hash must be unchanged. Any mismatch
        means the thing the reviewer approved is not the thing about to execute.
        """
        if self.raw_args_digest and self.raw_args_digest != attempt.raw_args_digest():
            # Canonically identical but not byte-identical: two unicode spellings of one
            # visible filename are two different files, and the reviewer approved one.
            return False
        return (
            self.tool_name == attempt.tool_name
            and self.tool_server == attempt.tool_server
            and self.args_digest == attempt.canonical_args_digest()
            and self.task_id == attempt.task_id
            and self.policy_revision == policy_revision
            and self.contract_hash == contract_hash
        )


class Decision(_Base):
    """Public, typed result returned by :meth:`agent_drift.sdk.DriftGuard.evaluate`.

    Note the deliberate narrowness: this is the *evaluation* result. Receiving
    ``status == "allow"`` from the SDK does not mean anything was enforced -- the caller
    is the one that decides whether to run the tool. Enforcement only happens when calls
    traverse the MCP gateway. This is stated again in the SDK docstring and in
    ``docs/INTEGRATION.md`` because conflating the two would be a security error.
    """

    status: DecisionStatus
    reason_codes: list[str]
    rule_ids: list[str]
    policy_revision: int | None
    attempt_id: str
    resource: str | None
    destination: str | None = None
    risk: RiskLevel = RiskLevel.LOW
    elapsed_ms: float = 0.0
    contract_hash: str | None = None
    explanations: list[str] = Field(default_factory=list)

    @property
    def is_enforcement(self) -> Literal[False]:
        """Always ``False``: the SDK evaluates, the gateway enforces."""
        return False
