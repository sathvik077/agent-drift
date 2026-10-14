"""Agent Drift: runtime intent integrity for MCP agents.

Agent Drift interposes on real MCP ``tools/call`` traffic and evaluates every call
against an explicit, user-approved **intent contract** for one specific task. Calls that
fall outside the contract are denied *before* they reach the tool, and every decision is
recorded as a replayable receipt.

Public surface:

* :class:`~agent_drift.contracts.IntentContract` -- what a task is permitted to do
* :class:`~agent_drift.contracts.ToolAttempt` -- one observed attempt
* :class:`~agent_drift.contracts.PolicyDecision` -- the recorded decision
* :class:`~agent_drift.policy.PolicyEngine` -- the deterministic evaluator
* :class:`~agent_drift.gateway.Gateway` -- the MCP stdio proxy that enforces
* :class:`~agent_drift.sdk.DriftGuard` -- advisory evaluation for non-MCP frameworks

What Agent Drift does **not** do is as important as what it does; see
``docs/THREAT_MODEL.md``. In short: it can only see calls that traverse it, it offers no
formal guarantee, and ``DriftGuard`` evaluates rather than enforces.
"""

from __future__ import annotations

from .contracts import (
    ApprovalGrant,
    ContractSource,
    Decision,
    DecisionStatus,
    IntentContract,
    Operation,
    PolicyDecision,
    RiskLevel,
    ToolAttempt,
)
from .policy import PolicyEngine, ToolSpec
from .reasons import Reason, explain, rule_for
from .sdk import DriftGuard, PolicyViolation
from .store import Store, StoreUnavailable

__version__ = "0.1.0"

#: MCP protocol revision this gateway is built and tested against.
MCP_PROTOCOL_REVISION = "2026-07-28"

#: MCP Python SDK version pinned in ``pyproject.toml`` and verified at runtime.
MCP_SDK_VERSION = "2.2.0"

__all__ = [
    "MCP_PROTOCOL_REVISION",
    "MCP_SDK_VERSION",
    "ApprovalGrant",
    "ContractSource",
    "Decision",
    "DecisionStatus",
    "DriftGuard",
    "IntentContract",
    "Operation",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyViolation",
    "Reason",
    "RiskLevel",
    "Store",
    "StoreUnavailable",
    "ToolAttempt",
    "ToolSpec",
    "__version__",
    "explain",
    "rule_for",
]
