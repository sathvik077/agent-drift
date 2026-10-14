"""Tool manifest fingerprinting and drift classification.

The threat this addresses is the one Microsoft's own MCP guidance names and does not
answer: a **rug pull**, where a tool the user approved changes afterwards. The 2026-07-28
tools specification also warns that tool *annotations* are hints from a possibly
untrusted server. Agent Drift therefore treats the entire effective tool manifest --
name, title, description, input schema, output schema and annotations -- as data to be
fingerprinted at approval time and compared on every subsequent call.

Design points worth stating explicitly:

* **New annotations never grant privilege.** A server that flips ``read_only_hint`` to
  ``true`` does not thereby make a write tool safe. Operations are mapped by local
  configuration (see :data:`agent_drift.policy.DEFAULT_OPERATION_MAP`), not by annotation.
* **Drift is classified, not merely detected.** A changed description is a different
  thing from a changed input schema, and a brand-new tool is different again. The
  contract's ``manifest_drift_policy`` decides what each class does.
* **A missing pin is not a pass.** If no fingerprint was pinned for a task, risky
  operations are denied with ``AD-E032`` rather than allowed on trust.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from .canonical import digest

__all__ = [
    "ManifestDiff",
    "ManifestFingerprint",
    "ToolFingerprint",
    "diff_manifests",
    "fingerprint_tools",
]

DriftClass = Literal[
    "none", "description_only", "schema_changed", "annotations_changed", "tool_added", "tool_removed"
]


@dataclass(frozen=True, slots=True)
class ToolFingerprint:
    """Fingerprint of one tool definition."""

    name: str
    schema_digest: str
    description_digest: str
    annotations_digest: str
    full_digest: str

    def to_dict(self) -> dict[str, str]:
        """Serializable form, stored alongside the contract."""
        return {
            "name": self.name,
            "schema_digest": self.schema_digest,
            "description_digest": self.description_digest,
            "annotations_digest": self.annotations_digest,
            "full_digest": self.full_digest,
        }


@dataclass(frozen=True, slots=True)
class ManifestFingerprint:
    """Fingerprint of an entire upstream tool manifest."""

    server: str
    tools: dict[str, ToolFingerprint]
    manifest_digest: str
    cache_scope: str | None = None
    ttl_ms: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serializable form."""
        return {
            "server": self.server,
            "manifest_digest": self.manifest_digest,
            "cache_scope": self.cache_scope,
            "ttl_ms": self.ttl_ms,
            "tools": {name: fp.to_dict() for name, fp in sorted(self.tools.items())},
        }

    def is_cacheable_across_tasks(self) -> bool:
        """False when the upstream marked the list private.

        2026-07-28 added ``cacheScope`` to list results specifically to tell shared
        intermediaries whether they may cache. A gateway is a shared intermediary, so a
        ``private`` list is never reused across task bindings (decision D-010).
        """
        return self.cache_scope != "private"


@dataclass(slots=True)
class ManifestDiff:
    """Difference between a pinned manifest and the one observed now."""

    changed: bool
    drift_classes: set[DriftClass] = field(default_factory=set)
    added_tools: list[str] = field(default_factory=list)
    removed_tools: list[str] = field(default_factory=list)
    changed_tools: dict[str, list[str]] = field(default_factory=dict)

    def summary(self) -> str:
        """One-line human summary for the dashboard and logs."""
        if not self.changed:
            return "manifest unchanged"
        bits: list[str] = []
        if self.added_tools:
            bits.append(f"added {', '.join(sorted(self.added_tools))}")
        if self.removed_tools:
            bits.append(f"removed {', '.join(sorted(self.removed_tools))}")
        for tool, fields in sorted(self.changed_tools.items()):
            bits.append(f"{tool} changed ({', '.join(sorted(fields))})")
        return "; ".join(bits)

    def affects(self, tool_name: str) -> bool:
        """Did the drift touch this specific tool?"""
        return (
            tool_name in self.changed_tools
            or tool_name in self.added_tools
            or tool_name in self.removed_tools
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializable form recorded in decision evidence."""
        return {
            "changed": self.changed,
            "drift_classes": sorted(self.drift_classes),
            "added_tools": sorted(self.added_tools),
            "removed_tools": sorted(self.removed_tools),
            "changed_tools": {k: sorted(v) for k, v in sorted(self.changed_tools.items())},
            "summary": self.summary(),
        }


def _tool_to_parts(tool: Any) -> tuple[str, Any, Any, Any]:
    """Extract (name, schema, description, annotations) from an SDK Tool or a dict.

    Accepting both keeps this function usable from tests and from the eval harness
    without constructing SDK objects, and keeps the fingerprint definition in one place.
    """
    if isinstance(tool, dict):
        name = str(tool.get("name", ""))
        schema = tool.get("input_schema", tool.get("inputSchema"))
        description = tool.get("description")
        annotations = tool.get("annotations")
        output_schema = tool.get("output_schema", tool.get("outputSchema"))
        title = tool.get("title")
    else:
        name = str(getattr(tool, "name", ""))
        schema = getattr(tool, "input_schema", None)
        description = getattr(tool, "description", None)
        annotations = getattr(tool, "annotations", None)
        output_schema = getattr(tool, "output_schema", None)
        title = getattr(tool, "title", None)

    if annotations is not None and not isinstance(annotations, dict):
        dump = getattr(annotations, "model_dump", None)
        annotations = dump(mode="json", exclude_none=True) if callable(dump) else str(annotations)

    # Title and output schema are folded into the schema component: a changed output
    # contract is a schema change, and a changed title is cosmetic but still recorded.
    schema_component = {"input_schema": schema, "output_schema": output_schema, "title": title}
    return name, schema_component, description, annotations


def fingerprint_tools(
    server: str,
    tools: list[Any],
    *,
    cache_scope: str | None = None,
    ttl_ms: int | None = None,
) -> ManifestFingerprint:
    """Fingerprint a list of tool definitions from one upstream server."""
    fingerprints: dict[str, ToolFingerprint] = {}
    for tool in tools:
        name, schema_component, description, annotations = _tool_to_parts(tool)
        if not name:
            continue
        schema_digest = digest(schema_component)
        description_digest = digest(description)
        annotations_digest = digest(annotations)
        fingerprints[name] = ToolFingerprint(
            name=name,
            schema_digest=schema_digest,
            description_digest=description_digest,
            annotations_digest=annotations_digest,
            full_digest=digest(
                {
                    "name": name,
                    "schema": schema_digest,
                    "description": description_digest,
                    "annotations": annotations_digest,
                }
            ),
        )

    manifest_digest = digest(
        {
            "server": server,
            "tools": {name: fp.full_digest for name, fp in sorted(fingerprints.items())},
        }
    )
    return ManifestFingerprint(
        server=server,
        tools=fingerprints,
        manifest_digest=manifest_digest,
        cache_scope=cache_scope,
        ttl_ms=ttl_ms,
    )


def diff_manifests(pinned: dict[str, Any] | None, observed: ManifestFingerprint) -> ManifestDiff:
    """Compare a stored manifest fingerprint dict against a freshly observed one.

    ``pinned`` is the ``to_dict()`` form persisted with the contract. ``None`` means
    nothing was pinned, which is reported as ``changed=True`` with class
    ``tool_added`` for every observed tool, so the caller must decide explicitly rather
    than defaulting to trust.
    """
    if pinned is None:
        return ManifestDiff(
            changed=True,
            drift_classes={"tool_added"},
            added_tools=sorted(observed.tools),
        )

    pinned_tools: dict[str, dict[str, str]] = pinned.get("tools", {}) or {}
    if pinned.get("manifest_digest") == observed.manifest_digest:
        return ManifestDiff(changed=False)

    diff = ManifestDiff(changed=True)
    pinned_names = set(pinned_tools)
    observed_names = set(observed.tools)

    for name in sorted(observed_names - pinned_names):
        diff.added_tools.append(name)
        diff.drift_classes.add("tool_added")
    for name in sorted(pinned_names - observed_names):
        diff.removed_tools.append(name)
        diff.drift_classes.add("tool_removed")

    for name in sorted(pinned_names & observed_names):
        before = pinned_tools[name]
        after = observed.tools[name]
        changed_fields: list[str] = []
        if before.get("schema_digest") != after.schema_digest:
            changed_fields.append("input_schema")
            diff.drift_classes.add("schema_changed")
        if before.get("description_digest") != after.description_digest:
            changed_fields.append("description")
            diff.drift_classes.add("description_only")
        if before.get("annotations_digest") != after.annotations_digest:
            changed_fields.append("annotations")
            diff.drift_classes.add("annotations_changed")
        if changed_fields:
            diff.changed_tools[name] = changed_fields

    if not diff.drift_classes:
        # Digests differ but no per-tool component did: server metadata changed.
        diff.drift_classes.add("description_only")

    return diff
