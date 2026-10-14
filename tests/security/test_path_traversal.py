"""Path traversal and path-confusion regressions (AD-21).

Every case here is a real technique for getting a path check to disagree with the
filesystem. The suite is parameterized so adding a new technique is one line, and each
case asserts both that the normalizer rejects it *and* that the fixture tool rejects it
at the moment of use -- the two places where disagreement would be exploitable.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from agent_drift.contracts import ContractSource, DecisionStatus, IntentContract, Operation, ToolAttempt
from agent_drift.paths import matches_scope, normalize_relative_path, resolve_in_root
from agent_drift.reasons import Reason

#: Paths that climb above the sandbox root, or are otherwise malformed. The normalizer
#: must reject these outright: there is no root-relative reading of them.
#: (description, raw path, expected reason code)
TRAVERSAL_CASES: list[tuple[str, str, str]] = [
    ("leading parent", "../etc/passwd", Reason.PATH_TRAVERSAL),
    ("parent only", "..", Reason.PATH_TRAVERSAL),
    ("backslash parent", "..\\..\\windows\\system32", Reason.PATH_TRAVERSAL),
    ("climbs past the root", "sandbox-repo/a/../../../outside", Reason.PATH_TRAVERSAL),
    ("percent encoded climb", "%2e%2e/%2e%2e/etc/passwd", Reason.PATH_TRAVERSAL),
    ("double encoded climb", "%252e%252e/%252e%252e/etc/passwd", Reason.PATH_TRAVERSAL),
    ("encoded separator climb", "sandbox-repo%2f..%2f..%2f..%2fetc", Reason.PATH_TRAVERSAL),
    ("absolute posix", "/etc/passwd", Reason.PATH_ABSOLUTE),
    ("absolute with dots", "/../etc/passwd", Reason.PATH_ABSOLUTE),
    ("windows drive", "C:\\Windows\\System32\\config", Reason.PATH_ABSOLUTE),
    ("windows drive forward", "C:/Windows/System32", Reason.PATH_ABSOLUTE),
    ("unc path", "\\\\server\\share\\secret", Reason.PATH_ABSOLUTE),
    ("null byte", "sandbox-repo/README.md\x00.txt", Reason.PATH_UNSAFE_ENCODING),
    ("newline", "sandbox-repo/a\nb", Reason.PATH_UNSAFE_ENCODING),
    ("tab", "sandbox-repo/a\tb", Reason.PATH_UNSAFE_ENCODING),
    ("zero width space", "sandbox-repo/doc\u200bs/a.md", Reason.PATH_UNSAFE_ENCODING),
    ("zero width joiner", "sandbox-repo/doc\u200ds/a.md", Reason.PATH_UNSAFE_ENCODING),
    ("bidi override", "sandbox-repo/\u202ecod.md", Reason.PATH_UNSAFE_ENCODING),
    ("byte order mark", "sandbox-repo/\ufeffa.md", Reason.PATH_UNSAFE_ENCODING),
    ("fullwidth dot", "sandbox-repo/\uff0e\uff0e/escape", Reason.PATH_UNSAFE_ENCODING),
    ("ideographic dot", "sandbox-repo/\u3002\u3002/escape", Reason.PATH_UNSAFE_ENCODING),
    ("fullwidth solidus", "sandbox-repo\uff0f..\uff0fescape", Reason.PATH_UNSAFE_ENCODING),
    ("division slash", "sandbox-repo\u2215..\u2215escape", Reason.PATH_UNSAFE_ENCODING),
    ("empty", "", Reason.RESOURCE_MISSING),
    ("root only", ".", Reason.RESOURCE_MISSING),
    ("collapses to nothing", "sandbox-repo/..", Reason.RESOURCE_MISSING),
    ("slashes only", "///", Reason.PATH_ABSOLUTE),
]

#: Paths that *stay inside* the sandbox root once ``..`` is collapsed, but land outside
#: the scope a contract granted. The normalizer accepts them -- collapsing is the correct
#: reading, and rejecting ``docs/../docs/x`` was a false block the evaluation suite caught
#: -- and the **scope rule** is what denies them. The outcome is still a denial; only the
#: reason code differs, and the more specific code is the more useful one for a reviewer.
WITHIN_ROOT_OUT_OF_SCOPE: list[tuple[str, str, str]] = [
    ("climbs out of docs into private", "sandbox-repo/docs/../../private/secret.txt", "private/secret.txt"),
    ("climbs out of docs into src", "sandbox-repo/docs/../src/payment.py", "sandbox-repo/src/payment.py"),
    ("deep climb staying in root", "sandbox-repo/docs/subdir/../../../outside.md", "outside.md"),
    ("sibling via parent", "sandbox-repo/docs/../issues/1-exfil.md", "sandbox-repo/issues/1-exfil.md"),
]

#: Paths that are legitimate and must be accepted. A traversal check that rejects these
#: is a false block, which is as much a defect as a bypass.
BENIGN_CASES: list[tuple[str, str]] = [
    ("simple file", "sandbox-repo/README.md"),
    ("nested", "sandbox-repo/docs/guide/intro.md"),
    ("dots in a name", "sandbox-repo/..hidden/file.txt"),
    ("double dots inside a name", "sandbox-repo/a..b/file.txt"),
    ("dot prefix", "sandbox-repo/.config"),
    ("trailing dot segment resolved", "sandbox-repo/./docs/README.md"),
    ("redundant slashes", "sandbox-repo//docs///README.md"),
    ("unicode filename", "sandbox-repo/docs/café.md"),
    ("space in name", "sandbox-repo/docs/my notes.md"),
]


class TestNormalizer:
    """Rejections and acceptances at the string level."""

    @pytest.mark.parametrize(
        ("label", "raw", "expected"), TRAVERSAL_CASES, ids=[c[0] for c in TRAVERSAL_CASES]
    )
    def test_hostile_path_is_rejected(self, label: str, raw: str, expected: str) -> None:
        verdict = normalize_relative_path(raw)
        assert verdict.ok is False, f"{label}: {raw!r} was accepted as {verdict.normalized!r}"
        assert verdict.reason == expected, f"{label}: expected {expected}, got {verdict.reason}"

    @pytest.mark.parametrize(
        ("label", "raw", "expected"),
        WITHIN_ROOT_OUT_OF_SCOPE,
        ids=[c[0] for c in WITHIN_ROOT_OUT_OF_SCOPE],
    )
    def test_within_root_path_collapses_rather_than_being_rejected(
        self, label: str, raw: str, expected: str
    ) -> None:
        """``..`` is collapsed; containment, not the presence of ``..``, is the rule."""
        verdict = normalize_relative_path(raw)
        assert verdict.ok is True, f"{label}: {raw!r} was rejected ({verdict.detail})"
        assert verdict.normalized == expected
        assert ".." not in verdict.normalized.split("/")

    @pytest.mark.parametrize(("label", "raw"), BENIGN_CASES, ids=[c[0] for c in BENIGN_CASES])
    def test_benign_path_is_accepted(self, label: str, raw: str) -> None:
        verdict = normalize_relative_path(raw)
        assert verdict.ok is True, f"{label}: {raw!r} was wrongly rejected ({verdict.detail})"
        assert ".." not in verdict.normalized.split("/")
        assert not verdict.normalized.startswith("/")

    def test_non_string_input_is_rejected(self) -> None:
        assert normalize_relative_path(None).ok is False  # type: ignore[arg-type]

    def test_normalized_output_is_idempotent(self) -> None:
        once = normalize_relative_path("sandbox-repo//docs///README.md").normalized
        assert normalize_relative_path(once).normalized == once


class TestSymlinkEscape:
    """resolve_in_root must follow links and compare real paths."""

    def test_symlink_pointing_outside_is_rejected(self, tmp_path: Path) -> None:
        root = tmp_path / "workspace"
        (root / "sandbox-repo").mkdir(parents=True)
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("sensitive")
        (root / "sandbox-repo" / "link").symlink_to(outside, target_is_directory=True)

        verdict = resolve_in_root(root, "sandbox-repo/link/secret.txt")
        assert verdict.ok is False
        assert verdict.reason == Reason.PATH_SYMLINK_ESCAPE

    def test_symlink_inside_the_root_is_allowed(self, tmp_path: Path) -> None:
        root = tmp_path / "workspace"
        (root / "sandbox-repo" / "docs").mkdir(parents=True)
        (root / "sandbox-repo" / "docs" / "real.md").write_text("ok")
        (root / "sandbox-repo" / "alias").symlink_to(root / "sandbox-repo" / "docs", target_is_directory=True)
        verdict = resolve_in_root(root, "sandbox-repo/alias/real.md")
        assert verdict.ok is True

    def test_symlink_loop_is_rejected_not_hung(self, tmp_path: Path) -> None:
        root = tmp_path / "workspace"
        root.mkdir(parents=True)
        (root / "a").symlink_to(root / "b")
        (root / "b").symlink_to(root / "a")
        verdict = resolve_in_root(root, "a/file.txt")
        assert verdict.ok is False

    def test_resolving_to_the_root_itself_is_rejected(self, tmp_path: Path) -> None:
        root = tmp_path / "workspace"
        root.mkdir(parents=True)
        assert resolve_in_root(root, "./").ok is False


class TestScopeMatching:
    """Scope globs must not let a single star cross a directory boundary."""

    @pytest.mark.parametrize(
        ("path", "scope", "expected"),
        [
            ("sandbox-repo/docs/README.md", "sandbox-repo/docs/**", True),
            ("sandbox-repo/docs/a/b/c.md", "sandbox-repo/docs/**", True),
            ("sandbox-repo/src/payment.py", "sandbox-repo/docs/**", False),
            ("sandbox-repo/docsx/a.md", "sandbox-repo/docs/**", False),
            ("sandbox-repo/docs/a.md", "sandbox-repo/docs/*", True),
            ("sandbox-repo/docs/a/b.md", "sandbox-repo/docs/*", False),
            ("sandbox-repo/README.md", "sandbox-repo/**", True),
            ("other/README.md", "sandbox-repo/**", False),
            ("anything/at/all", "**", True),
            ("sandbox-repo/docs", "sandbox-repo/docs/**", True),
        ],
    )
    def test_scope_matching(self, path: str, scope: str, expected: bool) -> None:
        assert matches_scope(path, scope) is expected

    def test_empty_scope_matches_nothing(self) -> None:
        assert matches_scope("anything", "") is False

    def test_prefix_similarity_does_not_match(self) -> None:
        """'docs' must not admit 'docs-internal'."""
        assert matches_scope("sandbox-repo/docs-internal/secret.md", "sandbox-repo/docs") is False


class TestPolicyRejectsTraversal:
    """The engine must deny these, not merely the normalizer."""

    @pytest.fixture
    def contract(self, store) -> IntentContract:
        contract = IntentContract(
            principal="dev",
            task_id="t",
            user_goal="g",
            approved_by="dev",
            source=ContractSource.TRUSTED_CONFIG,
            allowed_tools=["repo.read_file", "repo.write_file"],
            allowed_operations=[Operation.READ, Operation.WRITE],
            resource_scopes=["sandbox-repo/**"],
            max_writes=5,
            max_calls=50,
        )
        store.put_contract(contract)
        return contract

    @pytest.mark.parametrize(
        ("label", "raw", "expected"), TRAVERSAL_CASES, ids=[c[0] for c in TRAVERSAL_CASES]
    )
    def test_engine_denies_hostile_path(
        self, engine, contract: IntentContract, label: str, raw: str, expected: str
    ) -> None:
        attempt = ToolAttempt(tool_server="sandbox", tool_name="repo.read_file", args={"path": raw})
        decision = engine.evaluate(attempt, bound_task_id="t")
        assert decision.status is DecisionStatus.DENY, f"{label}: {raw!r} was allowed"
        assert expected in decision.reason_codes

    @pytest.mark.parametrize(
        ("label", "raw", "_normalized"),
        WITHIN_ROOT_OUT_OF_SCOPE,
        ids=[c[0] for c in WITHIN_ROOT_OUT_OF_SCOPE],
    )
    def test_engine_denies_within_root_paths_that_leave_the_scope(
        self, engine, store, label: str, raw: str, _normalized: str
    ) -> None:
        """A path that collapses inside the root but outside the granted scope is denied
        by the scope rule, with the specific reason a reviewer needs."""
        narrow = IntentContract(
            principal="dev",
            task_id="t-narrow",
            user_goal="g",
            approved_by="dev",
            source=ContractSource.TRUSTED_CONFIG,
            allowed_tools=["repo.read_file", "repo.write_file"],
            allowed_operations=[Operation.READ, Operation.WRITE],
            resource_scopes=["sandbox-repo/docs/**"],
            max_writes=5,
            max_calls=50,
        )
        store.put_contract(narrow)
        attempt = ToolAttempt(
            tool_server="sandbox", tool_name="repo.write_file", args={"path": raw, "content": "x"}
        )
        decision = engine.evaluate(attempt, bound_task_id="t-narrow")
        assert decision.status is DecisionStatus.DENY, f"{label}: {raw!r} was allowed"
        assert str(Reason.RESOURCE_OUT_OF_SCOPE) in decision.reason_codes, decision.reason_codes

    def test_engine_consumes_no_budget_on_a_denied_path(self, engine, contract, store) -> None:
        attempt = ToolAttempt(
            tool_server="sandbox",
            tool_name="repo.write_file",
            args={"path": "../escape", "content": "x"},
        )
        engine.evaluate(attempt, bound_task_id="t")
        assert store.get_budget("t", contract.policy_revision)["writes_used"] == 0


class TestFixtureRejectsTraversalAtUse:
    """The controlled fixture re-validates at the moment of use, closing the TOCTOU gap."""

    @pytest.fixture
    def fixture_module(self, fixture_state: Path):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "examples" / "upstream_mcp"))
        import importlib

        module = importlib.import_module("server")
        importlib.reload(module)
        module.state_dir().mkdir(parents=True, exist_ok=True)
        module.seed_sandbox(force=True)
        return module

    @pytest.mark.parametrize(
        "raw",
        [
            "sandbox-repo/../../../etc/passwd",
            "/etc/passwd",
            "../counters.json",
            "..\\..\\escape",
            "%2e%2e/%2e%2e/escape",
        ],
    )
    def test_read_file_rejects_escape_at_use(self, fixture_module, raw: str) -> None:
        with pytest.raises(ValueError, match="rejected by fixture sandbox"):
            fixture_module.repo_read_file(raw)

    def test_write_cannot_reach_the_counter_file(self, fixture_module) -> None:
        """The oracle itself must be unreachable from a tool, even by a valid-looking path."""
        with pytest.raises(ValueError, match="rejected by fixture sandbox"):
            fixture_module.repo_write_file("../counters.json", "{}")
        assert fixture_module.counters_path().is_file()

    def test_counter_file_lives_outside_the_workspace(self, fixture_module) -> None:
        counters = str(fixture_module.counters_path())
        workspace = str(fixture_module.workspace_root())
        assert not counters.startswith(workspace + os.sep)
