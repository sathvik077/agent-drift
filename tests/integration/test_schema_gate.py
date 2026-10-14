"""The schema gate: undeclared and ill-typed arguments are refused before forwarding.

Also guards against the evaluation harness's copy of the fixture schemas going stale,
which would make the benchmark measure something the gateway does not do.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_drift.seed import build_contract
from agent_drift.store import Store

from .harness import decision_of, direct_upstream, gateway_client, reason_codes

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


@pytest.fixture
def anyio_backend() -> str:
    """Run the async tests on asyncio."""
    return "asyncio"


def seed(db_path: Path, name: str) -> Path:
    """Register one seed contract."""
    store = Store(db_path)
    try:
        store.put_contract(build_contract(name))
    finally:
        store.close()
    return db_path


class TestEvalSchemasAreCurrent:
    """The benchmark's schema copies must match what the fixture advertises."""

    async def test_fixture_schemas_match_the_eval_copies(self, fixture_state: Path) -> None:
        import sys

        repo_root = Path(__file__).resolve().parent.parent.parent
        sys.path.insert(0, str(repo_root / "evals"))
        from baselines import FIXTURE_SCHEMAS  # type: ignore[import-not-found]

        async with direct_upstream(fixture_state) as upstream:
            live = {tool.name: tool.input_schema for tool in (await upstream.list_tools()).tools}

        assert set(live) == set(FIXTURE_SCHEMAS), (
            "the fixture's tool set has changed; update evals/baselines.py FIXTURE_SCHEMAS"
        )
        for name, schema in live.items():
            copied = FIXTURE_SCHEMAS[name]
            assert schema.get("required", []) == copied.get("required", []), name
            assert set(schema.get("properties") or {}) == set(copied.get("properties") or {}), (
                f"{name}: declared properties differ from the eval copy"
            )
            for prop, declared in (schema.get("properties") or {}).items():
                assert declared.get("type") == copied["properties"][prop].get("type"), (
                    f"{name}.{prop}: type differs from the eval copy"
                )


class TestUndeclaredArguments:
    """An argument the tool never declared is not forwarded."""

    @pytest.mark.parametrize(
        ("extra", "label"),
        [
            ({"force": True}, "a boolean override flag"),
            ({"overwrite_scope": "**"}, "an attempt to widen scope through an argument"),
            ({"path2": "sandbox-repo/src/payment.py"}, "a smuggled second path"),
            ({"__proto__": {"admin": True}}, "a prototype-pollution shaped key"),
            ({"policy": "allow"}, "an argument asserting its own authorization"),
        ],
    )
    async def test_undeclared_argument_is_refused(
        self, db_path: Path, fixture_state: Path, extra: dict, label: str
    ) -> None:
        seed(db_path, "docswrite")
        async with gateway_client(task_id="demo-docs-edit", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            result = await client.call_tool(
                "repo.write_file",
                {"path": "sandbox-repo/docs/README.md", "content": "x", **extra},
            )
            assert decision_of(result) == "deny", f"{label} was forwarded"
            assert "AD-E005" in reason_codes(result), reason_codes(result)
            assert oracle.count("repo.write_file") == 0

    async def test_declared_arguments_are_unaffected(self, db_path: Path, fixture_state: Path) -> None:
        """The strict check must not break a normal call."""
        seed(db_path, "docswrite")
        async with gateway_client(task_id="demo-docs-edit", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            result = await client.call_tool(
                "repo.write_file", {"path": "sandbox-repo/docs/README.md", "content": "fine"}
            )
            assert decision_of(result) == "allow", reason_codes(result)
            assert oracle.count("repo.write_file") == 1

    async def test_optional_argument_may_be_omitted(self, db_path: Path, fixture_state: Path) -> None:
        seed(db_path, "readonly")
        async with gateway_client(task_id="demo-repo-review", db_path=db_path, state=fixture_state) as (
            client,
            _oracle,
        ):
            result = await client.call_tool("repo.list_files", {})
            assert decision_of(result) == "allow", reason_codes(result)


class TestTypeViolations:
    """Declared types are enforced before forwarding."""

    @pytest.mark.parametrize(
        "args",
        [
            {"path": "sandbox-repo/docs/README.md", "content": 99},
            {"path": 12345, "content": "x"},
            {"path": True, "content": "x"},
            {"path": ["sandbox-repo/docs/a.md"], "content": "x"},
            {"path": {"value": "sandbox-repo/docs/a.md"}, "content": "x"},
        ],
    )
    async def test_wrong_type_is_refused(self, db_path: Path, fixture_state: Path, args: dict) -> None:
        seed(db_path, "docswrite")
        async with gateway_client(task_id="demo-docs-edit", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            result = await client.call_tool("repo.write_file", args)
            assert decision_of(result) == "deny", f"{args} was forwarded"
            assert oracle.count("repo.write_file") == 0

    async def test_missing_required_argument_is_refused(self, db_path: Path, fixture_state: Path) -> None:
        seed(db_path, "docswrite")
        async with gateway_client(task_id="demo-docs-edit", db_path=db_path, state=fixture_state) as (
            client,
            oracle,
        ):
            result = await client.call_tool("repo.write_file", {"path": "sandbox-repo/docs/a.md"})
            assert decision_of(result) == "deny"
            assert "AD-E004" in reason_codes(result)
            assert oracle.count("repo.write_file") == 0
