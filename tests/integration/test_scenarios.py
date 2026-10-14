"""Assert the bundled demo scenarios produce the decisions the dashboard advertises.

The dashboard's Scenarios tab renders each step's ``expected_decision`` straight from
these JSON files. This module runs them through the same runner the ``make demo`` target
uses, so a scenario whose expectation the system does not actually meet cannot be
displayed as if it did (AD-15).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_drift.seed import load_scenarios

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

SCENARIOS = load_scenarios()
SCENARIO_IDS = [scenario["id"] for scenario in SCENARIOS]


@pytest.fixture
def anyio_backend() -> str:
    """Run the async tests on asyncio."""
    return "asyncio"


@pytest.fixture(autouse=True)
def _runner_on_path() -> None:
    """Make ``scripts/run_scenarios.py`` importable."""
    import sys

    scripts = Path(__file__).resolve().parent.parent.parent / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))


class TestBundledScenarios:
    """Each scenario, run end to end against a real gateway."""

    @pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
    async def test_scenario_matches_its_published_expectations(
        self, scenario_id: str, db_path: Path, fixture_state: Path, monkeypatch
    ) -> None:
        import run_scenarios  # type: ignore[import-not-found]

        monkeypatch.setenv("AD_FIXTURE_STATE", str(fixture_state))
        scenario = next(s for s in SCENARIOS if s["id"] == scenario_id)
        outcome = await run_scenarios.run_one(scenario, db_path=db_path, approval_timeout_s=2.0)

        failures = [
            f"step {index + 1} {step.tool}: expected {step.expected}, observed {step.observed} "
            f"(reasons={step.reason_codes}, upstream_delta={step.upstream_delta})"
            for index, step in enumerate(outcome.steps)
            if not step.matched
        ]
        assert not failures, f"{scenario_id}:\n  " + "\n  ".join(failures)

    @pytest.mark.parametrize("scenario_id", SCENARIO_IDS)
    async def test_denied_steps_never_reach_the_tool(
        self, scenario_id: str, db_path: Path, fixture_state: Path, monkeypatch
    ) -> None:
        """A denial that still incremented the upstream counter would be a failure of
        the central claim, so it is asserted per scenario rather than only in aggregate."""
        import run_scenarios  # type: ignore[import-not-found]

        monkeypatch.setenv("AD_FIXTURE_STATE", str(fixture_state))
        scenario = next(s for s in SCENARIOS if s["id"] == scenario_id)
        outcome = await run_scenarios.run_one(scenario, db_path=db_path, approval_timeout_s=2.0)
        for index, step in enumerate(outcome.steps):
            if step.observed == "deny":
                assert step.upstream_delta == 0, (
                    f"{scenario_id} step {index + 1} ({step.tool}) was denied but the "
                    f"upstream counter moved by {step.upstream_delta}"
                )


class TestScenarioCatalogue:
    """The catalogue must satisfy the acceptance criteria it is cited for."""

    def test_at_least_six_scenarios_are_bundled(self) -> None:
        assert len(SCENARIOS) >= 6, f"AD-15 requires at least six scenarios, found {len(SCENARIOS)}"

    def test_both_categories_are_represented(self) -> None:
        categories = {scenario["category"] for scenario in SCENARIOS}
        assert categories == {"benign", "adversarial"}

    def test_the_six_named_attacks_are_present(self) -> None:
        """CLAUDE.md section 5 names attacks A through F; all six must exist."""
        ids = set(SCENARIO_IDS)
        for expected in (
            "attack-a-exfiltration",
            "attack-b-scope-drift",
            "attack-c-budget-drift",
            "attack-d-approval-exactness",
            "attack-e-benign-keyword",
            "attack-f-manifest-rug-pull",
        ):
            assert expected in ids, f"missing scenario {expected}"

    def test_every_step_declares_an_expected_decision(self) -> None:
        for scenario in SCENARIOS:
            for index, step in enumerate(scenario["steps"]):
                assert step.get("expected_decision") in ("allow", "deny", "needs_approval"), (
                    f"{scenario['id']} step {index + 1} has no valid expected_decision"
                )

    def test_every_scenario_names_a_seeded_task(self) -> None:
        from agent_drift.seed import CONTRACT_BUILDERS, build_contract

        known = {build_contract(name).task_id for name in CONTRACT_BUILDERS}
        for scenario in SCENARIOS:
            assert scenario["task_id"] in known, (
                f"{scenario['id']} references unseeded task {scenario['task_id']!r}"
            )

    def test_adversarial_scenarios_declare_an_attack_label(self) -> None:
        for scenario in SCENARIOS:
            if scenario["category"] == "adversarial":
                assert scenario.get("attack_label"), f"{scenario['id']} has no attack_label"

    def test_every_scenario_has_a_narrative(self) -> None:
        for scenario in SCENARIOS:
            assert len(scenario.get("narrative", "")) > 40, f"{scenario['id']} needs a narrative"
