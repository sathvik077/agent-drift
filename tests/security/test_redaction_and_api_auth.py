"""Secret redaction before logging, and control-plane auth on mutations (AD-22)."""

from __future__ import annotations

import json
import os

import pytest

from agent_drift.contracts import ContractSource, IntentContract, Operation, ToolAttempt


@pytest.fixture
def seeded(store) -> IntentContract:
    """A registered contract."""
    contract = IntentContract(
        principal="dev",
        task_id="t",
        user_goal="g",
        approved_by="dev",
        source=ContractSource.TRUSTED_CONFIG,
        allowed_tools=["repo.read_file"],
        allowed_operations=[Operation.READ],
        resource_scopes=["sandbox-repo/**"],
        max_calls=50,
    )
    store.put_contract(contract)
    return contract


class TestRedactionBeforePersistence:
    """A secret in a tool argument must not reach the database or the event log."""

    SECRETS = {
        "api_key": "sk-REALLOOKINGKEY1234567890",
        "password": "hunter2-not-a-real-password",
        "note": "ping someone@example.test with ghp_ABCDEFGHIJKLMNOPQRSTUV",
    }

    def test_attempt_rows_are_redacted(self, store, seeded) -> None:
        attempt = ToolAttempt(
            task_id="t",
            tool_server="sandbox",
            tool_name="repo.read_file",
            args={"path": "sandbox-repo/README.md", **self.SECRETS},
        )
        store.record_attempt(attempt)
        row = store.conn.execute(
            "SELECT payload FROM attempts WHERE attempt_id = ?", (attempt.attempt_id,)
        ).fetchone()
        blob = row["payload"]
        assert "sk-REALLOOKINGKEY" not in blob
        assert "hunter2" not in blob
        assert "ghp_ABCDEFGHIJKLMNOPQRSTUV" not in blob
        assert "someone@example.test" not in blob
        assert "sandbox-repo/README.md" in blob, "redaction must not destroy useful evidence"

    def test_event_log_is_redacted(self, store, seeded) -> None:
        attempt = ToolAttempt(
            task_id="t",
            tool_server="sandbox",
            tool_name="repo.read_file",
            args={"path": "sandbox-repo/README.md", **self.SECRETS},
        )
        store.record_attempt(attempt)
        serialized = json.dumps(store.events_since(0, limit=100))
        assert "sk-REALLOOKINGKEY" not in serialized
        assert "hunter2" not in serialized

    def test_decision_evidence_is_redacted(self, store, engine, seeded) -> None:
        attempt = ToolAttempt(
            tool_server="sandbox",
            tool_name="repo.read_file",
            args={"path": "sandbox-repo/README.md", "authorization": "Bearer sk-SECRETVALUE1234567"},
        )
        store.record_attempt(attempt)
        decision = engine.evaluate(attempt, bound_task_id="t")
        store.record_decision(decision, run_id=attempt.run_id)
        row = store.conn.execute(
            "SELECT payload FROM decisions WHERE attempt_id = ?", (attempt.attempt_id,)
        ).fetchone()
        assert "sk-SECRETVALUE" not in row["payload"]

    def test_digest_is_computed_before_redaction(self, store, seeded) -> None:
        """The args digest must cover the real arguments, or approvals would be wrong."""
        attempt = ToolAttempt(
            task_id="t",
            tool_server="sandbox",
            tool_name="repo.read_file",
            args={"path": "a", "api_key": "sk-AAAAAAAAAAAAAAAAAAAA"},
        )
        other = ToolAttempt(
            task_id="t",
            tool_server="sandbox",
            tool_name="repo.read_file",
            args={"path": "a", "api_key": "sk-BBBBBBBBBBBBBBBBBBBB"},
        )
        assert attempt.canonical_args_digest() != other.canonical_args_digest()


class TestControlPlaneAuth:
    """Mutations require a bearer token; reads do not; a missing token fails closed."""

    def _client(self, store, token: str | None, *, disable: bool = False):
        from apps.api.main import create_app
        from starlette.testclient import TestClient

        os.environ.pop("AD_ADMIN_TOKEN", None)
        os.environ.pop("AD_DISABLE_AUTH", None)
        if token is not None:
            os.environ["AD_ADMIN_TOKEN"] = token
        if disable:
            os.environ["AD_DISABLE_AUTH"] = "1"
        return TestClient(create_app(store=store))

    TASK_BODY = {
        "task_id": "created-by-test",
        "user_goal": "a goal",
        "allowed_tools": ["repo.read_file"],
        "allowed_operations": ["read"],
        "resource_scopes": ["sandbox-repo/**"],
    }

    def test_reads_do_not_require_a_token(self, store, seeded) -> None:
        client = self._client(store, "secret-token")
        assert client.get("/healthz").status_code == 200
        assert client.get("/api/tasks").status_code == 200
        assert client.get("/api/events").status_code == 200

    def test_mutation_without_a_token_is_rejected(self, store, seeded) -> None:
        client = self._client(store, "secret-token")
        response = client.post("/api/tasks", json=self.TASK_BODY)
        assert response.status_code == 401
        assert response.json()["code"] == "AD-API-UNAUTHORIZED"

    def test_mutation_with_a_wrong_token_is_rejected(self, store, seeded) -> None:
        client = self._client(store, "secret-token")
        response = client.post("/api/tasks", json=self.TASK_BODY, headers={"authorization": "Bearer wrong"})
        assert response.status_code == 401

    def test_mutation_with_the_wrong_scheme_is_rejected(self, store, seeded) -> None:
        client = self._client(store, "secret-token")
        response = client.post(
            "/api/tasks", json=self.TASK_BODY, headers={"authorization": "Basic secret-token"}
        )
        assert response.status_code == 401

    def test_mutation_with_the_right_token_succeeds(self, store, seeded) -> None:
        client = self._client(store, "secret-token")
        response = client.post(
            "/api/tasks", json=self.TASK_BODY, headers={"authorization": "Bearer secret-token"}
        )
        assert response.status_code == 201, response.text
        assert store.get_contract("created-by-test") is not None

    def test_missing_token_configuration_fails_closed(self, store, seeded) -> None:
        """No token configured must mean 'nobody may write policy', not 'anybody may'."""
        client = self._client(store, None)
        response = client.post(
            "/api/tasks", json=self.TASK_BODY, headers={"authorization": "Bearer anything"}
        )
        assert response.status_code == 503
        assert response.json()["code"] == "AD-API-NOTOKEN"
        assert store.get_contract("created-by-test") is None

    def test_explicit_opt_out_is_honoured(self, store, seeded) -> None:
        """Tests may disable auth, but only by saying so explicitly."""
        client = self._client(store, None, disable=True)
        response = client.post("/api/tasks", json=self.TASK_BODY)
        assert response.status_code == 201

    def test_approval_endpoints_require_a_token(self, store, seeded) -> None:
        client = self._client(store, "secret-token")
        assert client.post("/api/approvals/apr_x/approve").status_code == 401
        assert client.post("/api/approvals/apr_x/deny").status_code == 401

    def test_evaluate_endpoint_requires_a_token(self, store, seeded) -> None:
        client = self._client(store, "secret-token")
        response = client.post(
            "/api/attempts/evaluate",
            json={"task_id": "t", "tool_name": "repo.read_file", "args": {"path": "a"}},
        )
        assert response.status_code == 401

    def test_unknown_field_in_a_payload_is_rejected(self, store, seeded) -> None:
        client = self._client(store, "secret-token")
        response = client.post(
            "/api/tasks",
            json={**self.TASK_BODY, "is_admin": True},
            headers={"authorization": "Bearer secret-token"},
        )
        assert response.status_code == 422

    def test_export_is_redacted(self, store, seeded) -> None:
        attempt = ToolAttempt(
            task_id="t",
            tool_server="sandbox",
            tool_name="repo.read_file",
            args={"path": "a", "api_key": "sk-EXPORTSECRET12345678"},
        )
        store.record_attempt(attempt)
        client = self._client(store, "secret-token")
        response = client.get("/api/export/t")
        assert response.status_code == 200
        assert "sk-EXPORTSECRET" not in response.text
        assert "disclosure" in response.json()
