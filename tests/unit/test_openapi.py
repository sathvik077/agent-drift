"""The hand-maintained OpenAPI document must not drift from the routes (D-002)."""

from __future__ import annotations

import os

import pytest
from pydantic import ValidationError

os.environ.setdefault("AD_DISABLE_AUTH", "1")


@pytest.fixture
def app(store):
    """A Starlette app bound to an isolated store."""
    from apps.api.main import create_app

    return create_app(store=store)


class TestDocumentCoverage:
    """Every route is documented and every documented path exists."""

    def test_documented_paths_equal_registered_paths(self, app) -> None:
        from apps.api.main import ROUTES

        documented = set(app.state.openapi["paths"])
        registered = {route.path for route in ROUTES}
        assert documented == registered, {
            "undocumented": sorted(registered - documented),
            "phantom": sorted(documented - registered),
        }

    def test_every_route_method_is_documented(self, app) -> None:
        from apps.api.main import ROUTES

        paths = app.state.openapi["paths"]
        for route in ROUTES:
            for method in route.methods or set():
                if method in ("HEAD", "OPTIONS"):
                    continue
                assert method.lower() in paths[route.path], f"{method} {route.path} is undocumented"

    def test_mutating_routes_declare_bearer_security(self, app) -> None:
        """A mutating route without declared auth would be a documentation lie."""
        paths = app.state.openapi["paths"]
        for path, methods in paths.items():
            for method, operation in methods.items():
                if method.lower() in ("post", "put", "patch", "delete"):
                    assert operation.get("security"), f"{method.upper()} {path} omits security"

    def test_is_openapi_31(self, app) -> None:
        assert app.state.openapi["openapi"].startswith("3.1")

    def test_security_scheme_is_defined(self, app) -> None:
        schemes = app.state.openapi["components"]["securitySchemes"]
        assert schemes["bearerAuth"]["scheme"] == "bearer"

    def test_every_schema_reference_resolves(self, app) -> None:
        import json
        import re

        document = app.state.openapi
        text = json.dumps(document)
        referenced = set(re.findall(r'"#/components/schemas/([A-Za-z0-9_]+)"', text))
        defined = set(document["components"]["schemas"])
        assert referenced <= defined, sorted(referenced - defined)


class TestExamplesAreValid:
    """Documented example payloads must actually be accepted by the models."""

    def test_examples_validate_against_their_models(self, app) -> None:
        from apps.api.schemas import ApprovalActionRequest, CreateTaskRequest, EvaluateAttemptRequest

        models = {
            "/api/tasks": CreateTaskRequest,
            "/api/attempts/evaluate": EvaluateAttemptRequest,
            "/api/approvals/{approval_id}/approve": ApprovalActionRequest,
            "/api/approvals/{approval_id}/deny": ApprovalActionRequest,
        }
        checked = 0
        for path, model in models.items():
            operation = app.state.openapi["paths"][path]["post"]
            body = operation.get("requestBody", {}).get("content", {}).get("application/json", {})
            for name, example in (body.get("examples") or {}).items():
                try:
                    model.model_validate(example["value"])
                except ValidationError as exc:  # pragma: no cover - a failure is the point
                    pytest.fail(f"example {name!r} for {path} does not validate: {exc}")
                checked += 1
        assert checked >= 5, f"expected several documented examples, found {checked}"

    def test_enforcement_boundary_is_documented(self, app) -> None:
        """The advisory nature of /api/attempts/evaluate must be stated in the docs."""
        summary = app.state.openapi["paths"]["/api/attempts/evaluate"]["post"]["summary"].lower()
        assert "advisory" in summary
        description = app.state.openapi["info"]["description"].lower()
        assert "advisory" in description and "gateway" in description
